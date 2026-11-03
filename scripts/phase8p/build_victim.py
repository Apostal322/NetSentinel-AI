"""Phase 8p: victim-side windows (VW) and source-window context (SX) for every development domain
(`netsentinel.behavior.victim`). Feature construction only; no model is fitted.

One streaming pass per domain over ALL flows, in the Phase 8i order and development cut
(`build_windows.chunks`: whole 30 s windows, time-ordered). The victim history (`History`) is
carried across chunks and through calibration and evaluation with one causal expanding
semantics. Each VW row is tagged:

- `period`: "cal" if its window ends at or before the domain's registered midpoint, otherwise
  "eval". The one window straddling the midpoint is a single merged evaluation row, unlike the
  source-side builder, which splits it.
- `noisy`: holds an NF-CIC `infiltration` flow (as Phase 8h).

`attack_flows` / `attack_srcs` are evaluation-only counts and never features.

Output: data/derived/phase8p/victim/<network>/<domain>/
- vw/part-*.parquet, sx/part-*.parquet;
- attacker_contacts.parquet: distinct (src, dst, win) of attack-labelled flows, for attribution
  in evaluation only;
- meta.json.
Plus reports/phase8p/build_victim_<network>.json.

Usage: python scripts/run_capped.py -- <python> scripts/phase8p/build_victim.py nfcic [--days d1,d2]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
import build_windows as BW  # noqa: E402, N812

from netsentinel.behavior.victim import SCHEMA_VERSION, History, source_context, victim_windows  # noqa: E402
from netsentinel.behavior.windows import prepare_flows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

DERIVED = ROOT / "data" / "derived" / "phase8i"
OUT = ROOT / "data" / "derived" / "phase8p" / "victim"
REPORTS = ROOT / "reports" / "phase8p"
W_MS = BW.W * 1000


def build(
    files: list[Path], dev_cut: bool, network: str, domain: str, max_rows: int = BW.MAX_ROWS
) -> dict:
    t0 = time.perf_counter()
    mid = int(json.loads((DERIVED / network / domain / "meta.json").read_text("utf-8"))["mid_ms"])
    out = OUT / network / domain
    for sub in ("vw", "sx", "contacts"):
        (out / sub).mkdir(parents=True, exist_ok=True)
        for old in (out / sub).glob("*.parquet"):
            old.unlink()
    hist = History()
    n = rows_vw = rows_sx = 0
    for i, frame in enumerate(BW.chunks(files, dev_cut, max_rows)):
        infil = frame.filter(pl.col("label") == BW.NOISY).select(
            pl.col("ipv4_dst_addr").cast(pl.Utf8).alias("dst"),
            (pl.col("flow_end_milliseconds") // W_MS).alias("win")).unique()  # fmt: skip
        flows = prepare_flows(frame)
        n += frame.height
        del frame
        vw = victim_windows(flows, BW.W, history=hist)
        sx = source_context(flows, vw, BW.W)
        period = (
            pl.when((pl.col("win") + 1) * W_MS <= mid).then(pl.lit("cal")).otherwise(pl.lit("eval"))
        )
        vw = vw.join(infil.with_columns(pl.lit(True).alias("noisy")), on=["dst", "win"], how="left").with_columns(
            pl.col("noisy").fill_null(False), period.alias("period"))  # fmt: skip
        sx = sx.with_columns(period.alias("period"))
        vw.write_parquet(out / "vw" / f"part-{i:05d}.parquet")
        sx.write_parquet(out / "sx" / f"part-{i:05d}.parquet")
        rows_vw, rows_sx = rows_vw + vw.height, rows_sx + sx.height
        att = flows.filter(pl.col("is_attack") > 0)
        if att.height:
            # written per slice: a kept in-memory slice of string columns can pin the whole
            # slice's string buffers, so collecting them in a list grows with the stream
            att.select("src", "dst", (pl.col("end_ms") // W_MS).alias("win")).unique().write_parquet(
                out / "contacts" / f"part-{i:05d}.parquet")  # fmt: skip
        del flows, vw, sx, att
    parts = sorted((out / "contacts").glob("*.parquet"))
    (pl.scan_parquet(parts).unique().collect() if parts
     else pl.DataFrame(schema={"src": pl.Utf8, "dst": pl.Utf8, "win": pl.Int64})
     ).write_parquet(out / "attacker_contacts.parquet")  # fmt: skip
    meta = {"schema_version": SCHEMA_VERSION, "mid_ms": mid, "flows": n, "vw_rows": rows_vw,
            "sx_rows": rows_sx, "hosts_in_history": len(hist.sum),
            "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
    (out / "meta.json").write_bytes(json.dumps(meta, indent=1).encode())
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("network", choices=("nfcic", "nfunsw", "nfton", "nfbot"))
    ap.add_argument("--days")
    ap.add_argument(
        "--max-rows",
        type=int,
        default=BW.MAX_ROWS,
        help="flows per slice (smaller bounds the memory of flood captures)",
    )
    a = ap.parse_args()
    src, dev_cut, per_day = BW.NETWORKS[a.network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    t0 = time.perf_counter()
    res = {}
    if per_day:
        days = set(a.days.split(",")) if a.days else None
        for f in files:
            if (days is None or f.stem in days) and (DERIVED / a.network / f.stem).exists():
                res[f.stem] = build([f], dev_cut, a.network, f.stem, a.max_rows)
                print(f.stem, json.dumps(res[f.stem]), flush=True)
    else:
        res["all"] = build(files, dev_cut, a.network, "all", a.max_rows)
        print(json.dumps(res["all"]), flush=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    rep = REPORTS / f"build_victim_{a.network}.json"
    prev = json.loads(rep.read_text("utf-8"))["domains"] if rep.exists() else {}
    rep.write_bytes(json.dumps({"domains": {**prev, **res}, "seconds": round(time.perf_counter() - t0, 1),
                                "peak_rss_mb": peak_rss_mb()}, indent=1).encode())  # fmt: skip


if __name__ == "__main__":
    main()
