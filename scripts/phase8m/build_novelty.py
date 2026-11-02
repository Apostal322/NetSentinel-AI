"""Phase 8m Stage 3: causal adaptive-novelty features for every development domain
(docs/phase8m/PREREGISTRATION.md section 2).

One streaming pass per domain over the same flows, in the same order, as the Phase 8i windows
(`build_windows.chunks`, the domain's registered time midpoint from the Phase 8i meta.json).
Two memories run side by side; they differ only in which calibration flows they learn from,
mirroring the two window sets the models see:

- ``clean``: calibration attack FLOWS removed (the Phase 8i `cal_clean`/`eval_clean` windows that
  the source models are TRAINED on; source-network labels only);
- ``p1x``: calibration-period attacker HOSTS removed (the Phase 8j P1x windows that the target is
  CALIBRATED and SCORED on; calibration-period labels only, never evaluation labels).

After the midpoint every flow updates both memories, as it would in deployment. Each memory
reproduces its window set's `new_dst_frac` as `nov_frozen`; the build checks this on every
window and records the largest difference. Contacts are tagged by flow end time, so the calibration
part of the one 30 s window index that straddles the midpoint still enters the frozen memory;
that window itself is scored once from its merged flows (its calibration and evaluation rows get
the same values) and is excluded from the check (meta.json `straddle_win`).

Output: data/derived/phase8m/novelty/<network>/<domain>/
          {clean,p1x}.parquet         features per (key, win)
          dst_state_{clean,p1x}.parquet  final memory state per destination
          contacts_p1x/part-*.parquet  the p1x contact stream (for contamination re-runs)
          meta.json
        reports/phase8m/build_novelty_<network>.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8m/build_novelty.py nfcic
       [--days 2018-02-14] [--max-chunks N]   (N: a bounded timing sample, not a full build)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
import build_windows as BW  # noqa: E402, N812

_spec = importlib.util.spec_from_file_location(
    "build_p1x_8j", ROOT / "scripts/phase8j/build_p1x.py"
)
P1X = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P1X)
C = P1X.C

from netsentinel.behavior.novelty import (  # noqa: E402
    FEATURES,
    NoveltyMemory,
    contacts_from_flows,
    destination_state,
)
from netsentinel.behavior.windows import prepare_flows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = ROOT / "data" / "derived" / "phase8m" / "novelty"
SAMPLE = ROOT / "data" / "derived" / "phase8m" / "novelty_sample"  # --max-chunks output
REPORTS = ROOT / "reports" / "phase8m"
VARIANTS = ("clean", "p1x")
# the window sets each memory must reproduce (`new_dst_frac` = `nov_frozen`)
REFERENCE = {"clean": (C.DERIVED, "cal_clean", "eval_clean"),
             "p1x": (P1X.OUT, "cal_p1x", "eval_p1x")}  # fmt: skip


def keep_flows(flows: pl.DataFrame, variant: str, mid: int, excluded: list[str]) -> pl.DataFrame:
    cal = pl.col("end_ms") < mid
    if variant == "clean":
        return flows.filter(~(cal & (pl.col("is_attack") > 0)))
    return flows.filter(~(cal & pl.col("src").is_in(excluded)))


def check(feat: pl.DataFrame, variant: str, network: str, domain: str, skip_win: int,
          last_win: int | None) -> dict:  # fmt: skip
    """Largest |nov_frozen - new_dst_frac| over the reference windows (all present unless the
    build was truncated at `last_win`)."""
    root, cal, ev = REFERENCE[variant]
    out = {}
    for part in (cal, ev):
        ref = pl.read_parquet(root / network / domain / f"{part}.parquet",
                              columns=["key", "win", "new_dst_frac"])  # fmt: skip
        ref = ref.filter(pl.col("win") != skip_win)
        if last_win is not None:
            ref = ref.filter(pl.col("win") <= last_win)
        j = ref.join(feat.select("key", "win", "nov_frozen"), on=["key", "win"], how="left")
        missing = int(j["nov_frozen"].null_count())
        diff = (j["new_dst_frac"].cast(pl.Float64) - j["nov_frozen"]).abs().max()
        out[part] = {"windows": ref.height, "missing": missing,
                     "max_abs_diff": float(diff) if diff is not None else 0.0}  # fmt: skip
    return out


def build(files: list[Path], dev_cut: bool, network: str, domain: str, max_rows: int,
          max_chunks: int | None) -> dict:  # fmt: skip
    t0 = time.perf_counter()
    src_dir = C.DERIVED / network / domain
    mid = int(json.loads((src_dir / "meta.json").read_text("utf-8"))["mid_ms"])
    excluded = sorted(P1X.calibration_attackers(src_dir))
    mems = {v: NoveltyMemory(freeze_ms=mid) for v in VARIANTS}
    parts: dict[str, list[pl.DataFrame]] = {v: [] for v in VARIANTS}
    out = (SAMPLE if max_chunks is not None else OUT) / network / domain
    cdir = out / "contacts_p1x"  # the p1x contact stream, for the contamination re-runs
    cdir.mkdir(parents=True, exist_ok=True)
    for old in cdir.glob("*.parquet"):
        old.unlink()
    n = chunks = contacts = 0
    for df in BW.chunks(files, dev_cut, max_rows):
        if max_chunks is not None and chunks >= max_chunks:
            break
        flows = prepare_flows(df)
        n += df.height
        chunks += 1
        del df
        for v in VARIANTS:
            c = contacts_from_flows(keep_flows(flows, v, mid, excluded), BW.W, freeze_ms=mid)
            contacts += c.height
            parts[v].append(mems[v].process(c))
            if v == "p1x" and c.height:
                c.write_parquet(cdir / f"part-{chunks:05d}.parquet")
        del flows
    skip_win = mid // (BW.W * 1000)
    truncated = max_chunks is not None and chunks >= max_chunks
    meta = {"mid_ms": mid, "straddle_win": skip_win, "excluded_hosts": len(excluded), "flows": n,
            "chunks": chunks, "contacts": contacts, "truncated": truncated, "variants": {}}  # fmt: skip
    for v in VARIANTS:
        feat = pl.concat(parts[v]) if parts[v] else pl.DataFrame()
        parts[v] = []
        if feat.height:
            feat.write_parquet(out / f"{v}.parquet")
        destination_state(mems[v]).write_parquet(out / f"dst_state_{v}.parquet")
        last = mems[v].last_win if truncated else None
        meta["variants"][v] = {
            "rows": feat.height, "destinations": len(mems[v].dst),
            "frozen_destinations": len(mems[v].frozen),
            "promoted": sum(s.promoted for s in mems[v].dst.values()),
            "check_new_dst_frac": check(feat, v, network, domain, skip_win, last) if feat.height else None,
        }  # fmt: skip
        del feat
    meta["seconds"] = round(time.perf_counter() - t0, 1)
    meta["features"] = list(FEATURES)
    (out / "meta.json").write_bytes(json.dumps(meta, indent=1).encode())
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("network", choices=("nfcic", "nfunsw", "nfton", "nfbot"))
    ap.add_argument("--days", help="NF-CIC days (comma-separated); default: the Phase 8j days")
    ap.add_argument("--max-rows", type=int, default=BW.MAX_ROWS)
    ap.add_argument("--max-chunks", type=int, help="timing sample: stop after N chunks")
    a = ap.parse_args()
    src, dev_cut, per_day = BW.NETWORKS[a.network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    if not files:
        sys.exit(f"no ingested files under {src}")
    t0 = time.perf_counter()
    res = {}
    if per_day:
        days = a.days.split(",") if a.days else C.PRIMARY_N1 + C.SECONDARY_N1
        for f in files:
            if f.stem in days:
                res[f.stem] = build([f], dev_cut, a.network, f.stem, a.max_rows, a.max_chunks)
                print(f.stem, json.dumps(res[f.stem]), flush=True)
    else:
        res["all"] = build(files, dev_cut, a.network, "all", a.max_rows, a.max_chunks)
        print(json.dumps(res["all"]), flush=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    tail = "_sample" if a.max_chunks is not None else ""
    rep = REPORTS / f"build_novelty_{a.network}{tail}.json"
    rep.write_bytes(json.dumps({"domains": res, "seconds": round(time.perf_counter() - t0, 1),
                                "peak_rss_mb": peak_rss_mb()}, indent=1).encode())  # fmt: skip


if __name__ == "__main__":
    main()
