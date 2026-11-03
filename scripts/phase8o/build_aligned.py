"""Phase 8o Experiment D feature build (docs/phase8o/PREREGISTRATION.md section 2).

One streaming pass per domain over the calibration flows (flow end before the registered time
midpoint), in the Phase 8i order (`build_windows.chunks`), with three causal destination
memories (`netsentinel.behavior.novelty.NoveltyMemory`, `frozen` policy):

- ``f1``  (source domains) clean memory (calibration attack flows removed), frozen at q_src,
          the start of the last 30 % of the source's calibration slots (`split_cut` of the
          training calibration windows). Rows with win >= q_src are the F1 training values.
- ``f3``  (source domains) the same clean memory frozen at the midpoint: before the midpoint it
          is the expanding memory, so it must reproduce `cal_clean.new_dst_frac` exactly (R3).
- ``c1``  (target domains) P1x memory (calibration-period attacker hosts removed), frozen at
          q_tgt, the T0 hold-out start (`split_cut` of `cal_p1x`). Rows with win >= q_tgt are the
          C1 hold-out values.

Checks written to meta.json:
- F3, and F1 and C1 before their freeze, against the historical calibration windows
  (max |difference|, missing rows);
- whether the F1/C1 rows cover every training or hold-out row.

Output: data/derived/phase8o/aligned/<network>/<domain>/{f1_clean,c1_p1x}.parquet + meta.json
        reports/phase8o/build_aligned_<network>.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8o/build_aligned.py nfcic
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


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BN = _load("build_novelty_8m", ROOT / "scripts/phase8m/build_novelty.py")
BW, P1X, C = BN.BW, BN.P1X, BN.C
S = C.S

from netsentinel.behavior.novelty import NoveltyMemory, contacts_from_flows  # noqa: E402
from netsentinel.behavior.windows import prepare_flows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = ROOT / "data" / "derived" / "phase8o" / "aligned"
REPORTS = ROOT / "reports" / "phase8o"
W_MS = BW.W * 1000


def compare(rows: pl.DataFrame, ref: pl.DataFrame, lo: int | None = None,
            hi: int | None = None) -> dict:  # fmt: skip
    """max |nov_frozen - new_dst_frac| over the reference windows with lo <= win < hi."""
    if lo is not None:
        ref = ref.filter(pl.col("win") >= lo)
    if hi is not None:
        ref = ref.filter(pl.col("win") < hi)
    j = ref.join(rows.select("key", "win", "nov_frozen"), on=["key", "win"], how="left")
    diff = (j["new_dst_frac"].cast(pl.Float64) - j["nov_frozen"]).abs().max()
    return {"windows": ref.height, "missing": int(j["nov_frozen"].null_count()),
            "max_abs_diff": float(diff) if diff is not None else 0.0}  # fmt: skip


def build(files: list[Path], dev_cut: bool, network: str, domain: str, max_rows: int) -> dict:
    t0 = time.perf_counter()
    src_dir = C.DERIVED / network / domain
    mid = int(json.loads((src_dir / "meta.json").read_text("utf-8"))["mid_ms"])
    is_source = network in C.DEV_NETWORKS
    p1x_dir = P1X.OUT / network / domain
    is_target = (p1x_dir / "cal_p1x.parquet").exists()
    mems: dict[str, tuple[NoveltyMemory, int, str]] = {}  # name -> (memory, freeze ms, variant)
    refs: dict[str, pl.DataFrame] = {}
    if is_source:
        cal_train = C.load_domain(src_dir, network)["cal"]  # the training calibration rows
        q_src = S.split_cut(cal_train) * W_MS
        mems["f1"] = (NoveltyMemory(freeze_ms=q_src), q_src, "clean")
        mems["f3"] = (NoveltyMemory(freeze_ms=mid), mid, "clean")
        refs["clean"] = pl.read_parquet(src_dir / "cal_clean.parquet",
                                        columns=["key", "win", "new_dst_frac"])  # fmt: skip
        refs["train"] = cal_train.select("key", "win", "new_dst_frac")
        del cal_train
    excluded: list[str] = []
    if is_target:
        cal_p1x = pl.read_parquet(
            p1x_dir / "cal_p1x.parquet", columns=["key", "win", "new_dst_frac"]
        )
        q_tgt = S.split_cut(cal_p1x) * W_MS
        excluded = sorted(P1X.calibration_attackers(src_dir))
        mems["c1"] = (NoveltyMemory(freeze_ms=q_tgt), q_tgt, "p1x")
        refs["p1x"] = cal_p1x
    if not mems:
        return {"status": "neither source nor target"}
    parts: dict[str, list[pl.DataFrame]] = {k: [] for k in mems}
    n = chunks = 0
    for df in BW.chunks(files, dev_cut, max_rows):
        flows = prepare_flows(df)
        del df
        if flows.height and int(flows["end_ms"].min()) >= mid:
            break  # time-ordered: no calibration flow follows
        flows = flows.filter(pl.col("end_ms") < mid)
        n += flows.height
        chunks += 1
        for name, (mem, freeze, variant) in mems.items():
            kept = BN.keep_flows(flows, variant, mid, excluded)
            parts[name].append(mem.process(contacts_from_flows(kept, BW.W, freeze_ms=freeze)))
        del flows
    out = OUT / network / domain
    out.mkdir(parents=True, exist_ok=True)
    meta: dict = {"mid_ms": mid, "flows": n, "chunks": chunks, "checks": {}}
    feat = {k: pl.concat(v) if v else pl.DataFrame() for k, v in parts.items()}
    if is_source:
        q_win = mems["f1"][1] // W_MS
        meta["q_src_ms"] = mems["f1"][1]
        meta["checks"]["f3_vs_cal_clean"] = compare(feat["f3"], refs["clean"])
        meta["checks"]["f1_before_q_vs_cal_clean"] = compare(feat["f1"], refs["clean"], hi=q_win)
        meta["checks"]["f1_rows_cover_training_rows"] = compare(feat["f1"], refs["train"], lo=q_win)
        f1 = feat["f1"].filter(pl.col("win") >= q_win).select(
            "key", "win", pl.col("nov_frozen").alias("new_dst_frac_f1"))  # fmt: skip
        f1.write_parquet(out / "f1_clean.parquet")
        meta["f1_rows"] = f1.height
    if is_target:
        q_win = mems["c1"][1] // W_MS
        meta["q_tgt_ms"] = mems["c1"][1]
        meta["checks"]["c1_before_q_vs_cal_p1x"] = compare(feat["c1"], refs["p1x"], hi=q_win)
        meta["checks"]["c1_rows_cover_holdout"] = compare(feat["c1"], refs["p1x"], lo=q_win)
        c1 = feat["c1"].filter(pl.col("win") >= q_win).select(
            "key", "win", pl.col("nov_frozen").alias("new_dst_frac_c1"))  # fmt: skip
        c1.write_parquet(out / "c1_p1x.parquet")
        meta["c1_rows"] = c1.height
    meta["seconds"] = round(time.perf_counter() - t0, 1)
    (out / "meta.json").write_bytes(json.dumps(meta, indent=1).encode())
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("network", choices=("nfcic", "nfunsw", "nfton", "nfbot"))
    ap.add_argument("--days", help="NF-CIC days (comma-separated); default: every day")
    ap.add_argument("--max-rows", type=int, default=BW.MAX_ROWS)
    a = ap.parse_args()
    src, dev_cut, per_day = BW.NETWORKS[a.network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    if not files:
        sys.exit(f"no ingested files under {src}")
    t0 = time.perf_counter()
    res = {}
    if per_day:
        days = set(a.days.split(",")) if a.days else None
        for f in files:
            if (days is None or f.stem in days) and (C.DERIVED / a.network / f.stem).exists():
                res[f.stem] = build([f], dev_cut, a.network, f.stem, a.max_rows)
                print(f.stem, json.dumps(res[f.stem]), flush=True)
    else:
        res["all"] = build(files, dev_cut, a.network, "all", a.max_rows)
        print(json.dumps(res["all"]), flush=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    rep = REPORTS / f"build_aligned_{a.network}.json"
    prev = json.loads(rep.read_text("utf-8"))["domains"] if rep.exists() else {}
    rep.write_bytes(json.dumps({"domains": {**prev, **res}, "seconds": round(time.perf_counter() - t0, 1),
                                "peak_rss_mb": peak_rss_mb()}, indent=1).encode())  # fmt: skip


if __name__ == "__main__":
    main()
