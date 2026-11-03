"""Phase 8p H4 scenario C2, delayed verified labels (docs/phase8p/PREREGISTRATION.md section 5).
Feature construction only; no model is fitted.

**What is known.** A calibration-period attacker host counts as known (and is purged, as in P1x)
only if its last attack window in the calibration period ended at least `DELAY_MIN` minutes
before the calibration end, the time needed to review and confirm it. Hosts attacking later in
calibration stay unlabelled: their windows remain in the hold-out and their destinations in
the memory.

**How.** Phase 8j `P1xBuilder`, unchanged, with that partial exclusion list. The last attack
window comes from the Phase 8i calibration window labels (`cal_truth.parquet`: calibration
labels only).

Output: data/derived/phase8p/c2/<network>/<domain>/{cal_p1x,eval_p1x}.parquet + meta.json
        reports/phase8p/build_c2.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8p/build_c2.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "build_p1x_8j", ROOT / "scripts/phase8j/build_p1x.py"
)
P1X = importlib.util.module_from_spec(_spec)
sys.modules["build_p1x_8j"] = P1X
_spec.loader.exec_module(P1X)
BW, C = P1X.BW, P1X.C

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = ROOT / "data" / "derived" / "phase8p" / "c2"
REPORT = ROOT / "reports" / "phase8p" / "build_c2.json"
DELAY_MIN = 60
W_MS = BW.W * 1000


def known_attackers(
    src_dir: Path, mid_ms: int, delay_min: int = DELAY_MIN
) -> tuple[set[str], set[str]]:
    """(verified in time, all) calibration-period attacker hosts."""
    p = src_dir / "cal_truth.parquet"
    if not p.exists():
        return set(), set()
    last = pl.read_parquet(p).filter(pl.col("y")).group_by("key").agg(pl.col("win").max())
    cutoff = mid_ms - delay_min * 60_000
    known = set(last.filter((pl.col("win") + 1) * W_MS <= cutoff)["key"].to_list())
    return known, set(last["key"].to_list())


def main() -> None:
    t0 = time.perf_counter()
    res = {}
    for net in ("nfcic", "nfunsw", "nfton", "nfbot"):
        src, dev_cut, per_day = BW.NETWORKS[net]
        files = sorted(Path(src).glob("[0-9]*.parquet"))
        doms = (
            [(f.stem, [f]) for f in files if f.stem in C.PRIMARY_N1 + C.SECONDARY_N1]
            if per_day
            else [("all", files)]
        )
        for dom, fs in doms:
            src_dir = C.DERIVED / net / dom
            mid = int(json.loads((src_dir / "meta.json").read_text("utf-8"))["mid_ms"])
            known, every = known_attackers(src_dir, mid)
            b = P1X.P1xBuilder(mid, known)
            for df in BW.chunks(fs, dev_cut):
                b.add(df)
                del df
            meta = {"mid_ms": mid, "delay_min": DELAY_MIN, "calibration_attackers": len(every),
                    "known_in_time": len(known), "unlabelled_attackers": sorted(every - known)}  # fmt: skip
            b.save(OUT / net / dom, meta)
            res[f"{net}/{dom}"] = {k: v for k, v in meta.items() if k != "unlabelled_attackers"}
            print(net, dom, res[f"{net}/{dom}"], flush=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_bytes(json.dumps({"domains": res, "seconds": round(time.perf_counter() - t0, 1),
                                   "peak_rss_mb": peak_rss_mb()}, indent=1).encode())  # fmt: skip


if __name__ == "__main__":
    main()
