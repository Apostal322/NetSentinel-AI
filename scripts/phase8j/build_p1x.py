"""Phase 8j: P1x windows, the registered deployable calibration (docs/phase8j/PREREGISTRATION.md
section 2; DATA_INTEGRITY_AUDIT.md section 5).

P1x = all-flow windows (no flow-level cleaning). The hosts that attack DURING THE CALIBRATION
PERIOD are removed from the calibration windows AND from the destination memory that the
evaluation feature `new_dst_frac` is computed against. Everything else is the Phase 8i
"unlabelled" variant: the same streaming (`build_windows.chunks`), the same time midpoint (read
from the Phase 8i meta.json) and the same aggregation. With an empty exclusion list the output
equals cal_unlabelled / eval_unlabelled (tests/unit/test_phase8j_stats.py).

The exclusion list is the keys of the Phase 8i calibration windows labelled attack
(`cal_truth.parquet`): calibration-period labels only, never evaluation labels.

Networks: the Phase 8i development networks plus NF-BoT-IoT-v3 (consumed in Phase 8i; a
development network in Phase 8j). NF-CIC: the Phase 8i target days only.
Output: data/derived/phase8j/p1x/<network>/<domain>/{cal_p1x,eval_p1x}.parquet + meta.json
Usage: uv run python scripts/run_capped.py -- uv run python scripts/phase8j/build_p1x.py nfunsw
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

# build_windows' phase6 import binds the name `common` to scripts/phase6/common.py, so the
# Phase 8i module is loaded under its own name.
_spec = importlib.util.spec_from_file_location("common_8i", ROOT / "scripts/phase8i/common.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

from netsentinel.behavior.windows import aggregate, prepare_flows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("data/derived/phase8j/p1x")


class P1xBuilder:
    """Calibration and evaluation windows from all flows, with `excluded` source hosts kept out
    of the calibration windows and of the destination memory."""

    def __init__(self, mid_ms: int, excluded: set[str]):
        self.mid, self.excluded = mid_ms, sorted(excluded)
        self.seen: set = set()
        self.cal: list[pl.DataFrame] = []
        self.ev: list[pl.DataFrame] = []

    def add(self, frame: pl.DataFrame) -> None:
        flows = prepare_flows(frame)
        cal = flows.filter((pl.col("end_ms") < self.mid) & ~pl.col("src").is_in(self.excluded))
        ev = flows.filter(pl.col("end_ms") >= self.mid)
        if cal.height:
            self.cal.append(aggregate(cal, BW.LEVEL, BW.W, prior_dst=self.seen))
            self.seen |= set(cal["dst"].unique().to_list())
        if ev.height:
            self.ev.append(aggregate(ev, BW.LEVEL, BW.W, known_dst=self.seen))

    def save(self, out: Path, meta: dict) -> None:
        out.mkdir(parents=True, exist_ok=True)
        for part, lst in (("cal", self.cal), ("eval", self.ev)):
            df = pl.concat(lst, how="diagonal_relaxed") if lst else pl.DataFrame()
            df.write_parquet(out / f"{part}_p1x.parquet")
        (out / "meta.json").write_text(json.dumps(meta, indent=1), "utf-8")


def calibration_attackers(domain_dir: Path) -> set[str]:
    p = domain_dir / "cal_truth.parquet"
    return set(pl.read_parquet(p).filter(pl.col("y"))["key"].to_list()) if p.exists() else set()


def build(files: list[Path], dev_cut: bool, src_dir: Path, out: Path, max_rows: int) -> dict:
    t0 = time.perf_counter()
    mid = json.loads((src_dir / "meta.json").read_text("utf-8"))["mid_ms"]
    excluded = calibration_attackers(src_dir)
    b = P1xBuilder(int(mid), excluded)
    n = 0
    for df in BW.chunks(files, dev_cut, max_rows):
        b.add(df)
        n += df.height
        del df
    meta = {"mid_ms": int(mid), "excluded_hosts": len(excluded), "flows": n,
            "memory_destinations": len(b.seen), "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
    b.save(out, meta)
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("network", choices=("nfcic", "nfunsw", "nfton", "nfbot"))
    ap.add_argument("--max-rows", type=int, default=BW.MAX_ROWS)
    a = ap.parse_args()
    src, dev_cut, per_day = BW.NETWORKS[a.network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    if not files:
        sys.exit(f"no ingested files under {src}")
    res = {}
    if per_day:
        for f in files:
            if f.stem not in C.PRIMARY_N1 + C.SECONDARY_N1:
                continue
            res[f.stem] = build([f], dev_cut, C.DERIVED / a.network / f.stem,
                                OUT / a.network / f.stem, a.max_rows)  # fmt: skip
            print(f.stem, res[f.stem], flush=True)
    else:
        res["all"] = build(files, dev_cut, C.DERIVED / a.network / "all", OUT / a.network / "all",
                           a.max_rows)  # fmt: skip
        print(res["all"], flush=True)
    rep = Path("reports/phase8j/p1x") / f"build_{a.network}.json"
    rep.parent.mkdir(parents=True, exist_ok=True)
    rep.write_text(json.dumps({"domains": res, "peak_rss_mb": peak_rss_mb()}, indent=1), "utf-8")


if __name__ == "__main__":
    main()
