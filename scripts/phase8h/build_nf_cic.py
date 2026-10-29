"""Phase 8h: device windows of the NF-CIC-IDS2018-v3 DEVELOPMENT part, one domain per day
(docs/phase8h/PREREGISTRATION.md section 2).

Development part = flows ending in the first 78% of each day's time span; the consumed final
test starts at 80% (scripts/phase6/eval_nf_dev.read_day). Within a day: calibration = flows
ending before the midpoint of that development span, evaluation = the rest, with the Phase 8b
`WindowBuilder` (30 s device windows, clean and unlabelled calibration, truth per window).

`infiltration` flows stay in the traffic (they are real flows) but every evaluation window
containing one is listed in noisy.parquet and excluded from positives and negatives by the
Phase 8h evaluation (label noise: 84.5% identical to benign, docs/datasets).
Output: data/derived/phase8h/nf_cic/<day>/ and reports/phase8h/nf_cic_windows.json.
Usage: uv run python scripts/phase8h/build_nf_cic.py [--days 2018-02-14,...]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(ROOT / "scripts" / "phase6"))
from eval_nf_dev import DEV_SHARE, read_day  # noqa: E402
from harness import W, WindowBuilder  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

SRC = Path("data/interim/nf_cicids2018_v3")
OUT = Path("data/derived/phase8h/nf_cic")
REPORT = Path("reports/phase8h/nf_cic_windows.json")
NOISY = "infiltration"


def build_day(path: Path) -> dict:
    t0 = time.perf_counter()
    day = read_day(path, []).sort("flow_end_milliseconds")
    if day.height == 0:
        return {"status": "empty"}
    end = day["flow_end_milliseconds"]
    lo, hi = int(end.min()), int(end.max())
    mid = lo + (hi - lo) // 2
    b = WindowBuilder(mid)
    b.add(day)
    out = OUT / path.stem
    b.save(out, {"source": f"NF-CIC-IDS2018-v3 development part {path.stem}",
                 "dev_share": DEV_SHARE})  # fmt: skip
    ev = day.filter(pl.col("flow_end_milliseconds") >= mid)
    noisy = (ev.filter(pl.col("label") == NOISY)
             .select(pl.col("ipv4_src_addr").alias("key"),
                     (pl.col("flow_end_milliseconds") // (W * 1000)).alias("win"))
             .unique())  # fmt: skip
    noisy.write_parquet(out / "noisy.parquet")
    tr = pl.read_parquet(out / "truth.parquet")
    att = tr.filter(pl.col("y")).join(noisy, on=["key", "win"], how="anti")
    labels = ev.group_by("label").len().sort("len", descending=True)
    return {"flows_dev": day.height, "eval_flows": ev.height,
            "eval_labels": dict(labels.iter_rows()),
            "cal_windows_clean": pl.read_parquet(out / "cal_clean.parquet").height,
            "eval_windows": tr.height, "attack_windows": att.height,
            "attack_entities": att["key"].n_unique(), "noisy_windows": noisy.height,
            "entities": tr["key"].n_unique(), "seconds": time.perf_counter() - t0}  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days")
    a = ap.parse_args()
    files = sorted(SRC.glob("[0-9]*.parquet"))
    if a.days:
        files = [f for f in files if f.stem in a.days.split(",")]
    t0 = time.perf_counter()
    res = {}
    for f in files:
        res[f.stem] = build_day(f)
        print(f.stem, json.dumps(res[f.stem]), flush=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    prev = json.loads(REPORT.read_text("utf-8"))["days"] if REPORT.exists() else {}
    out = {"label": "[E] development data", "days": {**prev, **res},
           "seconds": time.perf_counter() - t0, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    REPORT.write_text(json.dumps(out, indent=1, default=str), "utf-8")


if __name__ == "__main__":
    main()
