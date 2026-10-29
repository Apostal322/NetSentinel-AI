"""Phase 8g post-hoc [R]: would the PRODUCT update gate (behavior.registry.update_check) have
required a human review before the scenario 9 refresh that absorbed 71% of the attack windows
(docs/phase8g/V4_FAILURE_ANALYSIS.md, section 3)?

The frozen V4 simulation gated at the device level (scripts/phase8f/recalibration_sim.gate).
The product gate tests the GLOBAL alert rate and strong outliers at every level. This saves the
frozen scenario 9 profile (evaluate.make_profile, unchanged since 121acbf) and runs the
product function on the raw flows of the same candidate period (the first two test hours),
taken from the arrival cache (stream_audit.py cache). Features come from the product
aggregation with the calibration's known destinations, not the frozen Builder's causal
expansion, so the scores can differ slightly from the evaluation's.
Usage: uv run python scripts/phase8g_post/sc9_product_gate.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8g"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8f"))
from evaluate import make_profile  # noqa: E402
from windows import LEVELS, initiators, load_config, load_windows  # noqa: E402

from netsentinel.behavior.registry import update_check  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.live import END  # noqa: E402
from netsentinel.telemetry.frames import records_to_frame  # noqa: E402

KEY = "scenario_9"
ARRIVAL = Path("data/derived/phase8g_post") / KEY / "arrival"
OUT = Path("reports/phase8g_post/sc9_product_gate.json")


def flows(lo: int, hi: int, drop: set[str] | None = None) -> pl.DataFrame:
    frames = []
    for part in sorted(ARRIVAL.glob("part_*.parquet")):
        df = pl.read_parquet(part).filter((pl.col(END) >= lo) & (pl.col(END) < hi))
        if drop:
            df = df.filter(~pl.col("IPV4_SRC_ADDR").is_in(list(drop))
                           & ~pl.col("IPV4_DST_ADDR").is_in(list(drop)))  # fmt: skip
        if df.height:
            frames.append(records_to_frame(df.drop("seq", "keyhash").to_dicts()))
    return pl.concat(frames, how="diagonal_relaxed")


def main() -> None:
    cfg = load_config(ROOT / "configs/phase8g/ctu13.yaml")
    meta = json.loads((Path(cfg["derived_root"]) / KEY / "meta.json").read_text("utf-8"))
    cut = meta["cut_ms"]
    span = int(cfg["refit_every_segments"] * cfg["segment_hours"] * 3.6e6)
    cal = {lv: load_windows(cfg, KEY, "cal", lv) for lv in LEVELS}
    out: dict = {
        "label": "[R] diagnosis on consumed data",
        "candidate_period_ms": [cut, cut + span],
    }
    with tempfile.TemporaryDirectory(prefix="ns-8g-gate-", ignore_cleanup_errors=True) as tmp:
        make_profile(cfg, KEY, cal, "vetted_benign", meta, Path(tmp) / "p")
        del cal
        prof_dir = next((Path(tmp) / "p").iterdir())
        for name, drop in (("candidate_period", None),
                           ("candidate_period_without_initiators", initiators(cfg))):  # fmt: skip
            frame = flows(cut, cut + span, drop)
            r = update_check(prof_dir, frame)
            r["flows"] = frame.height
            r["strong_outliers"] = r["strong_outliers"][:5]
            out[name] = r
            del frame
    out["peak_rss_mb"] = peak_rss_mb()
    OUT.write_text(json.dumps(out, indent=1, default=str), "utf-8")
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
