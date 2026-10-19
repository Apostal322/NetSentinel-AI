"""Per-label recall and per-day FPR on the TEST split from the scores saved by the one-time
`evaluate --final` (runs/<id>/test_scores.npy). No model is re-evaluated or changed.

Usage: uv run python scripts/test_breakdown.py runs/<id> [runs/<id> ...]
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from netsentinel.training.data import prepare  # noqa: E402

for run in map(Path, sys.argv[1:]):
    art = joblib.load(run / "model.joblib")
    scores = np.load(run / "test_scores.npy")
    test = prepare(art["config"]).part("test")
    assert test.height == len(scores), "test rows do not align with saved scores"
    thr = art["threshold"]
    df = test.with_columns(pl.Series("score", scores), (pl.Series(scores) > thr).alias("alert"))
    per_label = (
        df.filter(pl.col("label") != "benign")
        .group_by("label")
        .agg(pl.len().alias("rows"), pl.col("alert").mean().alias("recall"))
        .sort("label")
    )
    per_day = (
        df.filter(pl.col("label") == "benign")
        .group_by("day")
        .agg(
            pl.len().alias("rows"),
            (
                (pl.col("alert") * pl.col("sample_weight")).sum() / pl.col("sample_weight").sum()
            ).alias("fpr"),
        )
        .sort("day")
    )
    out = {
        "run": run.name,
        "threshold": thr,
        "per_label_recall": per_label.to_dicts(),
        "benign_fpr_by_day": per_day.to_dicts(),
    }
    (run / "test_breakdown.json").write_text(json.dumps(out, indent=2), "utf-8")
    print(f"== {run.name} (threshold {thr:.3g})")
    for r in per_label.iter_rows(named=True):
        print(f"   {r['label']:20s} rows={r['rows']:>6} recall={r['recall']:.3f}")
    for r in per_day.iter_rows(named=True):
        print(f"   benign {r['day']} rows={r['rows']:>6} fpr={r['fpr']:.4f}")
