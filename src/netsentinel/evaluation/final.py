"""One-shot test-set evaluation of a trained run. Re-creates the split deterministically,
checks it equals the split saved at training time, applies the frozen validation threshold,
and refuses to run twice on the same run (the test set is touched once)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
import polars as pl

from netsentinel.evaluation.metrics import binary_metrics, grouped_bootstrap_ci, multiclass_metrics
from netsentinel.features.schema import schema_fingerprint, schema_version_for
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


def evaluate_final(run_dir: str | Path, n_boot: int = 200) -> dict:
    run_dir = Path(run_dir)
    out_path = run_dir / "test_metrics.json"
    if out_path.exists():
        raise RuntimeError(f"{out_path} exists: the test split of this run was already used")
    art = joblib.load(run_dir / "model.joblib")
    version = schema_version_for(art["config"]["feature_set"])
    if art["feature_schema_version"] != version:
        raise ValueError("model was trained with a different feature schema version")
    if art["feature_fingerprint"] != schema_fingerprint(art["features"], version):
        raise ValueError("feature fingerprint mismatch; artifact may be corrupted")
    cfg = art["config"]
    prep = prepare(cfg)
    saved = pl.read_parquet(run_dir / "split.parquet").sort("day", "row_id")
    now = prep.frame.select("day", "row_id", "split").sort("day", "row_id")
    if not saved.equals(now):
        raise RuntimeError("re-created split differs from the training split; aborting")
    task = art["task"]
    X, y, w = prep.xy("test", task)  # noqa: N806
    proba = art["model"].predict_proba(X)
    test = prep.part("test")
    groups = (test["day"] + "_" + (test["event_sec"] // (15 * 60)).cast(pl.Utf8)).to_numpy()
    if task == "binary":
        score = proba[:, 1]
        thr = art["threshold"]
        result = binary_metrics(y, score, thr, w)
        for key in ("pr_auc", "recall", "fpr"):

            def metric(idx, key=key):
                return binary_metrics(y[idx], score[idx], thr, w[idx])[key]

            result[f"{key}_ci95"] = grouped_bootstrap_ci(metric, groups, n_boot=n_boot)
        # Observed test time = number of distinct 15-min (day, block) cells with test rows.
        hours = len(np.unique(groups)) * 0.25
        benign = y == 0
        false_alerts = float(w[benign & (score > thr)].sum())  # prevalence-weighted flow alerts
        result["false_alert_flows_weighted"] = false_alerts
        result["test_hours_observed"] = hours
        result["false_alert_flows_per_hour"] = false_alerts / hours if hours else float("nan")
        np.save(run_dir / "test_scores.npy", score.astype(np.float32))
    else:
        classes = art["classes"]
        pred = np.asarray(classes)[np.argmax(proba, axis=1)]
        labels = sorted(set(y) | set(classes))
        result = multiclass_metrics(y, pred, labels, w)
    result["test_rows"] = int(len(y))
    out_path.write_text(json.dumps(result, indent=2, default=str), "utf-8")
    log.info("final test metrics written to %s", out_path)
    return result
