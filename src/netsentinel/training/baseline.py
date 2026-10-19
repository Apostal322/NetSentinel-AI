"""Classical baselines (binary malicious-vs-benign and multiclass attack type).

Validation-only: thresholds and model choices use the validation split. Test metrics are
produced exclusively by `netsentinel evaluate --final` (netsentinel.evaluation.final)."""

from __future__ import annotations

import logging
import time
from typing import Any

import joblib
import numpy as np
import polars as pl

from netsentinel import __version__
from netsentinel.evaluation.metrics import binary_metrics, multiclass_metrics, threshold_at_fpr
from netsentinel.features.schema import FEATURE_SCHEMA_VERSION, schema_fingerprint
from netsentinel.ledger import Run
from netsentinel.models.baselines import fit_weighted, make_model
from netsentinel.seed import set_seed
from netsentinel.training.data import Prepared, prepare

log = logging.getLogger(__name__)


def _cap_rows(X, y, w, max_rows: int | None, seed: int):  # noqa: N803
    if not max_rows or len(y) <= max_rows:
        return X, y, w
    idx = np.sort(np.random.default_rng(seed).choice(len(y), max_rows, replace=False))
    log.info("capping training rows %d -> %d", len(y), max_rows)
    return X[idx], y[idx], w[idx]


def _scores(model, X, task: str):  # noqa: N803
    proba = model.predict_proba(X)
    return proba[:, 1] if task == "binary" else proba


def error_analysis(prep: Prepared, score: np.ndarray, threshold: float, k: int = 25) -> dict:
    val = prep.part("val").with_columns(pl.Series("score", score))
    attack = pl.col("label") != "benign"
    fp = val.filter(~attack & (pl.col("score") > threshold))
    fn = val.filter(attack & (pl.col("score") <= threshold))
    cols = ["day", "row_id", "label", "dst_port", "protocol", "score"]
    return {
        "false_positives_by_day_port": fp.group_by("day", "dst_port")
        .agg(pl.len().alias("rows"), pl.col("sample_weight").sum().alias("weighted"))
        .sort("weighted", descending=True)
        .head(k)
        .to_dicts(),
        "false_negatives_by_label": fn.group_by("label").agg(pl.len().alias("rows")).to_dicts(),
        "recall_by_label": val.filter(attack)
        .group_by("label")
        .agg((pl.col("score") > threshold).mean().alias("recall"), pl.len().alias("rows"))
        .sort("label")
        .to_dicts(),
        "fpr_by_day": val.filter(~attack)
        .group_by("day")
        .agg(
            ((pl.col("score") > threshold) * pl.col("sample_weight")).sum()
            .truediv(pl.col("sample_weight").sum()).alias("fpr")
        )
        .sort("day")
        .to_dicts(),
        "worst_false_positives": fp.sort("score", descending=True).head(k).select(cols).to_dicts(),
        "worst_false_negatives": fn.sort("score").head(k).select(cols).to_dicts(),
    }  # fmt: skip


def feature_importance(model, features: list[str]) -> list[dict[str, Any]]:
    clf = model.steps[-1][1] if hasattr(model, "steps") else model
    if hasattr(clf, "booster_"):
        gain = clf.booster_.feature_importance(importance_type="gain")
        vals = gain / max(gain.sum(), 1e-12)
    elif hasattr(clf, "feature_importances_"):
        vals = clf.feature_importances_
    else:
        return []
    order = np.argsort(-vals)
    return [{"feature": features[i], "importance": float(vals[i])} for i in order]


def run_baselines(cfg: dict[str, Any]) -> list[str]:
    set_seed(cfg["seed"])
    task = cfg.get("task", "binary")
    if task not in ("binary", "label", "family"):
        raise ValueError("task must be binary, label or family")
    prep = prepare(cfg)
    X_tr, y_tr, w_tr = _cap_rows(*prep.xy("train", task), cfg.get("max_train_rows"), cfg["seed"])  # noqa: N806
    X_va, y_va, w_va = prep.xy("val", task)  # noqa: N806
    run_ids = []
    for name in cfg["models"]:
        run = Run(cfg, name=f"{cfg['experiment']}_{name}")
        run.save_json("leakage_report.json", prep.leakage)
        prep.coverage.write_csv(run.dir / "split_coverage.csv")
        prep.frame.select("day", "row_id", "split").write_parquet(run.dir / "split.parquet")
        model = make_model(name, cfg.get("model_params", {}).get(name), cfg["seed"])
        t0 = time.perf_counter()
        fit_weighted(model, X_tr, y_tr, w_tr if cfg.get("train_with_prevalence_weights") else None)
        fit_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        score = _scores(model, X_va, task)
        pred_s = time.perf_counter() - t0
        artifact: dict[str, Any] = {
            "model": model,
            "task": task,
            "features": prep.features,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_fingerprint": schema_fingerprint(prep.features),
            "netsentinel_version": __version__,
            "run_id": run.id,
            "config": cfg,
        }
        timing = {"fit_seconds": fit_s, "val_predict_us_per_row": 1e6 * pred_s / len(X_va),
                  "train_rows": len(y_tr), "val_rows": len(y_va)}  # fmt: skip
        if task == "binary":
            thr = threshold_at_fpr(y_va, score, cfg.get("target_fpr", 1e-3), w_va)
            metrics = binary_metrics(y_va, score, thr, w_va, is_probability=name != "dummy")
            run.save_json("error_analysis_val.json", error_analysis(prep, score, thr))
            artifact["threshold"] = thr
            artifact["threshold_rule"] = f"val weighted FPR <= {cfg.get('target_fpr', 1e-3)}"
            np.save(run.dir / "val_scores.npy", score.astype(np.float32))
        else:
            classes = list(model.classes_)
            pred = np.asarray(classes)[np.argmax(score, axis=1)]
            labels = sorted(set(y_va) | set(classes))
            mc = multiclass_metrics(y_va, pred, labels, w_va)
            run.save_json("multiclass_val.json", mc)
            metrics = {k: mc[k] for k in ("macro_f1", "weighted_f1", "balanced_accuracy")}
            artifact["classes"] = classes
        run.log_metrics(metrics, prefix="val/")
        run.log_metrics(timing, prefix="cost/")
        run.save_json("feature_importance.json", feature_importance(model, prep.features))
        joblib.dump(artifact, run.dir / "model.joblib", compress=3)
        run.finish(notes=f"{task} {cfg['feature_set']} split={prep.split_cfg.protocol}")
        log.info("%s val %s", run.id, {k: round(v, 4) for k, v in metrics.items()})
        run_ids.append(run.id)
    return run_ids
