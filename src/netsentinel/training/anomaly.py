"""Experiment 3: normal-behaviour (anomaly) models, global vs service-conditioned (H2).

Detectors are fit on BENIGN train flows only. 20 % of benign train flows are held out as the
score reference (see netsentinel.models.anomaly). Validation attacks + benign are used to
compare variants; thresholds are set on validation benign at a target FPR."""

from __future__ import annotations

import logging
import time
from typing import Any

import joblib
import numpy as np
import polars as pl

from netsentinel import __version__
from netsentinel.evaluation.metrics import binary_metrics, threshold_at_fpr
from netsentinel.features.schema import FEATURE_SCHEMA_VERSION, schema_fingerprint
from netsentinel.ledger import Run
from netsentinel.models.anomaly import ConditionedAnomalyModel
from netsentinel.models.service import service_category_expr
from netsentinel.seed import set_seed
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


def _matrix(df: pl.DataFrame, features: list[str]) -> np.ndarray:
    return df.select(features).to_numpy().astype(np.float32)


def run_anomaly(cfg: dict[str, Any]) -> list[str]:
    set_seed(cfg["seed"])
    prep = prepare({**cfg, "task": "binary"})
    frame = prep.frame.with_columns(service_category_expr())
    rng = np.random.default_rng(cfg["seed"])

    benign_tr = frame.filter((pl.col("split") == "train") & (pl.col("label") == "benign"))
    cap = cfg.get("max_benign_train_rows", 100_000)
    if benign_tr.height > cap:
        benign_tr = benign_tr.sample(n=cap, seed=cfg["seed"])
    is_ref = rng.random(benign_tr.height) < cfg.get("reference_fraction", 0.2)
    fit_df, ref_df = benign_tr.filter(~pl.Series(is_ref)), benign_tr.filter(pl.Series(is_ref))
    val = frame.filter(pl.col("split") == "val")
    X_val = _matrix(val, prep.features)  # noqa: N806
    y_val = (val["label"] != "benign").to_numpy().astype(int)
    w_val = val["sample_weight"].to_numpy()

    run_ids = []
    for variant in cfg["variants"]:
        name = f"{variant['kind']}_{'cond' if variant.get('conditioned') else 'global'}"
        run = Run(cfg, name=f"{cfg['experiment']}_{name}")
        run.save_json("leakage_report.json", prep.leakage)
        prep.frame.select("day", "row_id", "split").write_parquet(run.dir / "split.parquet")
        model = ConditionedAnomalyModel(
            kind=variant["kind"],
            conditioned=bool(variant.get("conditioned")),
            min_rows=variant.get("min_rows", 2000),
            seed=cfg["seed"],
            params=variant.get("params", {}),
        )
        t0 = time.perf_counter()
        model.fit(
            _matrix(fit_df, prep.features), fit_df["service"].to_numpy(),
            _matrix(ref_df, prep.features), ref_df["service"].to_numpy(),
        )  # fmt: skip
        fit_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        score, used = model.score(X_val, val["service"].to_numpy())
        pred_s = time.perf_counter() - t0
        thr = threshold_at_fpr(y_val, score, cfg.get("target_fpr", 1e-2), w_val)
        metrics = binary_metrics(y_val, score, thr, w_val, is_probability=False)
        scored = val.with_columns(pl.Series("score", score), pl.Series("used_context", used))
        per_label = (
            scored.filter(pl.col("label") != "benign")
            .group_by("label")
            .agg((pl.col("score") > thr).mean().alias("recall"), pl.len().alias("rows"),
                 pl.col("score").median().alias("median_score"))
            .sort("label")
            .to_dicts()
        )  # fmt: skip
        per_service_fpr = (
            scored.filter(pl.col("label") == "benign")
            .group_by("service")
            .agg(((pl.col("score") > thr) * pl.col("sample_weight")).sum()
                 .truediv(pl.col("sample_weight").sum()).alias("fpr"), pl.len().alias("rows"))
            .sort("rows", descending=True)
            .to_dicts()
        )  # fmt: skip
        run.save_json("per_label_val.json", per_label)
        run.save_json("per_service_benign_fpr_val.json", per_service_fpr)
        run.log_metrics(metrics, prefix="val/")
        run.log_metrics({"fit_seconds": fit_s, "val_predict_us_per_row": 1e6 * pred_s / len(val),
                         "fit_rows": fit_df.height, "reference_rows": ref_df.height,
                         "contexts": len(model.models_) - 1}, prefix="cost/")  # fmt: skip
        np.save(run.dir / "val_scores.npy", score.astype(np.float32))
        joblib.dump(
            {
                "model": model,
                "task": "anomaly",
                "features": prep.features,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_fingerprint": schema_fingerprint(prep.features),
                "netsentinel_version": __version__,
                "threshold": thr,
                "threshold_rule": f"val weighted benign FPR <= {cfg.get('target_fpr', 1e-2)}",
                "run_id": run.id,
                "config": cfg,
            },
            run.dir / "model.joblib",
            compress=3,
        )
        run.finish(notes=f"anomaly {name} {cfg['feature_set']} split={prep.split_cfg.protocol}")
        log.info("%s val %s", run.id, {k: round(v, 4) for k, v in metrics.items()})
        run_ids.append(run.id)
    return run_ids
