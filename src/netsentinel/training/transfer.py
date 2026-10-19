"""Cross-dataset transfer: train on a SOURCE dataset, evaluate unchanged on a TARGET dataset.

Protocol (no target information is used for fitting or thresholding):
* Both datasets go through `prepare()` with their own split; the model is fit on the source
  TRAIN split and its threshold set on the source VALIDATION split (benign FPR <= target_fpr).
* Evaluation uses the target VALIDATION split only (the target test split stays protected).
* Reported on the target: PR-AUC / ROC-AUC (ranking transfer), recall and benign FPR at the
  frozen source threshold (operational transfer), and, separately, recall at an oracle
  threshold chosen on the target itself (upper bound on what re-thresholding could recover;
  never used for model selection).
* Feature sets must exist identically in both datasets (same `nf_*` schema).
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import polars as pl

from netsentinel.evaluation.metrics import binary_metrics, threshold_at_fpr
from netsentinel.ledger import Run
from netsentinel.models.baselines import fit_weighted, make_model
from netsentinel.seed import set_seed
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


def _xyw(df: pl.DataFrame, feats: list[str], what: str = ""):
    X = df.select(feats).to_numpy().astype(np.float32)  # noqa: N806
    y = (df["label"] != "benign").to_numpy().astype(int)
    if what and len(np.unique(y)) < 2:
        raise ValueError(f"{what} contains a single class ({int(y.sum())} attack of {len(y)} rows)")
    return X, y, df["sample_weight"].to_numpy()


def run_transfer(cfg: dict[str, Any]) -> list[str]:
    set_seed(cfg["seed"])
    if not cfg["feature_set"].startswith("nf_"):
        raise ValueError("transfer needs a feature set shared by both datasets (nf_*)")
    src_cfg = {**cfg, "data": cfg["source"], "task": "binary"}
    tgt_cfg = {**cfg, "data": cfg["target"], "task": "binary"}
    src = prepare(src_cfg)
    feats = src.features
    tr, va = src.part("train"), src.part("val")
    cap = cfg.get("max_train_rows")
    if cap and tr.height > cap:
        tr = tr.sample(n=cap, seed=cfg["seed"])
    model = make_model(cfg.get("model", "lightgbm"), cfg.get("model_params"), cfg["seed"])
    X, y, _ = _xyw(tr, feats, "source train")  # noqa: N806
    fit_weighted(model, X, y)
    Xv, yv, wv = _xyw(va, feats, "source validation")  # noqa: N806
    sv = model.predict_proba(Xv)[:, 1]
    thr = threshold_at_fpr(yv, sv, cfg.get("target_fpr", 1e-3), wv)
    src_metrics = binary_metrics(yv, sv, thr, wv)
    del src, tr, va, X, Xv

    tgt = prepare(tgt_cfg)
    tv = tgt.part("val")
    Xt, yt, wt = _xyw(tv, feats, "target validation")  # noqa: N806
    st = model.predict_proba(Xt)[:, 1]
    tgt_metrics = binary_metrics(yt, st, thr, wt)
    oracle_thr = threshold_at_fpr(yt, st, cfg.get("target_fpr", 1e-3), wt)
    oracle = binary_metrics(yt, st, oracle_thr, wt)
    per_label = (
        tv.with_columns(pl.Series("hit", st > thr))
        .filter(pl.col("label") != "benign")
        .group_by("label")
        .agg(pl.len().alias("rows"), pl.col("hit").mean().alias("recall_at_source_thr"))
        .sort("label")
        .to_dicts()
    )
    run = Run(cfg, name=f"{cfg['experiment']}_{cfg.get('model', 'lightgbm')}")
    run.log_metrics(src_metrics, prefix="source_val/")
    run.log_metrics(tgt_metrics, prefix="target_val/")
    run.log_metrics({"recall": oracle["recall"], "fpr": oracle["fpr"],
                     "threshold": oracle_thr}, prefix="target_val_oracle/")  # fmt: skip
    run.save_json("per_label_target.json", per_label)
    src_dir, tgt_dir = cfg["source"]["processed_dir"], cfg["target"]["processed_dir"]
    run.finish(notes=f"transfer {src_dir} -> {tgt_dir} {cfg['feature_set']}")
    log.info(
        "transfer %s: source PR-AUC %.4f -> target PR-AUC %.4f, target recall@src-thr %.4f "
        "FPR %.5f",
        run.id,
        src_metrics.get("pr_auc", float("nan")),
        tgt_metrics.get("pr_auc", float("nan")),
        tgt_metrics["recall"],
        tgt_metrics["fpr"],
    )
    return [run.id]
