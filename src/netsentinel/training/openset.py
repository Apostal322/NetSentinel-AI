"""Experiment 6 / H4: leave-one-attack-family-out (unseen attack) evaluation.

For each held-out family F:
* the supervised binary model is trained WITHOUT any F rows (train) and its threshold is set on
  validation WITHOUT any F rows, at weighted benign FPR <= target_fpr;
* the anomaly detector never uses attack labels; it is fit once on benign train flows and its
  threshold set on benign validation flows;
* fusion = alert if (supervised >= t_s) OR (anomaly >= t_a), with each threshold set at half the
  FPR budget, so the fused benign FPR on validation stays <= target_fpr (union bound).
Evaluation set: ALL rows of F (the model never saw F, in any partition) + benign validation
rows. This is a development-time open-set estimate, not the locked test set.
Detecting F as anomalous measures distribution shift w.r.t. benign traffic; it is not evidence
of "discovering" a new attack.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import polars as pl

from netsentinel.evaluation.metrics import threshold_at_fpr
from netsentinel.ledger import Run
from netsentinel.models.anomaly import ConditionedAnomalyModel
from netsentinel.models.baselines import fit_weighted, make_model
from netsentinel.models.service import service_category_expr
from netsentinel.seed import set_seed
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


def _x(df: pl.DataFrame, feats: list[str]) -> np.ndarray:
    return df.select(feats).to_numpy().astype(np.float32)


def _fpr(score: np.ndarray, thr: float, w: np.ndarray) -> float:
    return float((w * (score > thr)).sum() / w.sum())


def run_openset(cfg: dict[str, Any]) -> list[str]:
    set_seed(cfg["seed"])
    prep = prepare({**cfg, "task": "binary"})
    frame = prep.frame.with_columns(service_category_expr())
    feats = prep.features
    target = cfg.get("target_fpr", 1e-3)

    # Anomaly detector: benign train only, label-free -> shared across held-out families.
    benign_tr = frame.filter((pl.col("split") == "train") & (pl.col("label") == "benign"))
    benign_tr = benign_tr.sample(n=min(benign_tr.height, cfg.get("max_benign_train_rows", 100_000)),
                                 seed=cfg["seed"])  # fmt: skip
    ref = np.random.default_rng(cfg["seed"]).random(benign_tr.height) < 0.2
    an_cfg = cfg.get("anomaly", {"kind": "iforest", "conditioned": False})
    anomaly = ConditionedAnomalyModel(
        kind=an_cfg["kind"], conditioned=an_cfg.get("conditioned", False), seed=cfg["seed"]
    ).fit(
        _x(benign_tr.filter(pl.Series(~ref)), feats),
        benign_tr.filter(pl.Series(~ref))["service"].to_numpy(),
        _x(benign_tr.filter(pl.Series(ref)), feats),
        benign_tr.filter(pl.Series(ref))["service"].to_numpy(),
    )
    benign_val = frame.filter((pl.col("split") == "val") & (pl.col("label") == "benign"))
    w_bv = benign_val["sample_weight"].to_numpy()
    a_bv, _ = anomaly.score(_x(benign_val, feats), benign_val["service"].to_numpy())

    # Hold-out groups: explicit label lists (`holdout_groups`, required when classes have twins
    # in other families - see docs/audit) or, legacy, whole families (`holdout_families`).
    if cfg.get("holdout_groups"):
        groups = {k: list(v) for k, v in cfg["holdout_groups"].items()}
    else:
        fam_labels = frame.group_by("family").agg(pl.col("label").unique())
        lookup = {r["family"]: r["label"] for r in fam_labels.iter_rows(named=True)}
        groups = {f: lookup.get(f, []) for f in cfg["holdout_families"]}
    run_ids = []
    for fam, labels in groups.items():
        run = Run(cfg, name=f"{cfg['experiment']}_without_{fam}")
        held = pl.col("label").is_in(labels)
        seen = frame.filter(~held)
        unseen = frame.filter(held)
        if unseen.height == 0:
            raise ValueError(f"no rows for hold-out group {fam!r} ({labels})")
        run.save_json("holdout_group.json", {"name": fam, "labels": labels})
        tr = seen.filter(pl.col("split") == "train")
        va = seen.filter(pl.col("split") == "val")
        cap = cfg.get("max_train_rows")
        if cap and tr.height > cap:
            tr = tr.sample(n=cap, seed=cfg["seed"])
        model = make_model(cfg.get("model", "lightgbm"), cfg.get("model_params"), cfg["seed"])
        fit_weighted(model, _x(tr, feats), (tr["label"] != "benign").to_numpy().astype(int))

        y_va = (va["label"] != "benign").to_numpy().astype(int)
        s_va = model.predict_proba(_x(va, feats))[:, 1]
        w_va = va["sample_weight"].to_numpy()
        t_sup = threshold_at_fpr(y_va, s_va, target, w_va)
        t_sup_half = threshold_at_fpr(y_va, s_va, target / 2, w_va)
        zeros = np.zeros(len(a_bv), dtype=int)
        t_an = threshold_at_fpr(zeros, a_bv, target, w_bv)
        t_an_half = threshold_at_fpr(zeros, a_bv, target / 2, w_bv)

        s_bv = model.predict_proba(_x(benign_val, feats))[:, 1]
        s_un = model.predict_proba(_x(unseen, feats))[:, 1]
        a_un, _ = anomaly.score(_x(unseen, feats), unseen["service"].to_numpy())
        w_un = unseen["sample_weight"].to_numpy()

        def recall(mask: np.ndarray, w: np.ndarray = w_un) -> float:
            return float((w * mask).sum() / w.sum())

        fused_un = (s_un > t_sup_half) | (a_un > t_an_half)
        fused_bv = (s_bv > t_sup_half) | (a_bv > t_an_half)
        metrics = {
            "unseen_rows": unseen.height,
            "supervised_recall": recall(s_un > t_sup),
            "anomaly_recall": recall(a_un > t_an),
            "fused_recall": recall(fused_un),
            "supervised_benign_val_fpr": _fpr(s_bv, t_sup, w_bv),
            "anomaly_benign_val_fpr": _fpr(a_bv, t_an, w_bv),
            "fused_benign_val_fpr": float((w_bv * fused_bv).sum() / w_bv.sum()),
            "supervised_threshold": t_sup,
            "anomaly_threshold": t_an,
        }
        per_label = (
            unseen.with_columns(
                pl.Series("sup", s_un > t_sup), pl.Series("anom", a_un > t_an),
                pl.Series("fused", fused_un),
            )
            .group_by("label")
            .agg(pl.len().alias("rows"), pl.col("sup").mean(), pl.col("anom").mean(),
                 pl.col("fused").mean())
            .sort("label")
            .to_dicts()
        )  # fmt: skip
        run.save_json("per_label_unseen.json", per_label)
        run.log_metrics(metrics)
        run.finish(notes=f"openset holdout={fam} {cfg['feature_set']}")
        log.info("holdout %s: %s", fam, {k: round(v, 4) for k, v in metrics.items()})
        run_ids.append(run.id)
    return run_ids
