"""Evaluation metrics. All functions accept optional `sample_weight` so that metrics on a
stratified subsample can be re-weighted to the prevalence of the full capture."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)


def _w(weight: np.ndarray | None, n: int) -> np.ndarray:
    return np.ones(n) if weight is None else np.asarray(weight, dtype=float)


def expected_calibration_error(
    y: np.ndarray, p: np.ndarray, weight: np.ndarray | None = None, bins: int = 15
) -> float:
    """Weighted ECE with equal-width bins on [0, 1]."""
    w = _w(weight, len(y))
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    total = w.sum()
    err = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            wb = w[m].sum()
            err += wb / total * abs(np.average(y[m], weights=w[m]) - np.average(p[m], weights=w[m]))
    return float(err)


def threshold_at_fpr(
    y: np.ndarray, score: np.ndarray, target_fpr: float, weight: np.ndarray | None = None
) -> float:
    """Smallest threshold whose (weighted) false-positive rate on benign rows is <= target."""
    neg = y == 0
    if not neg.any():
        raise ValueError("threshold_at_fpr needs negative (benign) rows")
    s, w = score[neg], _w(weight, len(y))[neg]
    order = np.argsort(-s)
    s, w = s[order], w[order]
    cum_fp = np.cumsum(w) / w.sum()
    # Thresholds are "score > t" -> pick t at the first benign score whose inclusion exceeds FPR.
    k = np.searchsorted(cum_fp, target_fpr, side="right")
    if k >= len(s):
        return float(np.min(s)) - 1e-12
    return float(s[k])


def binary_metrics(
    y: np.ndarray,
    score: np.ndarray,
    threshold: float,
    weight: np.ndarray | None = None,
    fpr_targets: tuple[float, ...] = (1e-3, 1e-2),
    is_probability: bool = True,
) -> dict[str, float]:
    y = np.asarray(y).astype(int)
    score = np.asarray(score, dtype=float)
    w = _w(weight, len(y))
    pred = (score > threshold).astype(int)
    tp = w[(pred == 1) & (y == 1)].sum()
    fp = w[(pred == 1) & (y == 0)].sum()
    fn = w[(pred == 0) & (y == 1)].sum()
    tn = w[(pred == 0) & (y == 0)].sum()
    out = {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "threshold": float(threshold),
    }
    out["f1"] = (
        2 * out["precision"] * out["recall"] / (out["precision"] + out["recall"])
        if out["precision"] + out["recall"]
        else 0.0
    )
    if len(np.unique(y)) == 2:
        out["pr_auc"] = float(average_precision_score(y, score, sample_weight=w))
        out["roc_auc"] = float(roc_auc_score(y, score, sample_weight=w))
        fpr, tpr, _ = roc_curve(y, score, sample_weight=w)
        for t in fpr_targets:
            out[f"recall_at_fpr_{t:g}"] = float(np.max(tpr[fpr <= t], initial=0.0))
    if is_probability:
        out["brier"] = float(np.average((score - y) ** 2, weights=w))
        out["ece"] = expected_calibration_error(y, score, w)
    return {k: float(v) for k, v in out.items()}


def multiclass_metrics(
    y: np.ndarray, pred: np.ndarray, labels: list[str], weight: np.ndarray | None = None
) -> dict[str, Any]:
    w = _w(weight, len(y))
    p, r, f, support = precision_recall_fscore_support(
        y, pred, labels=labels, sample_weight=w, zero_division=0
    )
    present = [lab for lab in labels if (np.asarray(y) == lab).any()]
    return {
        "macro_f1": float(f1_score(y, pred, labels=present, average="macro", sample_weight=w,
                                   zero_division=0)),
        "weighted_f1": float(f1_score(y, pred, labels=present, average="weighted",
                                      sample_weight=w, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred, sample_weight=w)),
        "per_class": {
            lab: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                  "support_rows": int((np.asarray(y) == lab).sum())}
            for i, lab in enumerate(labels)
        },
        "labels": labels,
        "confusion_matrix": confusion_matrix(y, pred, labels=labels).tolist(),  # unweighted rows
    }  # fmt: skip


def grouped_bootstrap_ci(
    metric: Callable[[np.ndarray], float],
    groups: np.ndarray,
    n_boot: int = 200,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile CI resampling whole groups (e.g. day x time block), not correlated rows.

    `metric` receives an index array into the evaluation rows."""
    rng = np.random.default_rng(seed)
    uniq, inv = np.unique(groups, return_inverse=True)
    members = [np.flatnonzero(inv == g) for g in range(len(uniq))]
    vals = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(uniq), size=len(uniq))
        idx = np.concatenate([members[g] for g in pick])
        try:
            vals.append(metric(idx))
        except (ValueError, KeyError):  # e.g. a resample with one class only (no PR-AUC)
            continue
    if not vals:
        return (float("nan"), float("nan"))
    lo, hi = np.quantile(vals, [alpha / 2, 1 - alpha / 2])
    return float(lo), float(hi)
