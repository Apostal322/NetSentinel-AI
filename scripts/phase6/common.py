"""Shared window-level evaluation for Phase 6 experiments (research code, not product code).

`evaluate(cal, ev, ...)`: cal / ev are canonical flow frames with a numeric `is_attack`
column (labels are used ONLY to report metrics and, for the oracle 'clean' variant, to drop
attack flows from the calibration data). Window labels: an entity-window is an attack window
if any flow assigned to it (by end time) is an attack flow.
Detection delay of a detected attack window = window end - start of its earliest attack flow.
"""

from __future__ import annotations

import math

import numpy as np
import polars as pl

from netsentinel.behavior.calibrate import calibrate_flows
from netsentinel.behavior.monitor import score_flows
from netsentinel.behavior.profile import conformal_threshold
from netsentinel.behavior.windows import WINDOW_FEATURES, _key_expr, aggregate, prepare_flows


def auc(score: np.ndarray, y: np.ndarray) -> float | None:
    pos, neg = score[y == 1], score[y == 0]
    if not len(pos) or not len(neg):
        return None
    order = np.argsort(np.r_[pos, neg], kind="mergesort")
    ranks = np.empty(len(order))
    ranks[order] = np.arange(1, len(order) + 1)
    # average ranks for ties
    allv = np.r_[pos, neg]
    _, inv, cnt = np.unique(allv, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=ranks)
    ranks = sums[inv] / cnt[inv]
    return float((ranks[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def window_truth(ev: pl.DataFrame, level: str, window_s: int) -> pl.DataFrame:
    f = prepare_flows(ev)
    w_ms = window_s * 1000
    start = pl.col("end_ms") - pl.col("dur_ms")
    return (
        f.with_columns((pl.col("end_ms") // w_ms).alias("win"), _key_expr(level))
        .group_by("key", "win")
        .agg(
            (pl.col("is_attack").max() > 0).alias("y"),
            start.filter(pl.col("is_attack") > 0).min().alias("first_attack_start_ms"),
        )
    )


def metrics(scored: pl.DataFrame, truth: pl.DataFrame, hours: float) -> dict:
    d = scored.join(truth, on=["key", "win"], how="left").with_columns(pl.col("y").fill_null(False))
    y = d["y"].to_numpy().astype(int)
    a = d["anomalous"].to_numpy().astype(bool)
    out = {"windows": d.height, "attack_windows": int(y.sum()),
           "recall": float(a[y == 1].mean()) if y.sum() else None,
           "fpr": float(a[y == 0].mean()) if (y == 0).sum() else None,
           "fa_per_h": float((a & (y == 0)).sum()) / hours if hours else None,
           "precision": float((a & (y == 1)).sum() / a.sum()) if a.sum() else None,
           "roc_auc": auc(d["score"].to_numpy(), y)}  # fmt: skip
    det = d.filter(pl.col("anomalous") & pl.col("y"))
    if det.height:
        delay = (det["window_end_ms"] - det["first_attack_start_ms"]).to_numpy() / 1000
        out["median_detection_delay_s"] = float(np.median(delay))
    return out


def iforest_scores(cal_flows: pl.DataFrame, ev_flows: pl.DataFrame, level: str, window_s: int,
                   target_fpr: float, seed: int = 0,
                   fit_fraction: float = 0.7) -> pl.DataFrame:  # fmt: skip
    """Isolation Forest on the same window features (pooled per level), threshold from
    held-out calibration windows, frozen calibration destination set for scoring."""
    from sklearn.ensemble import IsolationForest

    w_ms = window_s * 1000
    win = cal_flows["end_ms"] // w_ms
    lo, hi = int(win.min()), int(win.max())
    cut = lo + int(math.floor((hi - lo + 1) * fit_fraction))
    agg = aggregate(cal_flows, level, window_s)
    fit, hold = agg.filter(pl.col("win") < cut), agg.filter(pl.col("win") >= cut)
    known = set(cal_flows.filter(pl.col("end_ms") < cut * w_ms)["dst"].unique().to_list())
    ev = aggregate(ev_flows, level, window_s, known_dst=known)

    def x(df):
        return np.nan_to_num(df.select(WINDOW_FEATURES).to_numpy().astype(np.float64))

    m = IsolationForest(n_estimators=200, max_samples=min(256, fit.height), random_state=seed,
                        n_jobs=1).fit(x(fit))  # fmt: skip
    thr, _ = conformal_threshold(-m.score_samples(x(hold)), target_fpr)
    s = -m.score_samples(x(ev))
    return ev.select("key", "win", "window_end_ms").with_columns(
        pl.Series("score", s), pl.Series("anomalous", s > thr)
    )


def evaluate(cal: pl.DataFrame, ev: pl.DataFrame, *, window_s: int = 30, target_fpr: float = 0.01,
             levels=("global", "device", "service"), with_iforest: bool = True,
             threshold_method: str = "split") -> dict:  # fmt: skip
    """`threshold_method` defaults to "split", the method Phase 6 used, so its results
    reproduce exactly; Phase 7 passes "crossfit" explicitly."""
    hours = (
        int(ev["flow_end_milliseconds"].max()) - int(ev["flow_end_milliseconds"].min())
    ) / 3.6e6
    res: dict = {"cal_flows": cal.height, "cal_attack_share": float(cal["is_attack"].mean()),
                 "eval_flows": ev.height, "eval_attack_share": float(ev["is_attack"].mean()),
                 "eval_hours": hours}  # fmt: skip
    truths = {lv: window_truth(ev, lv, window_s) for lv in levels}
    variants = {"clean": ("vetted_benign", cal.filter(pl.col("is_attack") == 0)),
                "unlabelled": ("unlabelled", cal)}  # fmt: skip
    for vname, (mode, data) in variants.items():
        if not data.height:
            res[vname] = {"status": "no calibration flows"}
            continue
        prof = calibrate_flows(data, window_s=window_s, mode=mode, target_fpr=target_fpr,
                               threshold_method=threshold_method,
                               levels=tuple(levels))  # fmt: skip
        r: dict = {"status": prof.status}
        if prof.status in ("baseline_ready", "baseline_provisional"):
            s = score_flows(prof, ev)
            for lv in levels:
                d = s.filter(pl.col("level") == lv)
                if d.height:
                    r[f"robustz_{lv}"] = metrics(d, truths[lv], hours)
            if with_iforest:
                cf, ef = prepare_flows(data), prepare_flows(ev)
                for lv in levels:
                    try:
                        sc = iforest_scores(cf, ef, lv, window_s, target_fpr)
                        r[f"iforest_{lv}"] = metrics(sc, truths[lv], hours)
                    except ValueError as exc:  # too few windows
                        r[f"iforest_{lv}"] = {"error": str(exc)}
        res[vname] = r
    return res
