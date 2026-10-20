"""Local behaviour profiles: robust per-entity baselines with hierarchical fallback.

Fit:   per (level, key) median and scaled MAD of each window feature, from the FIT part of the
       calibration period. Keys with fewer than `min_windows` windows get no own profile.
Score: robust |z| per feature against the most specific available profile
       (device -> pooled devices -> global statistics; service -> pooled services); window
       score = mean of the `top_k` largest |z| (default 2).
Threshold: per level, the conformal (1 - target_fpr) quantile of scores of HELD-OUT
       calibration windows (later part of the calibration period).
Severity: empirical percentile (0-100) of the score among held-out calibration windows -
       a `normalized_non_probability`, never a probability of attack.

Unlabelled mode: iterative trimming - after each fit, windows whose score is a robust outlier
(median + 4 scaled MAD of the scores, at most 20%) are dropped and the profile is refit. The
threshold uses ALL held-out windows; their outliers are only counted for review. Trimming
limits, but cannot exclude, persistent malicious behaviour that dominates the calibration period;
the artifact records how much was trimmed so the operator can review it.
"""

from __future__ import annotations

import math
import warnings
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import polars as pl

from netsentinel.behavior.windows import EXPLAIN, WINDOW_FEATURES

FRACTION_FEATURES = {"no_reply_frac", "rst_frac", "udp_share", "upload_share", "new_dst_frac"}
SCALE_FLOOR_LOG = 0.25
SCALE_FLOOR_FRAC = 0.15
POOLED = "__pooled__"


def _stats(x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Per-feature median and floored scaled MAD, ignoring undefined (NaN) values."""
    with warnings.catch_warnings():  # all-NaN column (feature never defined) -> 0
        warnings.simplefilter("ignore", RuntimeWarning)
        med = np.nan_to_num(np.nanmedian(x, axis=0))
        mad = np.nan_to_num(1.4826 * np.nanmedian(np.abs(x - med), axis=0))
    floor = np.array([SCALE_FLOOR_FRAC if f in FRACTION_FEATURES else SCALE_FLOOR_LOG
                      for f in WINDOW_FEATURES])  # fmt: skip
    return med, np.maximum(mad, floor)


@dataclass
class LevelProfile:
    level: str
    keys: dict[str, tuple[np.ndarray, np.ndarray]] = field(default_factory=dict)
    pooled: tuple[np.ndarray, np.ndarray] | None = None
    threshold: float | None = None
    holdout_scores: np.ndarray | None = None
    n_fit_windows: int = 0
    n_holdout_windows: int = 0
    trimmed_windows: int = 0
    trimmed_holdout_windows: int = 0
    warnings: list[str] = field(default_factory=list)

    def scope_for(self, key: str) -> str:
        return key if key in self.keys else POOLED

    def stats_for(self, key: str):
        return self.keys.get(key, self.pooled)


def _x(df: pl.DataFrame) -> np.ndarray:
    return df.select(WINDOW_FEATURES).to_numpy().astype(np.float64)


def _zs(prof: LevelProfile, df: pl.DataFrame) -> np.ndarray:
    X = _x(df)  # noqa: N806
    names = list(prof.keys)
    meds = np.vstack([prof.keys[k][0] for k in names] + [prof.pooled[0]])
    scales = np.vstack([prof.keys[k][1] for k in names] + [prof.pooled[1]])
    pos = {k: i for i, k in enumerate(names)}
    idx = np.array([pos.get(k, len(names)) for k in df["key"].to_list()], dtype=np.int64)
    return np.nan_to_num((X - meds[idx]) / scales[idx], nan=0.0)  # undefined feature: z = 0


def window_scores(Z: np.ndarray, top_k: int = 2) -> np.ndarray:  # noqa: N803
    a = np.sort(np.abs(Z), axis=1)[:, ::-1]
    return a[:, :top_k].mean(axis=1)


def conformal_threshold(scores: np.ndarray, target_fpr: float) -> tuple[float, bool]:
    """Finite-sample (split-conformal) upper quantile; returns (threshold, reliable).
    Unreliable when there are too few held-out windows to estimate that tail."""
    n = len(scores)
    if n == 0:
        return math.inf, False
    k = math.ceil((n + 1) * (1 - target_fpr))
    s = np.sort(scores)
    if k > n:  # too few held-out windows for this FPR: alert only above the largest one
        return float(s[-1]), False
    return float(s[k - 1]), True


def robust_outliers(s: np.ndarray, k: float = 4.0, max_share: float = 0.2) -> np.ndarray:
    """Mask of scores far above the bulk (median + k * scaled MAD), at most `max_share` of
    them (the largest). Clean data: almost nothing is flagged; a contaminating cluster that is
    far from the bulk is removed. Revised after the H1 run (see DEVELOPMENT_LOG): the first
    version always trimmed a fixed top quantile, which inflated false alerts on clean data."""
    if not len(s):
        return np.zeros(0, bool)
    med = np.median(s)
    mad = 1.4826 * np.median(np.abs(s - med))
    out = s > med + k * max(mad, 1e-9)
    if out.mean() > max_share:
        out = s > np.quantile(s, 1 - max_share)
    return out


def fit_level(fit: pl.DataFrame, holdout: pl.DataFrame, level: str, target_fpr: float,
              min_windows: int, mode: str, top_k: int = 2,
              trim_passes: int = 2) -> LevelProfile:  # fmt: skip
    prof = LevelProfile(level=level)
    data = fit
    for p in range(trim_passes + 1 if mode == "unlabelled" else 1):
        prof.keys = {}
        counts = data.group_by("key").len()
        for k in counts.filter(pl.col("len") >= min_windows)["key"].to_list():
            prof.keys[k] = _stats(_x(data.filter(pl.col("key") == k)))
        prof.pooled = _stats(_x(data)) if data.height else None
        if prof.pooled is None or p == trim_passes or mode != "unlabelled":
            break
        keep = ~robust_outliers(window_scores(_zs(prof, data), top_k))
        if keep.all():
            break
        prof.trimmed_windows += int((~keep).sum())
        data = data.filter(pl.Series(keep))
    prof.n_fit_windows = data.height
    if prof.pooled is None:
        prof.warnings.append("no fit windows")
        return prof
    hs = window_scores(_zs(prof, holdout), top_k) if holdout.height else np.array([])
    if mode == "unlabelled":
        # Held-out windows are NOT trimmed: trimming them always lowers the threshold and
        # raised false alerts on clean captures (H1 run 2). Contamination therefore raises the
        # threshold (costing recall, measured in H5) instead of flooding the operator.
        prof.trimmed_holdout_windows = int(robust_outliers(hs).sum()) if len(hs) else 0
        prof.warnings.append(
            "unlabelled calibration: profile fit on trimmed windows; threshold from all held-out "
            "windows (contamination raises it). Persistent malicious behaviour in the "
            "calibration period may be learned as normal"
        )
    prof.holdout_scores = np.sort(hs)
    prof.n_holdout_windows = len(hs)
    prof.threshold, reliable = conformal_threshold(hs, target_fpr)
    if not reliable:
        prof.warnings.append(
            f"{len(hs)} held-out windows are too few for target FPR {target_fpr}; threshold = "
            "largest held-out score (FPR not guaranteed)"
        )
    if level != "global" and not prof.keys:
        prof.warnings.append(f"no {level} key has >= {min_windows} windows; pooled profile only")
    return prof


def explain_row(z: np.ndarray, top: int = 3, min_abs: float = 3.0) -> list[str]:
    idx = [i for i in np.argsort(-np.abs(z))[:top] if abs(z[i]) >= min_abs]
    return [f"{EXPLAIN[WINDOW_FEATURES[i]]}_{'above' if z[i] > 0 else 'below'}_local_baseline"
            for i in idx]  # fmt: skip


@dataclass
class BehaviorProfile:
    window_s: int
    mode: str  # vetted_benign | unlabelled
    target_fpr: float
    min_windows: int
    top_k: int
    levels: dict[str, LevelProfile]
    known_dst: set[str]
    status: str  # baseline_ready | insufficient_history
    period: dict[str, Any]
    diagnostics: dict[str, Any]

    def score(self, windows: pl.DataFrame) -> pl.DataFrame:
        """Score entity-windows of any level present in the profile."""
        out = []
        for level, prof in self.levels.items():
            w = windows.filter(pl.col("level") == level)
            if not w.height or prof.pooled is None:
                continue
            Z = _zs(prof, w)  # noqa: N806
            s = window_scores(Z, self.top_k)
            hs = prof.holdout_scores if prof.holdout_scores is not None else np.array([])
            sev = (np.searchsorted(hs, s, side="right") / len(hs) * 100) if len(hs) else (
                np.full(len(s), np.nan))  # fmt: skip
            thr = prof.threshold if prof.threshold is not None else math.inf
            expl = [explain_row(row) for row in Z]
            out.append(w.select("level", "key", "win", "window_start_ms", "window_end_ms",
                                "n_flows").with_columns(
                pl.Series("score", s),
                pl.Series("severity", sev),
                pl.lit(thr).alias("threshold"),
                pl.Series("anomalous", s > thr if self.status == "baseline_ready"
                          else np.zeros(len(s), bool)),
                pl.Series("model_scope", [prof.scope_for(k) if level != "global" else "global"
                                          for k in w["key"].to_list()]),
                pl.Series("explanation", expl, dtype=pl.List(pl.Utf8)),
            ))  # fmt: skip
        if not out:
            return pl.DataFrame()
        return pl.concat(out, how="vertical").sort("win", "level", "key")
