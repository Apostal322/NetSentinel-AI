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
# baseline_provisional: thresholds exist but are statistically weak (see threshold_diagnostics)
ALERTING_STATUSES = ("baseline_ready", "baseline_provisional")


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
    threshold_method: str = "split"
    threshold_diag: dict = field(default_factory=dict)
    outlier_share: float = 0.0
    # Phase 8c: share of the held-out windows above the threshold that were scored against the
    # POOLED fallback (keys without an own profile - e.g. transient external sources)
    tail_fallback_share: float | None = None
    # Phase 8f: block summaries of the held-out windows for the calibration-validity test
    # (behavior.validity); None for calibrations made before Phase 8f
    validity_ref: dict | None = None

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


def threshold_diagnostics(n: int, target_fpr: float) -> dict:
    """Sampling uncertainty of a conformal threshold from n exchangeable held-out scores.

    The k-th order statistic's exceedance probability is Beta(n - k + 1, k) distributed, so even
    without drift the realised FPR varies around its expectation. Phase 6's H1 used about
    100-230 held-out windows at a 1% target: the threshold was the largest or second-largest
    score and the 95% upper bound of its exceedance probability was about 2.5% (RELIABILITY.md
    P2). `windows_needed` = smallest n whose 95% upper bound is <= 2 x target."""
    from scipy.stats import beta

    if n <= 0:
        return {"n": 0, "reliable": False}
    k = min(math.ceil((n + 1) * (1 - target_fpr)), n)
    a, b = n - k + 1, k
    up = float(beta.ppf(0.95, a, b))
    need = n
    while need < 1_000_000:
        kk = min(math.ceil((need + 1) * (1 - target_fpr)), need)
        if beta.ppf(0.95, need - kk + 1, kk) <= 2 * target_fpr:
            break
        need = int(need * 1.25) + 1
    return {"n": n, "k": k, "expected_fpr": a / (n + 1), "fpr_upper95": up,
            "reliable": up <= 2 * target_fpr, "windows_needed_for_2x_target": need}  # fmt: skip


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


def _fit_stats(data: pl.DataFrame, min_windows: int, mode: str, top_k: int,
               trim_passes: int = 2) -> tuple[dict, tuple | None, int, int]:  # fmt: skip
    """Robust per-key and pooled statistics; unlabelled mode trims robust-outlier windows."""
    tmp = LevelProfile(level="tmp")
    trimmed = 0
    for p in range(trim_passes + 1 if mode == "unlabelled" else 1):
        tmp.keys = {}
        counts = data.group_by("key").len()
        for k in counts.filter(pl.col("len") >= min_windows)["key"].to_list():
            tmp.keys[k] = _stats(_x(data.filter(pl.col("key") == k)))
        tmp.pooled = _stats(_x(data)) if data.height else None
        if tmp.pooled is None or p == trim_passes or mode != "unlabelled":
            break
        keep = ~robust_outliers(window_scores(_zs(tmp, data), top_k))
        if keep.all():
            break
        trimmed += int((~keep).sum())
        data = data.filter(pl.Series(keep))
    return tmp.keys, tmp.pooled, trimmed, data.height


TAIL_FALLBACK_WARN = 0.5


def _tail_diagnostic(prof: LevelProfile, hs: np.ndarray, fallback: np.ndarray | None) -> None:
    """Phase 8c root cause of the Phase 8b 0-of-4 detection failure: when most of the held-out
    tail comes from keys scored against the pooled fallback (transient sources with < min_windows
    windows, e.g. Internet hosts contacting an exposed device), the single level-wide threshold
    is set by them and keys with an own profile (local devices) can rarely exceed it. This is a
    diagnostic only; it does not change any decision."""
    if fallback is None or not len(hs) or prof.threshold is None or level_is_global(prof):
        return
    above = hs > prof.threshold
    tail = above if above.any() else hs >= np.max(hs)
    prof.tail_fallback_share = float(fallback[tail].mean())
    if prof.tail_fallback_share > TAIL_FALLBACK_WARN and prof.keys:
        prof.warnings.append(
            f"{prof.tail_fallback_share:.0%} of the held-out windows above the {prof.level} "
            "threshold come from sources WITHOUT an own profile (transient sources scored against "
            "the pooled fallback). The single threshold is set by them: devices with an own "
            "profile may be undetectable at this operating point (Phase 8c, "
            "docs/phase8c/ROOT_CAUSE.md)"
        )


def level_is_global(prof: LevelProfile) -> bool:
    return prof.level == "global"


def _finish(prof: LevelProfile, hs: np.ndarray, level: str, target_fpr: float,
            min_windows: int, mode: str,
            fallback: np.ndarray | None = None) -> LevelProfile:  # fmt: skip
    if mode == "unlabelled":
        # Held-out scores are NOT trimmed: trimming them always lowers the threshold and raised
        # false alerts on clean captures (Phase 6 H1 run 2). Contamination therefore raises the
        # threshold (costing recall, Phase 6 H5) instead of flooding the operator.
        prof.warnings.append(
            "unlabelled calibration: profile fit on trimmed windows; threshold from all held-out "
            "scores (contamination raises it). Persistent malicious behaviour in the "
            "calibration period may be learned as normal"
        )
    out = robust_outliers(hs) if len(hs) else np.zeros(0, bool)
    prof.trimmed_holdout_windows = int(out.sum())
    prof.outlier_share = float(out.mean()) if len(hs) else 0.0
    if prof.outlier_share > 0.05:
        prof.warnings.append(
            f"{prof.outlier_share:.1%} of held-out calibration windows are robust outliers: "
            "possible contamination or a regime change inside the calibration period; review "
            "it before relying on this baseline"
        )
    prof.holdout_scores = np.sort(hs)
    prof.n_holdout_windows = len(hs)
    prof.threshold, reliable = conformal_threshold(hs, target_fpr)
    prof.threshold_diag = threshold_diagnostics(len(hs), target_fpr)
    if not reliable:
        prof.warnings.append(
            f"{len(hs)} held-out windows are too few for target FPR {target_fpr}; threshold = "
            "largest held-out score (FPR not guaranteed)"
        )
    elif not prof.threshold_diag.get("reliable"):
        d = prof.threshold_diag
        prof.warnings.append(
            f"threshold from {d['n']} held-out windows: realised FPR may reach "
            f"{d['fpr_upper95']:.2%} (95% bound) even without drift; about "
            f"{d['windows_needed_for_2x_target']} windows are needed for <= 2x target"
        )
    if level != "global" and not prof.keys:
        prof.warnings.append(f"no {level} key has >= {min_windows} windows; pooled profile only")
    _tail_diagnostic(prof, hs, fallback)
    return prof


def fit_level(fit: pl.DataFrame, holdout: pl.DataFrame, level: str, target_fpr: float,
              min_windows: int, mode: str, top_k: int = 2,
              trim_passes: int = 2) -> LevelProfile:  # fmt: skip
    """Split calibration: fit on the earlier part, threshold on the later (held-out) part."""
    prof = LevelProfile(level=level, threshold_method="split")
    prof.keys, prof.pooled, prof.trimmed_windows, prof.n_fit_windows = _fit_stats(
        fit, min_windows, mode, top_k, trim_passes)  # fmt: skip
    if prof.pooled is None:
        prof.warnings.append("no fit windows")
        return prof
    zh = _zs(prof, holdout) if holdout.height else np.zeros((0, len(WINDOW_FEATURES)))
    hs = window_scores(zh, top_k) if holdout.height else np.array([])
    fb = (
        np.array([k not in prof.keys for k in holdout["key"].to_list()]) if holdout.height else None
    )
    prof = _finish(prof, hs, level, target_fpr, min_windows, mode, fb)
    if holdout.height:
        _validity_ref(prof, holdout["win"].to_numpy(), zh, fb)
    return prof


def _validity_ref(prof: LevelProfile, win: np.ndarray, z: np.ndarray, fb) -> None:
    from netsentinel.behavior.validity import block_summary

    fb = np.zeros(len(win), bool) if fb is None or prof.level == "global" else fb
    prof.validity_ref = block_summary(win, z, fb)


def fit_level_crossfit(windows: pl.DataFrame, level: str, target_fpr: float, min_windows: int,
                       mode: str, top_k: int = 2, folds: int = 5,
                       trim_passes: int = 2) -> LevelProfile:  # fmt: skip
    """Time-blocked cross-fitted calibration: windows are cut into `folds` contiguous time
    blocks; each block is scored by statistics fit on the OTHER blocks, so every calibration
    window yields an out-of-sample score (about 3x more than the 30% split). The final profile
    uses all windows. Exchangeability across blocks is assumed (it fails under strong drift)."""
    prof = LevelProfile(level=level, threshold_method=f"crossfit{folds}")
    if not windows.height:
        prof.warnings.append("no fit windows")
        return prof
    wins = np.sort(windows["win"].unique().to_numpy())
    edges = np.array_split(wins, folds)
    scores, fallback, zs, wins_h = [], [], [], []
    for block in edges:
        if not len(block):
            continue
        inside = pl.col("win").is_between(int(block[0]), int(block[-1]))
        train, test = windows.filter(~inside), windows.filter(inside)
        tmp = LevelProfile(level=level)
        tmp.keys, tmp.pooled, _, _ = _fit_stats(train, min_windows, mode, top_k, trim_passes)
        if tmp.pooled is not None and test.height:
            z = _zs(tmp, test)
            scores.append(window_scores(z, top_k))
            fallback.append(np.array([k not in tmp.keys for k in test["key"].to_list()]))
            zs.append(z)
            wins_h.append(test["win"].to_numpy())
    prof.keys, prof.pooled, prof.trimmed_windows, prof.n_fit_windows = _fit_stats(
        windows, min_windows, mode, top_k, trim_passes)  # fmt: skip
    if prof.pooled is None:
        prof.warnings.append("no fit windows")
        return prof
    hs = np.concatenate(scores) if scores else np.array([])
    fb = np.concatenate(fallback) if fallback else None
    prof = _finish(prof, hs, level, target_fpr, min_windows, mode, fb)
    if zs:
        _validity_ref(prof, np.concatenate(wins_h), np.vstack(zs), fb)
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
                pl.Series("anomalous", s > thr if self.status in ALERTING_STATUSES
                          else np.zeros(len(s), bool)),
                pl.Series("model_scope", [prof.scope_for(k) if level != "global" else "global"
                                          for k in w["key"].to_list()]),
                pl.Series("explanation", expl, dtype=pl.List(pl.Utf8)),
            ))  # fmt: skip
        if not out:
            return pl.DataFrame()
        return pl.concat(out, how="vertical").sort("win", "level", "key")
