"""Scoring traffic against a frozen behaviour profile, and baseline-state assessment.

The profile is never updated here (no online learning): adaptation happens only through an
explicit new `calibrate` run, which can exclude anomalous windows and can be rolled back by
pointing at the previous artifact. `baseline_state` reports when that is advisable.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import polars as pl

from netsentinel.behavior.profile import BehaviorProfile
from netsentinel.behavior.windows import aggregate, prepare_flows

STATES = ("collecting_baseline", "baseline_ready", "monitoring", "drift_suspected", "stale")


def score_flows(profile: BehaviorProfile, frame: pl.DataFrame,
                service_col: str | None = None) -> pl.DataFrame:  # fmt: skip
    flows = prepare_flows(frame, service_col)
    parts = [aggregate(flows, lv, profile.window_s, known_dst=profile.known_dst)
             for lv in profile.levels]  # fmt: skip
    if not parts:
        return pl.DataFrame()
    return profile.score(pl.concat(parts, how="diagonal_relaxed"))


def _ks(a: np.ndarray, b: np.ndarray) -> float:
    if not len(a) or not len(b):
        return 0.0
    a, b = np.sort(a), np.sort(b)
    g = np.unique(np.r_[a, b])
    return float(np.max(np.abs(np.searchsorted(a, g, "right") / len(a)
                              - np.searchsorted(b, g, "right") / len(b))))  # fmt: skip


def baseline_state(profile: BehaviorProfile, scored: pl.DataFrame, *,
                   now_ms: int | None = None, max_age_days: float = 30.0,
                   min_windows: int = 60, rate_factor: float = 3.0,
                   ks_limit: float = 0.3) -> dict[str, Any]:  # fmt: skip
    """Global-level drift assessment of a scored period against the calibration held-out
    windows: alert rate far above the target, or a shifted score distribution."""
    if profile.status != "baseline_ready":
        return {"state": "collecting_baseline", "reason": profile.diagnostics.get("cold_start")}
    end = profile.period["end_utc_ms"]
    if now_ms is not None and now_ms - end > max_age_days * 86_400_000:
        return {"state": "stale", "reason": f"calibration older than {max_age_days} days"}
    g = scored.filter(pl.col("level") == "global") if scored.height else scored
    if not g.height or g.height < min_windows:
        return {"state": "monitoring", "reason": f"{g.height} global windows scored; drift "
                f"check needs {min_windows}"}  # fmt: skip
    rate = float(g["anomalous"].mean())
    ks = _ks(g["score"].to_numpy(), profile.levels["global"].holdout_scores)
    info = {"global_alert_rate": rate, "target_fpr": profile.target_fpr, "score_ks": ks,
            "windows": g.height}  # fmt: skip
    if rate > rate_factor * profile.target_fpr or ks > ks_limit:
        return {
            "state": "drift_suspected",
            **info,
            "advice": "review the period; if the change is legitimate, recalibrate on "
            "vetted traffic (the previous artifact remains available for "
            "rollback). Persistent attack traffic must not be recalibrated in.",
        }
    return {"state": "monitoring", **info}
