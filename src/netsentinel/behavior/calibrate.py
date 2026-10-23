"""`netsentinel calibrate`: learn a local behaviour profile from authorised local traffic.

The calibration period is split in time: the first `fit_fraction` of windows fits the
profiles, the remainder (held out) sets the alert thresholds. Modes:
* vetted_benign - the operator asserts the traffic is normal; recorded in the artifact.
* unlabelled    - no such assertion; contamination-limiting trimming (profile.fit_level).
Cold start: fewer than `min_windows` global fit windows -> status `insufficient_history`, no
thresholds, alerting disabled; the artifact says how much more history is needed.

Artifact: <out>/<calibration_id>/profile.joblib + manifest.json (SHA-256, schema version,
period, mode, thresholds, diagnostics, library versions). `load_profile` refuses a corrupt
artifact or an incompatible schema version.
"""

from __future__ import annotations

import json
import math
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import polars as pl

from netsentinel import __version__
from netsentinel.behavior.profile import BehaviorProfile, fit_level, fit_level_crossfit
from netsentinel.behavior.windows import LEVELS, WINDOW_FEATURES, aggregate, prepare_flows
from netsentinel.ledger import file_sha256, git_sha

BEHAVIOR_SCHEMA_VERSION = "behavior-1.1.0"  # 1.1: cross-fit thresholds, diagnostics, statuses
THRESHOLD_METHODS = ("crossfit", "split")


def calibrate_flows(frame: pl.DataFrame, *, window_s: int = 30, mode: str = "vetted_benign",
                    target_fpr: float = 0.01, min_windows: int = 30, fit_fraction: float = 0.7,
                    levels: tuple[str, ...] = LEVELS, top_k: int = 2,
                    service_col: str | None = None,
                    threshold_method: str = "crossfit") -> BehaviorProfile:  # fmt: skip
    if threshold_method not in THRESHOLD_METHODS:
        raise ValueError(f"threshold_method must be one of {THRESHOLD_METHODS}")
    if mode not in ("vetted_benign", "unlabelled"):
        raise ValueError(f"unknown calibration mode {mode!r}")
    if not 0 < target_fpr < 0.5:
        raise ValueError("target_fpr must be in (0, 0.5)")
    flows = prepare_flows(frame, service_col)
    if not flows.height:
        raise ValueError("no flows in calibration data")
    w_ms = window_s * 1000
    win = flows["end_ms"] // w_ms
    lo, hi = int(win.min()), int(win.max())
    n_global = hi - lo + 1
    cut = lo + int(math.floor(n_global * fit_fraction))
    period = {"start_utc_ms": int(flows["end_ms"].min()),
              "end_utc_ms": int(flows["end_ms"].max()), "fit_end_utc_ms": cut * w_ms,
              "global_windows": n_global, "flows": flows.height}  # fmt: skip
    diagnostics: dict[str, Any] = {
        "devices": flows["src"].n_unique(), "destinations": flows["dst"].n_unique(),
        "services": flows["service"].value_counts(sort=True).head(10).to_dicts(),
        "flows_per_window_median": float(
            flows.group_by(win.alias("w")).len()["len"].median() or 0),
    }  # fmt: skip
    need_fit = min_windows
    fit_windows = cut - lo
    status = "baseline_ready" if fit_windows >= need_fit and n_global - fit_windows >= 1 else (
        "insufficient_history")  # fmt: skip
    levels_out = {}
    if status == "baseline_ready":
        windows = {level: aggregate(flows, level, window_s) for level in levels}
        levels_out = calibrate_windows(windows, cut, target_fpr=target_fpr,
                                       min_windows=min_windows, mode=mode, top_k=top_k,
                                       threshold_method=threshold_method)  # fmt: skip
        g = levels_out.get("global")
        if g is not None and not g.threshold_diag.get("reliable", False):
            status = "baseline_provisional"  # thresholds exist but are statistically weak
    else:
        missing_s = (need_fit - fit_windows) / fit_fraction * window_s
        diagnostics["cold_start"] = (
            f"{fit_windows} fit windows of {window_s} s available, {need_fit} required: collect "
            f"about {max(missing_s, window_s) / 60:.0f} more minutes of representative traffic "
            "before calibrated alerting can start")  # fmt: skip
    known_until = cut * w_ms if threshold_method == "split" else int(flows["end_ms"].max()) + 1
    known = set(flows.filter(pl.col("end_ms") < known_until)["dst"].unique().to_list())
    diagnostics["threshold_method"] = threshold_method
    return BehaviorProfile(window_s=window_s, mode=mode, target_fpr=target_fpr,
                           min_windows=min_windows, top_k=top_k, levels=levels_out,
                           known_dst=known, status=status, period=period,
                           diagnostics=diagnostics)  # fmt: skip


def calibrate_windows(windows: dict[str, pl.DataFrame], cut_win: int, *, target_fpr: float,
                      min_windows: int, mode: str, top_k: int = 2,
                      threshold_method: str = "split") -> dict:  # fmt: skip
    """Fit level profiles from pre-aggregated calibration windows.
    split: windows with index below `cut_win` fit the profile, the rest set the thresholds.
    crossfit: time-blocked cross-fitting over all windows (profile.fit_level_crossfit).
    Used by `calibrate_flows` and by chunked (per-day) research pipelines."""
    out = {}
    for level, agg in windows.items():
        if threshold_method == "crossfit":
            out[level] = fit_level_crossfit(agg, level, target_fpr, min_windows, mode, top_k)
        else:
            fit = agg.filter(pl.col("win") < cut_win)
            hold = agg.filter(pl.col("win") >= cut_win)
            out[level] = fit_level(fit, hold, level, target_fpr, min_windows, mode, top_k)
    return out


DOMAIN_CHECK_VERSION = 2


def threat_domain_check(engine, frame: pl.DataFrame, mode: str = "vetted_benign",
                        ratio: float = 2.0, alpha: float = 0.01,
                        min_expected_flags: float = 10.0) -> dict[str, Any]:  # fmt: skip
    """Is the supervised model plausibly in-domain on this network? (version 2)

    On traffic asserted benign, an in-domain model should flag about its validation FPR.
    `supported` = True only if (a) the calibration is vetted benign, (b) there are enough
    flows for the test (expected flags at the validation FPR >= `min_expected_flags`), and
    (c) a one-sided exact binomial test does NOT reject "flag rate <= ratio x validation FPR"
    at level `alpha`. Version 1 (Phase 6: limit max(10 x FPR, 1%)) accepted an unfamiliar CTU
    network with a flag rate 5.4x the validation FPR; see docs/phase7/RELIABILITY.md."""
    from scipy.stats import binom

    scored, missing = engine.score(frame, context="compute")
    flags = int((scored["p_raw"] >= engine.thresholds.threat).sum())
    n = scored.height
    rate = flags / n if n else float("nan")
    rule = engine.threat.get("threshold_rule") or ""
    val_fpr = 1e-3
    if "<=" in rule:
        try:
            val_fpr = float(rule.split("<=")[-1].strip())
        except ValueError:
            pass
    p0 = min(ratio * val_fpr, 1.0)
    p_value = float(binom.sf(flags - 1, n, p0)) if n else 0.0  # P(X >= flags | rate = p0)
    out = {"version": DOMAIN_CHECK_VERSION, "bundle": engine.bundle_id, "flows": n,
           "flags": flags, "flag_rate_on_calibration": rate, "validation_fpr": val_fpr,
           "null_rate": p0, "p_value": p_value, "alpha": alpha,
           "missing_features": missing}  # fmt: skip
    if mode != "vetted_benign":
        return {**out, "supported": False, "reason": "not_vetted_benign"}
    if n * val_fpr < min_expected_flags:
        return {**out, "supported": False, "reason": "insufficient_flows",
                "flows_needed": int(np.ceil(min_expected_flags / val_fpr))}  # fmt: skip
    if p_value < alpha:
        return {**out, "supported": False, "reason": "flag_rate_above_validation_fpr"}
    return {**out, "supported": True, "reason": "flag_rate_compatible_with_validation_fpr"}


def _libs() -> dict[str, str]:
    import sklearn

    return {"python": platform.python_version(), "numpy": np.__version__,
            "polars": pl.__version__, "scikit-learn": sklearn.__version__,
            "netsentinel": __version__}  # fmt: skip


def save_profile(profile: BehaviorProfile, out_dir: str | Path, *, sources: list[dict],
                 operator_statement: str, threat_check: dict | None = None,
                 update_check: dict | None = None) -> Path:  # fmt: skip
    cid = f"calibration-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    out = Path(out_dir) / cid
    out.mkdir(parents=True, exist_ok=False)
    joblib.dump(profile, out / "profile.joblib", compress=3)
    levels = {lv: {"threshold": p.threshold, "threshold_method": p.threshold_method,
                   "threshold_diagnostics": p.threshold_diag,
                   "holdout_outlier_share": p.outlier_share, "fit_windows": p.n_fit_windows,
                   "holdout_windows": p.n_holdout_windows, "own_profiles": len(p.keys),
                   "trimmed_windows": p.trimmed_windows,
                   "trimmed_holdout_windows": p.trimmed_holdout_windows,
                   "tail_fallback_share": getattr(p, "tail_fallback_share", None),
                   "warnings": p.warnings}
              for lv, p in profile.levels.items()}  # fmt: skip
    manifest = {
        "calibration_id": cid,
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "schema_version": BEHAVIOR_SCHEMA_VERSION,
        "features": list(WINDOW_FEATURES),
        "status": profile.status,
        "mode": profile.mode,
        "operator_statement": operator_statement,
        "hyperparameters": {"window_s": profile.window_s, "target_fpr": profile.target_fpr,
                            "min_windows": profile.min_windows, "top_k": profile.top_k},
        "period": profile.period,
        "sources": sources,
        "levels": levels,
        "diagnostics": profile.diagnostics,
        "threat_model_domain_check": threat_check,
        "update_check": update_check,
        "evaluation_status": "not evaluated (thresholds set on held-out calibration windows "
                             "only; no attack-labelled evaluation)",
        "domain_assumption": "valid only for the network and period it was calibrated on",
        "libraries": _libs(),
        "git": git_sha(),
        "sha256": {"profile.joblib": file_sha256(out / "profile.joblib")},
    }  # fmt: skip
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str), "utf-8")
    return out


def load_profile(path: str | Path) -> tuple[BehaviorProfile, dict]:
    path = Path(path)
    mf = path / "manifest.json"
    if not mf.exists():
        raise FileNotFoundError(f"{mf} missing: not a calibration artifact")
    manifest = json.loads(mf.read_text("utf-8"))
    if manifest.get("schema_version") != BEHAVIOR_SCHEMA_VERSION:
        raise ValueError(f"calibration schema {manifest.get('schema_version')} != "
                         f"{BEHAVIOR_SCHEMA_VERSION}; recalibrate")  # fmt: skip
    if manifest.get("features") != list(WINDOW_FEATURES):
        raise ValueError("calibration feature list differs from this code version; recalibrate")
    got = file_sha256(path / "profile.joblib")
    if got != manifest["sha256"]["profile.joblib"]:
        raise ValueError("calibration artifact hash mismatch (corrupted or modified); refusing")
    profile = joblib.load(path / "profile.joblib")
    if not isinstance(profile, BehaviorProfile):
        raise ValueError("calibration artifact does not contain a BehaviorProfile")
    return profile, manifest
