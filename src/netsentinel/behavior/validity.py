"""Phase 8f: calibration validity (docs/phase8f/PLAN.md section 1, CALIBRATION_VALIDITY.md).

Is a scored period still consistent with the calibration that scores it? The assessor
compares block summaries of the scored windows with block summaries of the calibration's
cross-fit held-out windows (stored with the profile):

* blocks of `BLOCK` windows (5 min at 30 s): window features decorrelate by lag 3 (Phase 8f M1);
* statistics per block: share of windows with |z| > `TAIL_Z`, per feature, and share of windows
  scored by the pooled fallback (the dominant false-alarm mechanism, M1);
* max-T block permutation test across the statistics (family-wise over statistics), Holm
  across levels; >= `MIN_BLOCKS` blocks on each side or the level is `untestable`.

A `confirmed_shift` says the period is statistically inconsistent with the calibration. It is
not evidence of a benign change or of an attack (attacks shift tails too), and it never
changes a verdict or an alert.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import polars as pl

BLOCK = 10
TAIL_Z = 3.0
MIN_BLOCKS = 10
N_PERM = 999
ALPHA_CONFIRMED = 0.01
ALPHA_POSSIBLE = 0.05
STATUSES = ("degraded_telemetry", "insufficient_history", "expired", "unreliable_threshold",
            "confirmed_shift", "possible_shift", "valid")  # fmt: skip
WORDING = ("statistical inconsistency between the scored period and the calibration; not by "
           "itself evidence of a benign change or of an attack")  # fmt: skip
# Phase 8e assessment state for each validity status (possible_shift: reason only)
ASSESSMENT_STATE = {"degraded_telemetry": "telemetry_degraded",
                    "insufficient_history": "insufficient_calibration",
                    "expired": "calibration_expired",
                    "unreliable_threshold": "insufficient_calibration",
                    "confirmed_shift": "drift_detected"}  # fmt: skip


def block_summary(win: np.ndarray, z: np.ndarray, fallback: np.ndarray) -> dict[str, Any]:
    """Per-block counts: windows, |z| > TAIL_Z per feature, pooled-fallback windows."""
    win = np.asarray(win, dtype=np.int64)
    if not len(win):
        return {"block": np.zeros(0, np.int64), "n": np.zeros(0, np.int64),
                "tail": np.zeros((0, z.shape[1] if z.ndim == 2 else 0), np.int64),
                "fallback": np.zeros(0, np.int64)}  # fmt: skip
    b = win // BLOCK
    blocks, inv = np.unique(b, return_inverse=True)
    n = np.bincount(inv, minlength=len(blocks))
    tail = np.zeros((len(blocks), z.shape[1]), np.int64)
    np.add.at(tail, inv, (np.abs(np.nan_to_num(z)) > TAIL_Z).astype(np.int64))
    fb = np.bincount(inv, weights=np.asarray(fallback, dtype=float), minlength=len(blocks))
    return {"block": blocks, "n": n, "tail": tail, "fallback": fb.astype(np.int64)}


def merge(a: dict | None, b: dict, keep_last: int | None = None) -> dict:
    """Combine block summaries (streaming); blocks present in both are added."""
    if a is None or not len(a["block"]):
        out = {k: np.array(v) for k, v in b.items()}
    else:
        blocks = np.union1d(a["block"], b["block"])
        out = {"block": blocks}
        for k in ("n", "tail", "fallback"):
            shape = (len(blocks), *np.asarray(a[k]).shape[1:])
            acc = np.zeros(shape, np.int64)
            for src in (a, b):
                idx = np.searchsorted(blocks, src["block"])
                np.add.at(acc, idx, np.asarray(src[k], dtype=np.int64))
            out[k] = acc
    if keep_last is not None and len(out["block"]) > keep_last:
        out = {k: np.asarray(v)[-keep_last:] for k, v in out.items()}
    return out


def level_blocks(prof, windows: pl.DataFrame) -> dict:
    """Block summary of scored windows of one level (z from the final profile)."""
    from netsentinel.behavior.profile import _zs

    if not windows.height or prof.pooled is None:
        return block_summary(np.zeros(0), np.zeros((0, 12)), np.zeros(0))
    z = _zs(prof, windows)
    keys = windows["key"].to_list()
    fb = np.array([prof.level != "global" and k not in prof.keys for k in keys])
    return block_summary(windows["win"].to_numpy(), z, fb)


def _rates(s: dict) -> np.ndarray:
    n = np.maximum(np.asarray(s["n"], dtype=float), 1.0)
    return np.column_stack([np.asarray(s["tail"]) / n[:, None], np.asarray(s["fallback"]) / n])


def shift_test(ref: dict | None, cur: dict, n_perm: int = N_PERM, seed: int = 0,
               names: list[str] | None = None) -> dict[str, Any]:  # fmt: skip
    """Max-T block permutation test of current vs reference block rates."""
    nr = 0 if ref is None else len(ref["block"])
    nc = len(cur["block"])
    out: dict[str, Any] = {"blocks_reference": nr, "blocks_scored": nc}
    if ref is None:
        return {**out, "status": "untestable", "reason": "calibration has no validity reference"}
    if nr < MIN_BLOCKS or nc < MIN_BLOCKS:
        why = f"needs >= {MIN_BLOCKS} blocks of {BLOCK} windows on each side"
        return {**out, "status": "untestable", "reason": why}
    x = np.vstack([_rates(ref), _rates(cur)])
    labels = list(names) if names else [f"tail_{i}" for i in range(x.shape[1] - 1)]
    labels = labels + ["fallback_share"]
    lab = np.r_[np.zeros(nr, bool), np.ones(nc, bool)]
    sd = x.std(axis=0, ddof=1)
    use = sd > 0
    if not use.any():
        return {**out, "status": "tested", "p": 1.0, "statistic": 0.0, "top": None}
    x, sd = x[:, use], sd[use]
    se = sd * np.sqrt(1 / nr + 1 / nc)

    def tstat(lb: np.ndarray) -> np.ndarray:
        return (x[lb].mean(axis=0) - x[~lb].mean(axis=0)) / se

    obs = tstat(lab)
    t_obs = float(np.max(np.abs(obs)))
    rng = np.random.default_rng(seed)
    exceed = 0
    for _ in range(n_perm):
        if np.max(np.abs(tstat(rng.permutation(lab)))) >= t_obs:
            exceed += 1
    labels = [lb for lb, u in zip(labels, use, strict=True) if u]
    j = int(np.argmax(np.abs(obs)))
    return {**out, "status": "tested", "p": (1 + exceed) / (n_perm + 1), "statistic": t_obs,
            "top": labels[j], "top_direction": "higher" if obs[j] > 0 else "lower",
            "reference_rate": float(x[~lab][:, j].mean()),
            "scored_rate": float(x[lab][:, j].mean())}  # fmt: skip


def holm(ps: dict[str, float]) -> dict[str, float]:
    items = sorted(ps.items(), key=lambda kv: kv[1])
    m, adj, run = len(items), {}, 0.0
    for i, (k, p) in enumerate(items):
        run = max(run, min(1.0, (m - i) * p))
        adj[k] = run
    return adj


def assess_validity(profile, blocks: dict[str, dict] | None = None,
                    windows: pl.DataFrame | None = None, *, now_ms: int | None = None,
                    telemetry_health: str | None = None, max_age_h: float = 24.0,
                    n_perm: int = N_PERM, seed: int = 0) -> dict[str, Any]:  # fmt: skip
    """Validity of `profile` for a scored period, given block summaries per level (`blocks`)
    or the raw entity-windows (`windows`, with a `level` column)."""
    from netsentinel.behavior.profile import ALERTING_STATUSES
    from netsentinel.behavior.windows import WINDOW_FEATURES

    cond: dict[str, str] = {}
    if telemetry_health not in (None, "ok"):
        cond["degraded_telemetry"] = f"telemetry health: {telemetry_health}"
    if profile.status not in ALERTING_STATUSES:
        cond["insufficient_history"] = f"calibration status {profile.status}"
    end = (profile.period or {}).get("end_utc_ms")
    if now_ms is not None and end is not None and now_ms - end > max_age_h * 3.6e6:
        cond["expired"] = (f"scored period ends {(now_ms - end) / 3.6e6:.1f} h after the "
                           f"calibration (limit {max_age_h:g} h)")  # fmt: skip
    dev = profile.levels.get("device")
    if dev is not None and dev.pooled is not None:
        diag = getattr(dev, "threshold_diag", None) or {}
        tail = getattr(dev, "tail_fallback_share", None)
        if diag and diag.get("reliable") is False:
            cond["unreliable_threshold"] = "device threshold diagnostics: unreliable"
        elif tail is not None and tail > 0.5 and dev.keys:
            cond["unreliable_threshold"] = "device threshold set by transient sources (8c)"
    if blocks is None:
        blocks = {}
        if windows is not None and windows.height:
            for lv, prof in profile.levels.items():
                blocks[lv] = level_blocks(prof, windows.filter(pl.col("level") == lv))
    tests, ref_blocks = {}, []
    for lv, prof in profile.levels.items():
        ref = getattr(prof, "validity_ref", None)
        if ref is not None:
            ref_blocks.append(len(ref["block"]))
        if lv in blocks:
            tests[lv] = shift_test(ref, blocks[lv], n_perm, seed, list(WINDOW_FEATURES))
    if ref_blocks and max(ref_blocks) < MIN_BLOCKS and "insufficient_history" not in cond:
        cond["insufficient_history"] = (f"calibration has {max(ref_blocks)} reference blocks "
                                        f"(< {MIN_BLOCKS})")  # fmt: skip
    ps = {lv: t["p"] for lv, t in tests.items() if t["status"] == "tested"}
    adj = holm(ps) if ps else {}
    for lv, t in tests.items():
        if lv in adj:
            t["p_holm"] = adj[lv]
    conf = [lv for lv, p in adj.items() if p < ALPHA_CONFIRMED]
    poss = [lv for lv, p in ps.items() if p < ALPHA_POSSIBLE and lv not in conf]
    if conf:
        t = tests[conf[0]]
        cond["confirmed_shift"] = (
            f"{', '.join(conf)}: {t['top']} {t['top_direction']} than in calibration "
            f"(Holm p = {t['p_holm']:.3g}); {WORDING}")  # fmt: skip
    elif poss:
        cond["possible_shift"] = (f"{', '.join(poss)}: unadjusted p < {ALPHA_POSSIBLE}; "
                                  "caution only")  # fmt: skip
    status = next((s for s in STATUSES if s in cond), "valid")
    tested = bool(ps)
    return {"status": status, "conditions": cond, "levels": tests,
            "shift_test": "tested" if tested else "untestable",
            "assessment_state": ASSESSMENT_STATE.get(status),
            "drift_detected": "confirmed_shift" in cond,
            "parameters": {"block_windows": BLOCK, "tail_z": TAIL_Z, "min_blocks": MIN_BLOCKS,
                           "permutations": n_perm, "alpha_confirmed": ALPHA_CONFIRMED,
                           "alpha_possible": ALPHA_POSSIBLE, "max_age_h": max_age_h},
            "wording": WORDING}  # fmt: skip


SHADOW_NOTE = ("shadow evaluation only: the shift test did not meet the pre-declared criterion "
               "C4 on development data (docs/phase8f/CALIBRATION_VALIDITY.md), so it does not "
               "change the assessment, verdicts or alerts")  # fmt: skip


def frame_blocks(profile, frame: pl.DataFrame) -> dict[str, dict]:
    """Block summaries per level for a canonical flow frame (aggregated with the profile's
    frozen destination set, as at scoring time)."""
    from netsentinel.behavior.windows import aggregate, prepare_flows

    if not frame.height:
        return {}
    flows = prepare_flows(frame)
    out = {}
    for lv, prof in profile.levels.items():
        w = aggregate(flows, lv, profile.window_s, known_dst=profile.known_dst)
        out[lv] = level_blocks(prof, w)
    return out


def shadow(profile, blocks: dict[str, dict], **kw) -> dict[str, Any]:
    """assess_validity for opt-in diagnostics (`--validity-shadow`), labelled as not adopted."""
    return {**assess_validity(profile, blocks, **kw), "adopted": False, "note": SHADOW_NOTE}
