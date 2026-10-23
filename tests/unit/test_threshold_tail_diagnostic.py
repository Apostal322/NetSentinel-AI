"""Phase 8c regression tests: the threshold-tail diagnostic for the Phase 8b 0-of-4 failure mode
(docs/phase8c/ROOT_CAUSE.md). Transient sources scored against the pooled fallback own the
held-out tail, so the single level-wide threshold rises above a local device's anomaly."""

import json

import numpy as np
import polars as pl

from netsentinel.behavior.calibrate import calibrate_windows, save_profile
from netsentinel.behavior.profile import BehaviorProfile, _zs, window_scores
from netsentinel.behavior.windows import WINDOW_FEATURES

FRAC = {"no_reply_frac", "rst_frac", "udp_share", "upload_share", "new_dst_frac"}


def _row(key, win, rng, shift=0.0, scale=0.2):
    r = {"key": key, "win": win, "level": "device", "window_start_ms": win * 30_000,
         "window_end_ms": (win + 1) * 30_000, "n_flows": 10}  # fmt: skip
    for f in WINDOW_FEATURES:
        if f in FRAC:
            r[f] = float(np.clip(rng.normal(0.2 + shift / 10, 0.03), 0, 1))
        else:
            r[f] = float(rng.normal(3.0 + shift, scale))
    return r


def _windows(n_local_devices=2, transients=0, seed=0):
    rng = np.random.default_rng(seed)
    rows = [_row(f"10.0.0.{d}", w, rng) for d in range(n_local_devices) for w in range(400)]
    # transient Internet sources: one window each, far from the pooled profile
    rows += [_row(f"203.0.113.{i % 250}-{i}", int(rng.integers(0, 400)), rng, shift=6.0)
             for i in range(transients)]  # fmt: skip
    return pl.DataFrame(rows)


def _fit(w):
    lv = calibrate_windows({"device": w}, 0, target_fpr=0.01, min_windows=30,
                           mode="vetted_benign", threshold_method="crossfit")  # fmt: skip
    return lv["device"]


def test_transient_sources_own_the_tail_and_are_flagged():
    lp = _fit(_windows(transients=300))
    assert lp.tail_fallback_share is not None and lp.tail_fallback_share > 0.9
    assert any("WITHOUT an own profile" in w for w in lp.warnings)


def test_consequence_local_anomaly_below_pooled_threshold():
    """Characterises the documented limitation (not a fix): a local device's clear deviation
    (+1.2 on every log feature, i.e. about 6 robust z) stays below a tail-inflated threshold,
    but exceeds the threshold the same profile gets without transient sources."""
    rng = np.random.default_rng(5)
    attack = pl.DataFrame([_row("10.0.0.0", 500 + i, rng, shift=1.2) for i in range(50)])

    def detected(lp):
        prof = BehaviorProfile(window_s=30, mode="vetted_benign", target_fpr=0.01,
                               min_windows=30, top_k=2, levels={"device": lp}, known_dst=set(),
                               status="baseline_ready", period={}, diagnostics={})  # fmt: skip
        s = window_scores(_zs(lp, attack), 2)
        return float((s > lp.threshold).mean()), prof

    with_transients, _ = detected(_fit(_windows(transients=300)))
    without, _ = detected(_fit(_windows(transients=0)))
    assert without > 0.9 and with_transients < 0.1


def test_no_warning_without_transient_sources():
    lp = _fit(_windows(n_local_devices=3, transients=0))
    assert (lp.tail_fallback_share or 0.0) < 0.5
    assert not any("WITHOUT an own profile" in w for w in lp.warnings)


def test_diagnostic_is_written_to_the_calibration_manifest(tmp_path):
    lp = _fit(_windows(transients=300))
    prof = BehaviorProfile(window_s=30, mode="vetted_benign", target_fpr=0.01, min_windows=30,
                           top_k=2, levels={"device": lp}, known_dst=set(),
                           status="baseline_ready", period={}, diagnostics={})  # fmt: skip
    out = save_profile(prof, tmp_path, sources=[], operator_statement="test")
    m = json.loads((out / "manifest.json").read_text("utf-8"))
    assert m["levels"]["device"]["tail_fallback_share"] > 0.9
