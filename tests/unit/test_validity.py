"""Phase 8f calibration-validity assessor (netsentinel.behavior.validity): the block
permutation test holds its level on stationary data, detects tail and composition shifts,
refuses to test with too few blocks, and maps statuses to the Phase 8e assessment."""

import numpy as np
import pytest

from netsentinel.behavior import validity as V


def _summary(rng, blocks, per_block=20, scale=1.0, fallback_p=0.1, shifted_feature=None,
             start=0):  # fmt: skip
    win = np.repeat(np.arange(start, start + blocks * V.BLOCK), per_block // V.BLOCK or 1)
    z = rng.standard_normal((len(win), 12)) * 1.2
    if shifted_feature is not None:
        z[:, shifted_feature] *= scale
    fb = rng.random(len(win)) < fallback_p
    return V.block_summary(win, z, fb)


def test_block_summary_counts():
    win = np.array([0, 1, 9, 10, 25])
    z = np.zeros((5, 12))
    z[0, 3] = 4.0
    z[4, 3] = -5.0
    s = V.block_summary(win, z, np.array([True, False, False, True, True]))
    assert s["block"].tolist() == [0, 1, 2] and s["n"].tolist() == [3, 1, 1]
    assert s["tail"][:, 3].tolist() == [1, 0, 1] and s["fallback"].tolist() == [1, 1, 1]


def test_stationary_periods_rarely_confirm_a_shift():
    rng = np.random.default_rng(1)
    hits = 0
    for seed in range(60):
        ref = _summary(rng, 24)
        cur = _summary(rng, 12, start=10_000)
        hits += V.shift_test(ref, cur, n_perm=199, seed=seed)["p"] < V.ALPHA_CONFIRMED
    assert hits <= 4  # nominal 1% of 60 = 0.6; generous for a 199-permutation p-value


def test_heavier_tail_in_one_feature_is_detected_and_named():
    rng = np.random.default_rng(2)
    ref = _summary(rng, 24)
    cur = _summary(rng, 12, scale=3.0, shifted_feature=5, start=10_000)
    names = [f"f{i}" for i in range(12)]
    t = V.shift_test(ref, cur, n_perm=499, names=names)
    assert t["p"] < V.ALPHA_CONFIRMED and t["top"] == "f5" and t["top_direction"] == "higher"


def test_composition_shift_to_fallback_scored_entities_is_detected():
    rng = np.random.default_rng(3)
    ref = _summary(rng, 24, fallback_p=0.05)
    cur = _summary(rng, 12, fallback_p=0.6, start=10_000)
    t = V.shift_test(ref, cur, n_perm=499)
    assert t["p"] < V.ALPHA_CONFIRMED and t["top"] == "fallback_share"


def test_constant_statistics_are_dropped_and_labels_stay_aligned():
    rng = np.random.default_rng(7)
    ref, cur = _summary(rng, 24, fallback_p=0.0), _summary(rng, 12, fallback_p=0.0, start=10_000)
    ref["tail"][:, :6] = 0
    cur["tail"][:, :6] = 0
    cur["tail"][:, 9] += 5  # shift in feature 9; features 0-5 and the fallback share constant
    t = V.shift_test(ref, cur, n_perm=199, names=[f"f{i}" for i in range(12)])
    assert t["top"] == "f9"


def test_too_few_blocks_or_no_reference_is_untestable():
    rng = np.random.default_rng(4)
    ref = _summary(rng, 24)
    assert V.shift_test(ref, _summary(rng, 5))["status"] == "untestable"
    assert V.shift_test(None, _summary(rng, 20))["status"] == "untestable"


def test_holm_and_merge():
    adj = V.holm({"global": 0.004, "device": 0.03, "service": 0.5})
    assert adj["global"] == pytest.approx(0.012) and adj["device"] == pytest.approx(0.06)
    assert adj["service"] == 0.5
    rng = np.random.default_rng(5)
    a, b = _summary(rng, 4), _summary(rng, 4, start=2 * V.BLOCK)  # blocks 0-3 and 2-5 overlap
    m = V.merge(a, b)
    assert m["block"].tolist() == [0, 1, 2, 3, 4, 5]
    assert m["n"].sum() == a["n"].sum() + b["n"].sum()
    assert V.merge(m, b, keep_last=3)["block"].tolist() == [3, 4, 5]


class _Prof:  # minimal profile stand-ins
    def __init__(self, ref, status="baseline_ready", reliable=True):
        lp = type("LP", (), {})()
        lp.level, lp.pooled, lp.keys, lp.validity_ref = "device", (0, 1), {"a": 1}, ref
        lp.threshold_diag, lp.tail_fallback_share = {"reliable": reliable}, 0.0
        self.levels, self.status, self.period = {"device": lp}, status, {"end_utc_ms": 0}


def test_assess_validity_statuses_and_mapping():
    rng = np.random.default_rng(6)
    ref = _summary(rng, 24)
    ok = V.assess_validity(_Prof(ref), {"device": _summary(rng, 12, start=10_000)},
                           now_ms=3_600_000, n_perm=199)  # fmt: skip
    assert ok["status"] in ("valid", "possible_shift") and ok["assessment_state"] is None
    sh = V.assess_validity(_Prof(ref), {"device": _summary(rng, 12, scale=3.0, shifted_feature=0,
                                                           start=10_000)}, n_perm=199)  # fmt: skip
    assert sh["status"] == "confirmed_shift" and sh["assessment_state"] == "drift_detected"
    assert "not by itself evidence" in sh["conditions"]["confirmed_shift"]
    old = V.assess_validity(_Prof(None), {"device": _summary(rng, 12)}, n_perm=99)
    assert old["shift_test"] == "untestable" and old["status"] == "valid"
    exp = V.assess_validity(_Prof(ref), {}, now_ms=48 * 3_600_000)
    assert exp["status"] == "expired" and exp["assessment_state"] == "calibration_expired"
    tel = V.assess_validity(_Prof(ref), {}, telemetry_health="clock_reset")
    assert tel["status"] == "degraded_telemetry" and "expired" not in tel["conditions"]
    unrel = V.assess_validity(_Prof(ref, reliable=False), {})
    assert unrel["status"] == "unreliable_threshold"
    hist = V.assess_validity(_Prof(_summary(rng, 4)), {})
    assert hist["status"] == "insufficient_history"
