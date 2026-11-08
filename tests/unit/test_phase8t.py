"""Phase 8t: threshold oracles on synthetic data (algorithm invariants, not research outcomes)."""

from __future__ import annotations

import importlib.util
import itertools
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8t_to_test", ROOT / "scripts/phase8t/threshold_oracles.py"
)
TO = importlib.util.module_from_spec(_spec)
sys.modules["phase8t_to_test"] = TO
_spec.loader.exec_module(TO)


def test_global_threshold_respects_budget_and_ties():
    b = np.array([0.1, 0.5, 0.5, 0.5, 0.9])
    for budget in range(6):
        t = TO.global_threshold(b, budget)
        assert (b > t).sum() <= budget
    assert TO.global_threshold(b, 1) == 0.5 and (b > 0.5).sum() == 1
    assert TO.global_threshold(b, 5) == -np.inf
    with pytest.raises(ValueError):
        TO.global_threshold(np.array([np.nan]), 0)


def test_group_curve_costs_are_exact():
    rng = np.random.default_rng(0)
    b, p = rng.random(50).round(1), rng.random(20).round(1)
    c = TO.group_curve(b, p, 10)
    for t, fa, tp in zip(c["t"], c["fa"], c["tp"], strict=True):
        assert fa == (b > t).sum() <= 10 and tp == (p > t).sum()


def test_allocation_matches_brute_force():
    rng = np.random.default_rng(1)
    for _ in range(25):
        curves = [
            TO.group_curve(rng.random(8).round(2), rng.random(rng.integers(0, 6)).round(2), 5)
            for _ in range(3)
        ]
        budget = int(rng.integers(0, 6))
        _, tp, fa = TO.allocate(curves, budget)
        best = 0
        for ix in itertools.product(*[range(len(c["t"])) for c in curves]):
            pairs = list(zip(curves, ix, strict=True))
            if sum(c["fa"][i] for c, i in pairs) <= budget:
                best = max(best, sum(c["tp"][i] for c, i in pairs))
        assert tp == best and fa <= budget


def test_group_oracle_never_beats_budget_and_dominates_global():
    rng = np.random.default_rng(2)
    s = rng.random(2000)
    groups = rng.integers(0, 4, 2000)
    pos = rng.random(2000) < 0.1
    benign = ~pos
    s = np.where(pos & (groups == 2), s + 0.5, s)  # one group separates well
    budget = int(0.01 * benign.sum())
    o = TO.group_oracle(s, groups, benign, pos, budget)
    alert = TO.apply_group_thresholds(s, groups, o["groups"], o["thresholds"], o["t_global"])
    assert (alert & benign).sum() == o["fa"] <= budget and (alert & pos).sum() == o["tp"]
    t0 = TO.global_threshold(s[benign], budget)
    assert o["tp"] >= (s[pos] > t0).sum()  # the single threshold is one feasible allocation


def test_guard_removes_free_parameter_of_benign_poor_group():
    s = np.r_[np.random.default_rng(3).random(1000), np.full(20, 0.01)]
    groups = np.r_[np.zeros(1000, int), np.ones(20, int)]
    pos = np.r_[np.zeros(1000, bool), np.ones(20, bool)]  # an attack-only group with low scores
    benign = ~pos
    raw = TO.group_oracle(s, groups, benign, pos, 10)
    guarded = TO.group_oracle(s, groups, benign, pos, 10, guard_min_benign=100)
    assert raw["tp"] == 20  # memorisation through group composition: −inf at zero cost
    assert guarded["tp"] == 0 and guarded["free_parameters"] == 1


def test_partial_auc_bounds_and_perfect_separation():
    rng = np.random.default_rng(4)
    b = rng.random(10_000)
    assert TO.partial_auc(np.full(10, 2.0), b) == pytest.approx(1.0)
    assert TO.partial_auc(np.full(10, -1.0), b) == pytest.approx(0.0)
    same = TO.partial_auc(rng.random(10_000), b)
    assert 0.0 <= same < 0.03  # a random score has TPR ≈ FPR ≤ 1 %


_spec2 = importlib.util.spec_from_file_location(
    "phase8t_cc_test", ROOT / "scripts/phase8t/conditional_calibration.py"
)
CC = importlib.util.module_from_spec(_spec2)
sys.modules["phase8t_cc_test"] = CC
_spec2.loader.exec_module(CC)


def _cal(seed=5):
    rng = np.random.default_rng(seed)
    g = np.r_[np.zeros(3000, int), np.ones(3000, int), np.full(40, 2)]
    s = np.r_[rng.normal(0, 1, 3000), rng.normal(3, 1, 3000), rng.normal(10, 1, 40)]
    h = rng.integers(0, 300, s.size).astype(str)
    return s, g, h


def test_global_and_group_thresholds():
    s, g, h = _cal()
    d0 = CC.Calibrator("D0", s, g, h)
    assert d0.t_glob == float(np.quantile(s, 0.99, method="inverted_cdf"))
    d1 = CC.Calibrator("D1", s, g, h)
    t = d1.group_thresholds()
    assert (
        t[0] == float(np.quantile(s[g == 0], 0.99, method="inverted_cdf")) and 2 not in t
    )  # sparse → global
    assert (d1.threshold_for(np.array([2]), np.array(["x"])) == d0.t_glob).all()


def test_partial_pooling_limits():
    s, g, h = _cal()
    d1 = CC.Calibrator("D1", s, g, h).group_thresholds()
    d0 = CC.Calibrator("D0", s, g, h).t_glob
    tiny = CC.Calibrator("D2", s, g, h, kappa=1e-6).group_thresholds()
    huge = CC.Calibrator("D2", s, g, h, kappa=1e9).group_thresholds()
    # κ → 0: the group's own quantile, up to one adjacent order statistic (inverted-CDF boundary)
    for k in (0, 1):
        own = np.sort(s[g == k])
        i = int(np.searchsorted(own, d1[k]))
        assert own[max(i - 1, 0)] <= tiny[k] <= own[min(i + 1, own.size - 1)]
    assert all(v == pytest.approx(d0, abs=1e-6) for v in huge.values())
    mid = CC.Calibrator("D2", s, g, h, kappa=500).group_thresholds()
    assert (
        min(d1[0], d0) - 1e-9 <= mid[0] <= max(d1[0], d0) + 1e-9
    )  # shrinks between local and global


def test_reliability_rule_and_host_fallback():
    s, g, h = _cal()
    d3 = CC.Calibrator("D3", s, g, h, d3_tail_hosts=10_000)  # impossible tail support → all global
    assert d3.group_thresholds() == {}
    dh = CC.Calibrator("D_host", s, g, np.where(np.arange(s.size) < 200, "big", h))
    t = dh.threshold_for(np.array([0, 0]), np.array(["big", "never_seen"]))
    assert t[1] == dh.t_glob and "big" in dh.dist


def test_cdf_consistency_and_errors():
    s, g, h = _cal()
    c = CC.Calibrator("D2", s, g, h)
    t = c.threshold_for(g, h)
    v = c.cdf_for(t, g, h)
    assert (v >= 0.99 - 1e-9).all() and (np.diff(c.glob.cdf(np.sort(s))) >= 0).all()
    with pytest.raises(ValueError):
        CC.Calibrator("D0", np.array([np.inf]), np.array([0]), np.array(["a"]))
    assert CC.service_group(np.array([0.9, 0.1]), np.array([1, 7])).tolist() == [3, 2]


def test_matched_budget_reproduces_global_oracle_and_handles_saturation():
    rng = np.random.default_rng(9)
    cal = rng.normal(0, 1, 2000)
    ev = np.r_[rng.normal(2, 1, 3000), rng.normal(5, 1, 100)]  # shifted: many scores above cal max
    benign = np.r_[np.ones(3000, bool), np.zeros(100, bool)]
    c = CC.Calibrator("D0", cal, np.zeros(cal.size, int), np.zeros(cal.size).astype(str))
    v = c.cdf_for(ev, np.zeros(ev.size, int), np.zeros(ev.size).astype(str))
    assert (v[benign] == 1.0).sum() > 30  # saturation present
    budget = 30
    a = CC.matched_budget_alert(v, ev, benign, budget)
    t0 = TO.global_threshold(ev[benign], budget)
    assert (a == (ev > t0)).all() and (a & benign).sum() <= budget and (a & ~benign).sum() > 0
