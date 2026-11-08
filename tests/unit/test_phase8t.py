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
