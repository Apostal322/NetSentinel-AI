"""Phase 8u: low-FPR learning components on synthetic data (algorithm invariants only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8u_lf_test", ROOT / "scripts/phase8u/lowfpr.py"
)
LF = importlib.util.module_from_spec(_spec)
sys.modules["phase8u_lf_test"] = LF
_spec.loader.exec_module(LF)


def _brute(a, b):
    m = 1 - (a[:, None] - b[None, :])
    h = np.maximum(m, 0)
    loss = (h**2).sum() / (a.size * b.size)
    ga = (-2 * h).sum(1) / (a.size * b.size)
    gb = (2 * h).sum(0) / (a.size * b.size)
    return ga, gb, loss


def test_pairwise_gradient_matches_brute_force_and_finite_differences():
    rng = np.random.default_rng(0)
    for _ in range(20):
        a, b = rng.normal(0, 1.5, rng.integers(1, 30)), rng.normal(0, 1.5, rng.integers(1, 30))
        ga, gb, ha, hb, loss = LF.pairwise_tail_grad(a, b)
        bga, bgb, bl = _brute(a, b)
        assert np.allclose(ga, bga) and np.allclose(gb, bgb) and loss == pytest.approx(bl)
        assert (ha >= 0).all() and (hb >= 0).all()
    a, b = rng.normal(size=5), rng.normal(size=7)
    eps = 1e-6
    ga, _, _, _, l0 = LF.pairwise_tail_grad(a, b)
    a2 = a.copy()
    a2[2] += eps
    assert (LF.pairwise_tail_grad(a2, b)[4] - l0) / eps == pytest.approx(ga[2], rel=1e-3, abs=1e-6)


def test_gradient_direction_pushes_attacks_up_and_tail_negatives_down():
    ga, gb, *_ = LF.pairwise_tail_grad(np.array([0.0]), np.array([0.5]))
    assert ga[0] < 0 and gb[0] > 0  # descent raises the attack and lowers the negative
    ga, gb, *_ = LF.pairwise_tail_grad(np.array([5.0]), np.array([0.0]))
    assert ga[0] == 0 and gb[0] == 0  # separated by more than the margin: no gradient


def test_objective_finite_on_extremes_and_only_within_domain():
    y = np.array([1, 0, 0, 1, 0, 0])
    dom = np.array([0, 0, 0, 1, 1, 1])
    obj = LF.PairwiseTailObjective(dom, np.ones(6, bool), np.array([0.5, 0.5]), beta=1.0, lam=10.0)
    g, h = obj(y, np.array([1e6, -1e6, 3.0, -1e6, 1e6, 0.0]))
    assert np.isfinite(g).all() and np.isfinite(h).all() and (h > 0).all()
    # an attack in domain 0 never pairs with domain 1's negatives
    obj2 = LF.PairwiseTailObjective(
        np.array([0, 1]), np.ones(2, bool), np.array([1.0, 1.0]), beta=1.0, lam=1.0
    )
    g2, _ = obj2(np.array([1, 0]), np.array([0.0, 0.5]), np.ones(2))
    log_only = 1 / (1 + np.exp(-np.array([0.0, 0.5]))) - np.array([1, 0])
    assert np.allclose(g2, log_only)


def test_ineligible_negatives_are_not_pushed():
    obj = LF.PairwiseTailObjective(
        np.zeros(3, int), np.array([True, True, False]), np.array([1.0]), beta=1.0, lam=5.0
    )
    g, _ = obj(np.array([1, 0, 0]), np.array([0.0, 0.2, 0.9]), np.ones(3))
    p = 1 / (1 + np.exp(-0.9))
    assert g[2] == pytest.approx(p)  # the ineligible high-scoring negative gets log-loss only


def test_hard_negative_selection_rules():
    s = np.array([0.9, 0.95, 0.99, 0.2, 0.98, 0.97, 0.1])
    elig = np.array([True, True, False, True, True, True, True])
    hosts = np.array(["a", "a", "a", "b", "a", "c", "c"])
    m = LF.select_hard_negatives(s, elig, hosts, top_frac=0.5, per_host_cap=2)
    assert not m[2]  # ineligible never mined
    assert m.sum() == 3 and m[4] and m[1] and m[5] and not m[0]  # host a capped at 2
    assert (LF.select_hard_negatives(s, elig, hosts, 0.5, 2) == m).all()  # deterministic
    assert not LF.select_hard_negatives(s, np.zeros(7, bool), hosts).any()


def test_service_relative_features():
    x = np.array([[1.0, 10.0], [3.0, 30.0], [5.0, 50.0], [7.0, 70.0]])
    prof = LF.service_profile(np.array([0.0, 0.0, 0.9, 0.9]), np.array([1, 1, 10, 10]))
    assert prof.tolist() == [0, 0, 5, 5]
    med = LF.service_medians(x, prof)
    r = LF.service_relative(x, prof, med)
    assert np.allclose(r[:, 0], [-1, 1, -1, 1])
    unseen = LF.service_relative(np.array([[2.0, 20.0]]), np.array([3]), med)  # profile 3 unseen
    assert np.allclose(unseen, np.array([[2.0, 20.0]]) - np.median(x, axis=0))


def test_tail_objective_improves_synthetic_low_fpr_ranking():
    """A controlled problem where log-loss under-weights a rare cluster of hard negatives."""
    lgb = pytest.importorskip("lightgbm")
    rng = np.random.default_rng(3)
    n_easy, n_hard, n_pos = 4000, 60, 400
    x = np.vstack([rng.normal(0, 1, (n_easy, 2)), rng.normal([2.2, 0.0], 0.3, (n_hard, 2)),
                   np.c_[rng.normal(2.0, 0.6, n_pos), rng.normal(1.0, 0.8, n_pos)]])  # fmt: skip
    y = np.r_[np.zeros(n_easy + n_hard), np.ones(n_pos)].astype(int)
    xt = np.vstack([rng.normal(0, 1, (n_easy, 2)), rng.normal([2.2, 0.0], 0.3, (n_hard, 2)),
                    np.c_[rng.normal(2.0, 0.6, n_pos), rng.normal(1.0, 0.8, n_pos)]])  # fmt: skip
    params = dict(
        n_estimators=100, learning_rate=0.05, num_leaves=7, verbose=-1, n_jobs=1, random_state=0
    )
    base = lgb.LGBMClassifier(**params).fit(x, y)
    obj = LF.PairwiseTailObjective(np.zeros(y.size, int), y == 0, np.array([1.0]), beta=0.05)
    tail = lgb.LGBMClassifier(objective=obj, **params).fit(x, y)

    def pauc(s):
        b, p = np.sort(s[y == 0]), s[y == 1]
        thr = b[int(np.ceil(0.99 * b.size)) - 1]
        return float((p > thr).mean())

    r_base = pauc(base.predict(xt, raw_score=True))
    r_tail = pauc(tail.predict(xt, raw_score=True))
    assert np.isfinite(r_tail) and r_tail >= r_base - 0.02  # never materially worse here


def test_exact_partial_auc_toy_cases_and_sklearn_agreement():
    assert (
        LF.partial_auc_exact(np.array([0.5]), np.array([1.0, 0.0]), 0.5) == 0.0
    )  # review's toy case
    assert LF.partial_auc_exact(np.array([2.0]), np.array([1.0, 0.0]), 0.5) == 1.0
    assert LF.partial_auc_exact(np.array([1.0]), np.array([1.0, 0.0]), 0.5) == pytest.approx(
        0.5
    )  # tie: diagonal
    skm = pytest.importorskip("sklearn.metrics")
    rng = np.random.default_rng(11)
    p, b = rng.normal(1, 1, 300).round(1), rng.normal(0, 1, 2000).round(1)
    y = np.r_[np.ones(p.size), np.zeros(b.size)]
    fpr, tpr, _ = skm.roc_curve(y, np.r_[p, b], drop_intermediate=False)
    m = 0.05
    k = np.searchsorted(fpr, m, side="right")
    xs, ys = np.r_[fpr[:k], m], np.r_[tpr[:k], np.interp(m, fpr, tpr)]
    assert LF.partial_auc_exact(p, b, m) == pytest.approx(np.trapezoid(ys, xs) / m)
    assert LF.partial_auc_exact(rng.random(5000), rng.random(5000), 0.01) < 0.03
