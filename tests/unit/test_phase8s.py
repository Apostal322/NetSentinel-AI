"""Phase 8s: sampling designs, simulated reviewer and design-based estimators (synthetic data).
These tests check behaviour, not the research hypotheses."""

from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8s_ac_test", ROOT / "scripts/phase8s/active_calibration.py"
)
AC = importlib.util.module_from_spec(_spec)
sys.modules["phase8s_ac_test"] = AC
_spec.loader.exec_module(AC)


def _hosts(seed=0):
    """A heavy-tailed population: many silent single-window hosts, a few heavy benign hosts that
    hold the score tail, and two heavy attackers."""
    rng = np.random.default_rng(seed)
    n_h = np.r_[np.ones(400, int), rng.integers(20, 60, 20), [400, 300]]
    mal = np.r_[np.zeros(420, bool), [True, True]]
    inv = np.repeat(np.arange(n_h.size), n_h)
    heavy = np.repeat(n_h > 1, n_h)
    benign_s = np.where(heavy, rng.beta(2, 3, inv.size), rng.beta(1, 50, inv.size))
    s = np.where(np.repeat(mal, n_h), rng.beta(9, 1, inv.size), benign_s)
    return n_h, mal, inv, s


@pytest.mark.parametrize("k", [0, 1, 7.5, 30, 10_000])
def test_designs_meet_expected_budget_and_bounds(k):
    n_h, *_ = _hosts()
    tail = (n_h > 30).astype(float) * n_h
    for pi in (AC.pi_random_host(n_h, k), AC.pi_pps(n_h, k), AC.pi_random_window(n_h, k),
               AC.pi_stratified(n_h, k), AC.pi_tail(n_h, tail, k)):  # fmt: skip
        assert ((pi >= 0) & (pi <= 1)).all()
        expect = min(k, n_h.size)
        assert abs(pi.sum() - expect) < 0.05 * max(expect, 1) + 1e-6 or k == 0


def test_positivity_for_probability_designs():
    n_h, *_ = _hosts()
    for pi in (AC.pi_random_host(n_h, 10), AC.pi_pps(n_h, 10), AC.pi_random_window(n_h, 10),
               AC.pi_stratified(n_h, 10)):  # fmt: skip
        assert (pi > 0).all()  # every host can be reviewed: Horvitz–Thompson weights exist


def test_pps_caps_dominant_host_at_one():
    n_h = np.r_[[10_000], np.ones(50, int)]
    pi = AC.pi_pps(n_h, 5)
    assert pi[0] == 1.0 and abs(pi.sum() - 5) < 1e-9


def test_one_host_and_silent_hosts():
    assert AC.pi_pps(np.array([5]), 3)[0] == 1.0
    pi = AC.pi_pps(np.array([0, 0, 4]), 1)
    assert pi[0] == 0 and pi[1] == 0 and pi[2] == 1.0


def test_horvitz_thompson_cdf_is_unbiased_under_unequal_probabilities():
    n_h, mal, inv, s = _hosts()
    ben = ~mal
    t = 0.3
    truth = (s[np.repeat(ben, n_h)] <= t).mean()
    pi = AC.pi_pps(n_h, 40)
    rng = np.random.default_rng(1)
    est = []
    for _ in range(400):
        sel = AC.poisson_draw(pi, rng)
        sel = sel[ben[sel]]
        m = np.isin(inv, sel)
        w = 1 / pi[inv[m]]
        est.append((w * (s[m] <= t)).sum() / w.sum())
    assert abs(np.mean(est) - truth) < 0.02  # Hájek: consistent, nearly unbiased here


def test_weighted_quantile_matches_unweighted_and_replication():
    rng = np.random.default_rng(2)
    s = rng.random(1000)
    assert AC.weighted_quantile(s, np.ones(1000), 0.99) == float(
        np.quantile(s, 0.99, method="inverted_cdf")
    )
    w = rng.integers(1, 4, 1000).astype(float)
    assert AC.weighted_quantile(s, w, 0.9) == float(
        np.quantile(np.repeat(s, w.astype(int)), 0.9, method="inverted_cdf")
    )


def test_weighted_quantile_tied_and_invalid_inputs():
    assert AC.weighted_quantile(np.array([1.0, 1.0, 1.0]), np.array([1.0, 2.0, 3.0]), 0.99) == 1.0
    with pytest.raises(ValueError):
        AC.weighted_quantile(np.array([]), np.array([]), 0.5)
    with pytest.raises(ValueError):
        AC.weighted_quantile(np.array([np.nan, 1.0]), np.ones(2), 0.5)
    with pytest.raises(ValueError):
        AC.weighted_quantile(np.array([1.0, 2.0]), np.array([0.0, 0.0]), 0.5)


def test_extreme_weights_collapse_effective_sample_size():
    w = np.r_[np.ones(999), 1e6]
    assert AC.kish_neff(w) < 1.01
    assert AC.kish_neff(np.ones(100)) == pytest.approx(100)


def test_conservative_abstains_without_tail_support_and_bounds_hajek_otherwise():
    rng = np.random.default_rng(3)
    inv = np.repeat(np.arange(3), 20)
    s = rng.random(inv.size)
    assert AC.conservative(s, np.ones(s.size), inv, rng) is None  # 60 windows, 3 hosts
    inv = np.repeat(np.arange(200), 5)
    s = rng.random(inv.size)
    c3 = AC.conservative(s, np.ones(s.size), inv, rng, b=50)
    assert c3 is not None and c3 >= AC.hajek(s, np.ones(s.size)) - 0.02


def test_reviewer_perfect_errors_inconclusive_and_logging():
    mal = np.array([False, False, True, True])
    n_h = np.array([1, 100, 1, 100])
    rv = AC.Reviewer(mal, n_h)
    out = rv.review(np.arange(4), np.random.default_rng(0))
    assert out.tolist() == [AC.BENIGN, AC.BENIGN, AC.MALICIOUS, AC.MALICIOUS]
    assert len(rv.log) == 4 and rv.cost == pytest.approx(4 + 0.01 * 202)
    rv = AC.Reviewer(mal, n_h, e_fb=1.0, e_fm=1.0)
    assert rv.review(np.arange(4), np.random.default_rng(0)).tolist() == [1, 1, 0, 0]
    rv = AC.Reviewer(mal, n_h, p_inc=0.0, p_inc_heavy=1.0, heavy_n=50)  # MNAR: heavy hosts fail
    out = rv.review(np.arange(4), np.random.default_rng(0))
    assert out[1] == AC.INCONCLUSIVE and out[3] == AC.INCONCLUSIVE and out[0] == AC.BENIGN
    with pytest.raises(ValueError):
        rv.review(np.array([0, 0]), np.random.default_rng(0))


def test_designs_cannot_see_labels():
    for fn in (AC.pi_random_host, AC.pi_pps, AC.pi_random_window, AC.pi_stratified, AC.pi_tail,
               AC.select_diverse):  # fmt: skip
        params = set(inspect.signature(fn).parameters)
        assert not params & {"malicious", "labels", "y", "truth", "is_att"}


def test_diversity_is_deterministic_and_covers():
    x = np.r_[np.zeros((50, 2)), np.ones((50, 2)) * 10, [[100, 100]]]
    a, b = AC.select_diverse(x, 3), AC.select_diverse(x, 3)
    assert a.tolist() == b.tolist() and 100 in a.tolist()


def test_seeded_draws_are_deterministic():
    n_h, *_ = _hosts()
    pi = AC.pi_pps(n_h, 20)
    assert (
        AC.poisson_draw(pi, np.random.default_rng(5)).tolist()
        == AC.poisson_draw(pi, np.random.default_rng(5)).tolist()
    )


def test_sample_size_and_design_effect():
    assert AC.n_for_max_guarantee(0.01, 0.05) == 299
    inv = np.repeat(np.arange(10), 100)
    y = np.repeat(np.r_[np.ones(1), np.zeros(9)], 100)  # all exceedances in one host
    d = AC.exceedance_deff(y, inv)
    assert d["icc"] > 0.95 and d["n_eff"] < 12
    y2 = np.random.default_rng(0).random(1000) < 0.1
    assert AC.exceedance_deff(y2, inv)["deff"] < 1.5
