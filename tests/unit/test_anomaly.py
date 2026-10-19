"""Anomaly score normalisation and conditioning on SYNTHETIC data."""

import numpy as np
import pytest

from netsentinel.models.anomaly import ConditionedAnomalyModel, EmpiricalScorer, RobustZ
from netsentinel.models.service import service_category


def test_empirical_scorer_range_and_monotonicity():
    s = EmpiricalScorer(np.arange(1000, dtype=float))
    out = s(np.array([-5, 0, 499.5, 999, 1e9]))
    assert out[0] == 0 and 99.9 < out[-1] <= 100  # 100 only at float saturation
    assert np.all(np.diff(out) >= 0)
    assert out[2] == pytest.approx(50, abs=0.2)
    beyond = s(np.array([1000.0, 1010.0, 1100.0]))  # drifted values above the reference max
    assert np.all(np.diff(beyond) > 0) and np.all(beyond < 100)
    with pytest.raises(ValueError):
        EmpiricalScorer(np.array([]))


def test_reference_rate_maps_to_benign_tail():
    rng = np.random.default_rng(0)
    ref = rng.normal(size=50_000)
    s = EmpiricalScorer(ref)
    fresh = rng.normal(size=50_000)
    assert np.mean(s(fresh) >= 99) == pytest.approx(0.01, abs=0.003)


def test_robust_z_flags_outliers_and_bounds_constant_features():
    rng = np.random.default_rng(1)
    X = np.c_[rng.normal(100, 5, 2000), np.zeros(2000)]  # noqa: N806
    rz = RobustZ().fit(X)
    s = rz.score(np.array([[100.0, 0.0], [10_000.0, 0.0], [100.0, 5.0]]))
    assert s[1] > 10 * s[0]
    # A constant-in-benign column is informative but bounded by the scale floor.
    assert s[0] < s[2] < 10


def test_robust_z_regression_near_constant_features_do_not_saturate():
    """Audit regression: near-constant features (MAD ~ 0) made v1 saturate, so benign flows
    tied with real outliers. With the floor, injected beyond-range rows must rank above all
    benign rows, and benign scores must not pile up at a single maximum."""
    from netsentinel.models.anomaly import EmpiricalScorer

    rng = np.random.default_rng(7)
    n = 5000
    benign = np.c_[rng.lognormal(5, 1, n), np.where(rng.random(n) < 0.98, 0.0, 1.0),
                   np.full(n, 3.0) + rng.normal(0, 1e-6, n)]  # fmt: skip
    rz = RobustZ().fit(benign[:4000])
    ref = EmpiricalScorer(rz.score(benign[4000:4500]))
    benign_scores = ref(rz.score(benign[4500:]))
    inj = benign[4500:].copy()
    inj[:, 0] = benign[:, 0].max() * 10
    inj_scores = ref(rz.score(inj))
    assert (benign_scores >= 99.9).mean() < 0.02
    assert inj_scores.min() > np.quantile(benign_scores, 0.99)


@pytest.mark.parametrize("kind", ["robust_z", "iforest"])
def test_conditioning_detects_context_specific_anomaly(kind):
    """Big transfers are normal for 'backup' but abnormal for 'mail'. A global model sees both
    as normal; the conditioned model flags a big transfer in the mail context."""
    rng = np.random.default_rng(2)
    n = 4000
    ctx = np.array(["mail"] * n + ["backup"] * n)
    size = np.r_[rng.normal(10, 1, n), rng.normal(1000, 50, n)]
    X = np.c_[size, rng.normal(size=2 * n)]  # noqa: N806
    ref_idx = rng.random(2 * n) < 0.2
    probe = np.array([[1000.0, 0.0]])
    glob = ConditionedAnomalyModel(kind, conditioned=False, min_rows=500).fit(
        X[~ref_idx], ctx[~ref_idx], X[ref_idx], ctx[ref_idx]
    )
    cond = ConditionedAnomalyModel(kind, conditioned=True, min_rows=500).fit(
        X[~ref_idx], ctx[~ref_idx], X[ref_idx], ctx[ref_idx]
    )
    g, _ = glob.score(probe, np.array(["mail"]))
    c, used = cond.score(probe, np.array(["mail"]))
    assert used[0] == "mail"
    assert c[0] > 99 and c[0] > g[0]


def test_unknown_context_falls_back_to_global():
    rng = np.random.default_rng(3)
    X = rng.normal(size=(3000, 3))  # noqa: N806
    ctx = np.array(["web"] * 3000)
    m = ConditionedAnomalyModel("robust_z", conditioned=True, min_rows=100).fit(X, ctx, X, ctx)
    _, used = m.score(X[:2], np.array(["never_seen", "web"]))
    assert list(used) == ["__global__", "web"]


def test_service_category_mapping():
    got = service_category(np.array([443, 53, 21, 22, 445, 1, 50000, 0]), np.array([6] * 8))
    assert list(got) == ["web", "dns", "file_transfer", "remote_access", "windows_directory",
                         "other_wellknown", "ephemeral", "no_port"]  # fmt: skip
