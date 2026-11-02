"""Phase 8j research code: the statistics behind the calibration-reliability design
(docs/phase8j/CALIBRATION_RELIABILITY_METHODOLOGY.md). These check calculations, not any
research outcome."""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
for sub in ("scripts/phase8j", "scripts/phase8i", "scripts/phase8h", "scripts/phase8b"):
    sys.path.insert(0, str(ROOT / sub))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/phase8j" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


T = _load("threshold_stats")


def test_rank_matches_the_deployed_conformal_threshold():
    from netsentinel.behavior.profile import conformal_threshold

    rng = np.random.default_rng(0)
    for n in (99, 150, 199, 313, 1000):
        s = rng.standard_normal(n)
        thr, _ = conformal_threshold(s, T.ALPHA)
        assert thr == np.sort(s)[T.k_of(n) - 1]


def test_iid_risk_is_a_sawtooth_and_199_is_on_a_bad_stretch():
    from scipy.stats import beta

    def q95(n):
        k = T.k_of(n)
        return beta.ppf(0.95, n + 1 - k, k)

    assert q95(198) <= 0.02 < q95(199)  # 199 drops from the maximum to the 2nd largest
    assert q95(312) > 0.02 >= q95(313)
    assert all(q95(n) <= 0.02 for n in range(313, 700))


def test_pac_count_is_the_largest_safe_one():
    from scipy.stats import beta

    assert T.pac_exceedances(100) == 0  # even the maximum is not safe at n = 100
    for n in (199, 313, 1000):
        lo = T.pac_exceedances(n)
        assert lo >= 1
        assert beta.sf(0.02, lo, n + 1 - lo) <= 0.05 < beta.sf(0.02, lo + 1, n - lo)


def test_pac_threshold_abstains_without_enough_independent_evidence():
    z = np.random.default_rng(1).standard_normal(4000)
    assert T.pac_threshold(z, 50.0) is None
    assert T.pac_threshold(z, float("nan")) is None
    t0 = np.sort(z)[T.k_of(len(z)) - 1]
    assert T.pac_threshold(z, 1000.0) == t0  # ample evidence: never looser than T0
    t = T.pac_threshold(z, 200.0)
    assert t is not None and t > t0  # thin evidence: stricter than T0


def test_pac_threshold_is_an_observed_score_so_ties_never_alert():
    z = np.repeat(np.arange(50, dtype=float), 40)  # heavy ties, as in N4
    t = T.pac_threshold(z, 1000.0)
    assert t in z
    assert (z > t).mean() <= 0.01


def test_autocorrelation_deflates_the_effective_sample():
    rng = np.random.default_rng(4)
    hosts = np.repeat(np.arange(20), 500)
    iid = rng.standard_normal(len(hosts))
    ar = np.concatenate([T.ar1(rng, 500, 0.9) for _ in range(20)])
    assert abs(T.lag1(iid, hosts)) < 0.05
    assert 0.85 < T.lag1(ar, hosts) < 0.95
    assert T.neff_m3(iid, hosts) > 0.8 * len(hosts)
    assert T.neff_m3(ar, hosts) < 0.1 * len(hosts)  # design effect (1 + 0.9) / (1 - 0.9) = 19


def test_out_of_fold_exceedance_flags_a_host_unlike_the_others():
    rng = np.random.default_rng(2)
    hosts = np.repeat(np.arange(12), 200)
    z = rng.standard_normal(len(hosts))
    z[hosts == 0] += 10  # host 0 sits far above everyone else
    out = T.out_of_fold_exceedance(z, hosts)
    assert out[hosts == 0].all()
    assert out[hosts != 0].mean() < 0.05
    assert not T.out_of_fold_exceedance(z, np.zeros(len(z), dtype=int)).any()  # one host


def test_cluster_bound_is_a_rate_and_zero_without_exceedances():
    rng = np.random.default_rng(3)
    hosts = np.repeat(np.arange(20), 50)
    assert T.cluster_ucb(np.zeros(1000, dtype=bool), hosts, rng) == 0.0
    e = np.zeros(1000, dtype=bool)
    e[hosts == 0] = True  # all exceedances in one host: a wide bound
    ub = T.cluster_ucb(e, hosts, rng)
    assert 0.05 < ub <= 1.0


def test_host_sizes_sum_to_n_and_skew_concentrates():
    for skew in (0.0, 1.0):
        m = T.sizes(10, 1000, skew)
        assert m.sum() == 1000 and (m >= 1).all()
    assert T.sizes(10, 1000, 1.0).max() > T.sizes(10, 1000, 0.0).max()
    assert math.isclose(T.sizes(4, 400, 0.0).std(), 0.0)
