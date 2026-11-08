"""Phase 8r: trusted-evidence calibration helpers on synthetic data."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


TM = _load("phase8r_tm_test", "scripts/phase8r/trusted_methods.py")


def _manski(s, eps, alpha=0.01):
    lo = float(np.quantile(s, (1 - alpha) * (1 - eps), method="inverted_cdf"))
    hi = float(np.quantile(s, 1 - alpha * (1 - eps), method="inverted_cdf"))
    return lo, hi


def _world(seed=0, n_ben=40, n_att=3, per=200):
    rng = np.random.default_rng(seed)
    hosts = np.repeat(np.arange(n_ben + n_att), per).astype(str)
    s = np.concatenate(
        [rng.beta(2, 8, per) for _ in range(n_ben)] + [rng.beta(9, 1, per) for _ in range(n_att)]
    )
    end = np.tile(np.arange(per) * 60_000 * 3, n_ben + n_att)
    udp = rng.random(s.size)
    ports = rng.integers(1, 10, s.size).astype(float)
    att = np.repeat(np.arange(n_ben + n_att) >= n_ben, per)
    return s, hosts, end, udp, ports, att


def test_manski_bound_contains_benign_quantile_exactly():
    rng = np.random.default_rng(1)
    for _ in range(20):
        ben, att = rng.normal(0, 1, 5000), rng.normal(3, 1, rng.integers(10, 3000))
        mix = np.concatenate([ben, att])
        eps = att.size / mix.size
        qb = float(np.quantile(ben, 0.99, method="inverted_cdf"))
        lo, hi = _manski(mix, eps)
        assert lo <= qb <= hi


def test_policies_are_label_free_and_respect_budget():
    s, hosts, end, udp, ports, att = _world()
    meta = TM.host_meta(hosts, end, udp, ports)
    for p in TM.POLICIES:
        ch = TM.select(p, meta, 10, np.random.default_rng(0))
        assert ch.size <= 10 and np.unique(ch).size == ch.size
        assert ch.max() < meta["uniq"].size


def test_vetting_oracle_and_errors():
    mal = np.array([False] * 8 + [True] * 2)
    chosen = np.arange(10)
    acc, found = TM.vet(chosen, mal, np.random.default_rng(0))
    assert set(acc) == set(range(8)) and set(found) == {8, 9}
    acc, found = TM.vet(chosen, mal, np.random.default_rng(0), e_fb=1.0)
    assert set(acc) == set(range(10)) and found.size == 0


def test_trusted_threshold_recovers_benign_quantile_and_anchoring_screens_attackers():
    s, hosts, end, udp, ports, att = _world()
    meta = TM.host_meta(hosts, end, udp, ports)
    inv = meta["inv"]
    benign_q = TM.t0(s[~att])
    trusted = np.isin(inv, np.arange(10))
    vetted = np.zeros(meta["uniq"].size, bool)
    vetted[:10] = True
    mal = np.zeros_like(vetted)
    a2 = TM.trusted_t0(s, trusted)
    a3 = TM.anchored_t0(s, inv, trusted, vetted, mal)
    assert abs(a2 - benign_q) < 0.08
    assert abs(a3 - benign_q) < 0.03  # attackers screened out, the rest of the benign hosts kept
    assert TM.t0(s) > 0.9  # the unlabelled threshold is attack-dominated
    a4 = TM.cluster_upper_t0(s, inv, trusted, np.random.default_rng(0), b=50)
    assert a4 >= a2 - 1e-12


def test_enough_evidence_gate():
    s, hosts, end, udp, ports, att = _world()
    meta = TM.host_meta(hosts, end, udp, ports)
    few = np.isin(meta["inv"], [0, 1])
    many = np.isin(meta["inv"], np.arange(10))
    assert not TM.enough_evidence(meta["inv"], meta["hour"], few)
    assert TM.enough_evidence(meta["inv"], meta["hour"], many)


@pytest.mark.parametrize(
    "mech", ["random", "persistent", "coordinated", "burst", "gradual", "service_matched"]
)
def test_contamination_hits_requested_fraction(mech):
    s, hosts, end, udp, ports, att = _world()
    meta = TM.host_meta(hosts, end, udp, ports)
    trusted = np.isin(meta["inv"], np.arange(10))
    idx = TM.contaminate(mech, 0.05, int(trusted.sum()), np.flatnonzero(att), meta["inv"], end, udp,
                         ports, trusted, np.random.default_rng(0))  # fmt: skip
    assert idx is not None and att[idx].all() and np.unique(idx).size == idx.size
    share = idx.size / (trusted.sum() + idx.size)
    assert abs(share - 0.05) < 0.005
    if mech == "persistent":
        assert np.unique(hosts[idx]).size == 1
