"""Phase 8w: reference estimation, relative representations and registered gates (synthetic)."""

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


RL = _load("phase8w_rl_test", "scripts/phase8w/relative.py")
NAMES = ["log_flows", "rst_frac"]


def test_reference_matches_the_product_scaler_used_by_phase8h():
    from netsentinel.behavior.temporal import RobustScaler
    from netsentinel.behavior.windows import WINDOW_FEATURES

    rng = np.random.default_rng(0)
    names = list(WINDOW_FEATURES)
    x = rng.normal(2, 1, (500, len(names)))
    x[:, names.index("rst_frac")] = 0.0  # a constant feature: MAD 0, floor applies
    ref = RL.fit_reference(x, names, "label_benign_training")
    sc = RobustScaler().fit(x, names)
    assert np.allclose(ref.location, sc.med) and np.allclose(ref.scale, sc.scale)
    xn = rng.normal(2, 1, (50, len(names)))
    assert np.allclose(RL.zscore(xn, ref), np.clip(sc.transform(xn), -10, 10), atol=1e-6)
    assert ref.floored[names.index("rst_frac")] and ref.scale[names.index("rst_frac")] == 0.15


def test_floors_constant_feature_and_outliers():
    x = np.column_stack([np.r_[np.full(299, 3.0), 1e9], np.zeros(300)])
    ref = RL.fit_reference(x, NAMES, "oracle_benign")
    assert ref.location.tolist() == [3.0, 0.0]
    assert ref.scale.tolist() == [0.25, 0.15] and ref.floored.all()  # MAD 0 → documented floors
    z = RL.zscore(np.array([[1e9, 1.0], [3.0, 0.0], [-1e9, 0.0]]), ref)
    assert z[0].tolist() == [10.0, pytest.approx(1 / 0.15)] and z[1].tolist() == [0.0, 0.0]
    assert z[2, 0] == -10.0  # clipped, finite


def test_failure_states():
    few = RL.fit_reference(np.zeros((10, 2)), NAMES, "unlabelled_history")
    assert few.status == "insufficient_history" and few.location is None
    with pytest.raises(ValueError):
        RL.zscore(np.zeros((1, 2)), few)  # never silently substituted
    with pytest.raises(ValueError):
        RL.fit_reference(np.array([[np.inf, 0.0]] * 300), NAMES, "oracle_benign")
    with pytest.raises(ValueError):
        RL.fit_reference(np.zeros((300, 3)), NAMES, "oracle_benign")
    with pytest.raises(ValueError):
        RL.fit_reference(np.zeros((300, 2)), NAMES, "assumed_benign")


def test_missing_values_and_population_label():
    x = np.random.default_rng(1).normal(0, 1, (400, 2))
    x[:100, 0] = np.nan
    ref = RL.fit_reference(x, NAMES, "unlabelled_history")
    assert ref.missing_share[0] == 0.25 and np.isfinite(ref.location).all()
    assert (
        RL.zscore(np.array([[np.nan, 0.0]]), ref)[0, 0] == 0.0
    )  # a missing value has no deviation
    j = ref.to_json()
    assert j["benign_reference"] is False and "NOT a benign reference" in j["note"]


def test_abs_is_two_sided_and_signed_keeps_direction():
    z = np.array([[-3.0, 0.5], [2.0, -0.5]])
    assert RL.represent(z, "signed") is z
    assert RL.represent(z, "abs").tolist() == [[3.0, 0.5], [2.0, 0.5]]
    assert RL.represent(z, "posneg").tolist() == [[0.0, 0.5, 3.0, 0.0], [2.0, 0.0, 0.0, 0.5]]


def test_positive_negative_split_is_the_same_tree_hypothesis_class_as_signed():
    """Every axis-aligned split on z is a split on z+ or on z−, and vice versa, so a tree model
    cannot gain or lose anything from the split encoding."""
    rng = np.random.default_rng(2)
    z = rng.normal(0, 2, 2000)
    zp, zn = np.maximum(z, 0), np.maximum(-z, 0)
    for t in rng.normal(0, 2, 200):
        left = z <= t
        same = (zp <= t) if t >= 0 else (zn >= -t)
        assert np.array_equal(left, same)
    for t in np.abs(rng.normal(0, 2, 200)):
        assert np.array_equal(zp <= t, z <= t) and np.array_equal(zn <= t, z >= -t)


def test_unlabelled_mixture_does_not_identify_the_benign_reference():
    """Two different worlds with the SAME observed distribution and different benign medians."""
    rng = np.random.default_rng(3)
    low, high = rng.normal(0, 1, 5000), rng.normal(6, 1, 5000)
    world_a_benign = np.r_[low, high]  # all benign: a bimodal benign population
    world_b_benign, world_b_attack = low, high  # half the traffic is an attack
    observed_a, observed_b = np.sort(world_a_benign), np.sort(np.r_[world_b_benign, world_b_attack])
    assert np.array_equal(observed_a, observed_b)  # indistinguishable without labels
    assert abs(np.median(world_a_benign) - np.median(world_b_benign)) > 2.5


def test_majority_contamination_moves_the_reference_onto_the_attack():
    rng = np.random.default_rng(4)
    benign = np.column_stack([rng.normal(2, 0.5, 1000), np.zeros(1000)])
    attack = np.column_stack([rng.normal(7, 0.5, 5000), np.zeros(5000)])
    clean = RL.fit_reference(benign, NAMES, "oracle_benign")
    for share, moved in ((0.1, False), (0.3, False), (0.76, True)):
        rows = RL.contaminated_rows(benign, attack, share, rng)
        assert abs((rows[:, 0] > 4.5).mean() - share) < 0.01
        ref = RL.fit_reference(rows, NAMES, "unlabelled_history")
        assert (abs(ref.location[0] - 7) < 1) == moved
    dirty = RL.fit_reference(
        RL.contaminated_rows(benign, attack, 0.76, rng), NAMES, "unlabelled_history"
    )
    za = np.abs(RL.zscore(attack, dirty)[:, 0]).mean()
    zb = np.abs(RL.zscore(benign, dirty)[:, 0]).mean()
    assert za < 1 < zb  # attacks look normal, benign windows look deviant
    assert np.abs(RL.zscore(attack, clean)[:, 0]).mean() > 5
    with pytest.raises(ValueError):
        RL.contaminated_rows(benign, attack, 1.0, rng)


def test_host_reference_fallback_and_new_hosts():
    rng = np.random.default_rng(5)
    hosts = np.r_[np.repeat("busy", 100), np.repeat("quiet", 100), np.repeat("rare", 5)]
    level = np.r_[rng.normal(8, 0.3, 100), rng.normal(1, 0.3, 100), rng.normal(4, 0.3, 5)]
    x = np.column_stack([level, np.zeros(205)])
    ref = RL.host_reference(x, hosts, NAMES, "label_benign_training")
    assert ref.hosts.tolist() == ["busy", "quiet"] and ref.coverage(hosts) == pytest.approx(
        200 / 205
    )
    q = np.array([[8.0, 0.0], [8.0, 0.0], [8.0, 0.0], [8.0, 0.0]])
    z = RL.zscore_host(q, np.array(["busy", "quiet", "rare", "never_seen"]), ref)
    assert (
        abs(z[0, 0]) < 1 and z[1, 0] == 10.0
    )  # normal for the busy host, extreme for the quiet one
    net = RL.zscore(q[:1], ref.network)[0, 0]
    assert z[2, 0] == net and z[3, 0] == net  # little or no history: network reference


def test_reference_is_frozen_and_ignores_later_data():
    rng = np.random.default_rng(6)
    past = rng.normal(0, 1, (500, 2))
    ref = RL.fit_reference(past, NAMES, "unlabelled_history", interval_ms=(0, 1000))
    before = (ref.location.copy(), ref.scale.copy())
    RL.zscore(rng.normal(50, 1, (500, 2)), ref)  # scoring later windows must not update it
    assert np.array_equal(ref.location, before[0]) and np.array_equal(ref.scale, before[1])
    assert ref.interval_ms == (0, 1000)


# ----------------------------------------------------------------------------- registered gates
G = _load("phase8w_gates_test", "scripts/phase8w/gates.py")
BASE_PAUC = {"nfcic": 0.40, "nfunsw": 0.01, "nfton": 0.01, "nfbot": 0.55}


def _agg(pauc=None, recall=None, fpr=None, cal_recall=0.5, missed=8):
    pauc = {**BASE_PAUC, **(pauc or {})}
    nets = {n: {"pauc_1pct": pauc[n], "recall_1pct": (recall or {}).get(n, pauc[n]),
                "calT_fpr": (fpr or {}).get(n, 0.10)} for n in G.NETS}  # fmt: skip
    return {"networks": nets, "macro_pauc_1pct": float(np.mean(list(pauc.values()))),
            "macro_calT_recall": cal_recall, "missed_calT": missed}  # fmt: skip


def _summary(cand_z1, cand_z3, seeds=G.ALL_SEEDS, arm="A"):
    base = {str(s): _agg() for s in G.ALL_SEEDS}
    weak = {str(s): _agg() for s in G.ALL_SEEDS}
    other = "S" if arm == "A" else "A"
    return {"Z1": {"R0": base, arm: {str(s): cand_z1 for s in seeds}, other: weak},
            "Z3": {"R0": base, arm: {str(s): cand_z3 for s in seeds}, other: weak}}  # fmt: skip


GOOD = {"nfunsw": 0.06, "nfton": 0.08, "nfcic": 0.42, "nfbot": 0.56}  # hard +0.06, macro +0.0375


def test_ranking_needs_effect_size_every_seed_and_all_seeds():
    base = {str(s): _agg() for s in G.ALL_SEEDS}
    good = {str(s): _agg(GOOD) for s in G.ALL_SEEDS}
    r = G.ranking(good, base, G.ALL_SEEDS)
    assert r["pass"] and r["mean_delta_hard"] == pytest.approx(0.06)
    assert r["mean_delta_macro"] == pytest.approx(0.0375)
    small = {str(s): _agg({"nfunsw": 0.02, "nfton": 0.02}) for s in G.ALL_SEEDS}
    assert not G.ranking(small, base, G.ALL_SEEDS)["pass"]  # +0.01 is below the minimum effect
    mixed = dict(good)
    mixed["1063"] = _agg({"nfcic": 0.10, "nfunsw": 0.06, "nfton": 0.08})  # one seed loses macro
    assert not G.ranking(mixed, base, G.ALL_SEEDS)["pass"]
    part = {s: good[s] for s in ("1060", "1061")}
    r = G.ranking(part, base, G.ALL_SEEDS)
    assert not r["complete"] and not r["pass"]  # two seeds can never support a verdict
    assert G.ranking(part, base, G.SCREEN_SEEDS)["pass"]
    # a gain on NF-CIC and NF-BoT alone cannot pass: the hard networks are not concealed
    easy = {str(s): _agg({"nfcic": 0.60, "nfbot": 0.75}) for s in G.ALL_SEEDS}
    assert not G.ranking(easy, base, G.ALL_SEEDS)["pass"]


def test_guardrails():
    base = {str(s): _agg() for s in G.SCREEN_SEEDS}

    def g(**kw):
        return G.guardrails(
            {str(s): _agg(GOOD, **kw) for s in G.SCREEN_SEEDS}, base, G.SCREEN_SEEDS
        )

    assert g()["pass"]
    assert not g(recall={"nfcic": 0.25})["pass"]  # a network loses > 0.10 recall at 1 % FPR
    assert not g(fpr={"nfton": 0.12})["pass"]  # + 2 points of as-calibrated FPR
    assert g(fpr={"nfbot": 0.15})["pass"] and not g(fpr={"nfbot": 0.17})["pass"]  # wider on NF-BoT
    assert not g(cal_recall=0.46)["pass"]  # passing by alerting less
    assert g(missed=10)["pass"] and not g(missed=11)["pass"]
    worse = {str(s): _agg({**GOOD, "nfunsw": 0.005, "nfton": 0.2}) for s in G.SCREEN_SEEDS}
    assert not G.guardrails(worse, base, G.SCREEN_SEEDS)["pass"]  # NF-UNSW hidden behind NF-ToN


def test_decide_no_candidate_passes():
    d = G.decide(_summary(_agg(), _agg()))
    assert d["selected"]["arm"] is None and d["development"] == "DEVELOPMENT NO-GO"
    assert (d["G1"], d["G3"], d["G4"]) == ("NOT SUPPORTED",) * 3 and d["G2"].startswith(
        "NOT EVALUABLE"
    )


def test_decide_supported_needs_five_seeds_under_the_deployable_reference():
    d = G.decide(_summary(_agg(GOOD), _agg(GOOD)))
    assert d["selected"] == {"arm": "A", "scenario": "Z1", "scope": "G1, G3, G4"}
    assert (d["G1"], d["G3"], d["G4"]) == ("SUPPORTED",) * 3 and d["development"].startswith(
        "DEVELOPMENT GO"
    )
    two = G.decide(_summary(_agg(GOOD), _agg(GOOD), seeds=G.SCREEN_SEEDS))
    assert two["selected"]["arm"] == "A" and two["G1"].startswith("NOT EVALUABLE")
    assert two["development"] == "NOT EVALUABLE"  # screening alone supports nothing


def test_decide_oracle_only_gain_is_not_a_development_go():
    d = G.decide(_summary(_agg(), _agg(GOOD)))
    assert d["selected"] == {"arm": "A", "scenario": "Z3", "scope": "G1 only"}
    assert d["G1"] == "SUPPORTED" and d["G3"] == "NOT SUPPORTED" and d["G4"] == "NOT SUPPORTED"
    assert d["development"] == "DEVELOPMENT NO-GO"


def test_decide_retention_and_guardrail_failures():
    big = {"nfunsw": 0.21, "nfton": 0.21, "nfcic": 0.42, "nfbot": 0.56}  # oracle macro + 0.1075
    d = G.decide(_summary(_agg(GOOD), _agg(big)))  # deployable keeps 35 % of the oracle gain
    assert d["G1"] == "SUPPORTED" and d["G3"] == "NOT SUPPORTED" and d["G4"] == "SUPPORTED"
    assert d["retained_share_of_oracle_macro_gain"] == pytest.approx(0.0375 / 0.1075)
    assert d["development"] == "DEVELOPMENT NO-GO"
    d = G.decide(_summary(_agg(GOOD, missed=12), _agg(GOOD)))  # fails screening guardrails on Z1
    assert d["selected"]["scenario"] == "Z3" and d["G4"] == "NOT SUPPORTED"


def test_the_signed_arm_can_be_selected_and_ties_go_to_the_larger_hard_gain():
    s = _summary(_agg(GOOD), _agg(GOOD), arm="S")
    assert G.decide(s)["selected"]["arm"] == "S"
    better = {**GOOD, "nfton": 0.20}
    s["Z1"]["A"] = {str(k): _agg(better) for k in G.ALL_SEEDS}
    assert G.decide(s)["selected"]["arm"] == "A"


def test_exact_partial_auc_regression_case():
    lf = _load("phase8u_lf_test8w", "scripts/phase8u/lowfpr.py")
    assert lf.partial_auc_exact(np.array([0.5]), np.array([1.0, 0.0])) == 0.0
    assert lf.partial_auc_exact(np.array([2.0]), np.array([1.0, 0.0])) == 1.0


def test_source_pooled_population_is_registered():
    assert "source_pooled_training" in RL.POPULATIONS
    ref = RL.fit_reference(np.zeros((300, 2)), NAMES, "source_pooled_training")
    assert ref.to_json()["benign_reference"] is True
