"""Phase 8p Experiment E logic on synthetic inputs: training rows identical to Phase 8n, the SX
join, the D3 fusion under one budget, the C3 host-balanced threshold, the C2 delayed-label rule,
and the registered decisions."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import polars as pl
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


EE = _load("phase8p_experiment_t", "scripts/phase8p/experiment_e.py")
AE = _load("phase8p_analyze_t", "scripts/phase8p/analyze_e.py")
B2 = _load("phase8p_c2_t", "scripts/phase8p/build_c2.py")


def domain(n_cal=300, n_ev=400, seed=0) -> dict:
    rng = np.random.default_rng(seed)
    feats = list(EE.FEATURES["S0"])
    mk = lambda n, k0: pl.DataFrame({"key": [f"h{i % 17}" for i in range(n)],  # noqa: E731
                                     "win": np.arange(k0, k0 + n),
                                     **{f: rng.random(n) for f in feats}})  # fmt: skip
    ev = mk(n_ev, n_cal).with_columns(
        pl.Series("y", rng.random(n_ev) < 0.2), pl.Series("noisy", rng.random(n_ev) < 0.05)
    )
    return {"cal": mk(n_cal, 0), "ev": ev, "network": "x"}


def test_train_rows_equal_phase8n_with_12_features(monkeypatch):
    d = domain()
    monkeypatch.setattr(EE.C, "CAP", 200)
    a = EE.FR.train_rows(d, 7)
    b = EE.train_rows(d, 7, EE.FEATURES["S0"])
    for u, v in zip(a, b, strict=True):
        np.testing.assert_array_equal(u, v)


def test_sx_join_requires_every_row_and_keeps_order():
    frame = pl.DataFrame({"key": ["b", "a"], "win": [2, 1]})
    sx = pl.DataFrame({"key": ["a", "b"], "win": [1, 2], **{c: [0.1, 0.2] for c in EE.SX_COLS}})
    j = EE.sx_join(frame, sx)
    assert j["key"].to_list() == ["b", "a"] and j[EE.SX_COLS[0]].to_list() == [0.2, 0.1]
    with pytest.raises(RuntimeError):
        EE.sx_join(pl.DataFrame({"key": ["c"], "win": [9]}), sx)


def test_fusion_shares_one_budget():
    rng = np.random.default_rng(1)
    s_hold, v_hold = rng.random(5000), rng.random(5000)
    f_hold, _ = AE.fuse(s_hold, v_hold, s_hold[:10], v_hold[:10])
    t0 = AE.AD.t0_of(f_hold)
    assert (f_hold > t0).mean() <= 0.01 + 1e-9  # the fused hold-out alert rate is held at alpha
    # independent branches: each branch alone alerts at about alpha / 2 of the hold-out
    assert 0.003 < (AE.ecdf(s_hold, s_hold) > t0).mean() < 0.007
    # a window extreme on the victim branch only is alerted
    _, f_ev = AE.fuse(s_hold, v_hold, np.array([0.5]), np.array([10.0]))
    assert f_ev[0] > t0


def test_host_balanced_threshold_limits_one_persistent_host():
    benign = np.linspace(0, 1, 1000)
    hosts_b = np.array([f"b{i % 100}" for i in range(1000)])
    persistent = np.full(300, 5.0)  # one host with many high-scoring windows
    s = np.r_[benign, persistent]
    h = np.r_[hosts_b, np.array(["evil"] * 300)]
    plain = AE.AD.t0_of(s)
    balanced = AE.host_balanced_t0(s, h)
    assert plain == 5.0  # the persistent host owns the unweighted tail
    assert balanced < 5.0  # its total weight is one host's, not 300 windows'
    even = AE.host_balanced_t0(benign, hosts_b)
    assert abs(even - np.quantile(benign, 0.99)) < 0.01  # equal hosts: the ordinary quantile


def test_c2_delayed_labels(tmp_path):
    w = 30_000
    mid = 1000 * w
    pl.DataFrame({"key": ["early", "early", "late", "benign"], "win": [100, 200, 990, 300],
                  "y": [True, True, True, False]}).write_parquet(
        tmp_path / "cal_truth.parquet")  # fmt: skip
    known, every = B2.known_attackers(tmp_path, mid, delay_min=60)
    assert every == {"early", "late"} and known == {"early"}  # 'late' attacked within the last hour


def summary(recall_doc=0.7, fa=1000.0, r20=37, u20=0, coll=0):
    nets = {n: {"recall_doc": recall_doc, "fa": fa} for n in AE.NETWORKS}
    return {"networks": nets, "macro_recall_doc": recall_doc, "collapses": coll,
            "doc": {"R": {20: r20}, "U": {20: u20}}}  # fmt: skip


def test_candidate_rule():
    s0 = summary()
    assert AE.decide(summary(r20=40), s0)["pass"]  # (a) three more documented attackers
    assert AE.decide(summary(recall_doc=0.73), s0)["pass"]  # (b) +0.03 macro
    assert not AE.decide(summary(recall_doc=0.72), s0)["pass"]
    assert not AE.decide(summary(r20=40, fa=1200), s0)["pass"]  # false-alert guardrail
    assert not AE.decide(summary(r20=40, u20=3), s0)["pass"]  # instability guardrail
    assert not AE.decide(summary(r20=40, coll=1), s0)["pass"]


def test_verdicts_and_service_shortcut_control():
    dec = {"D2": {"pass": False, "R20_doc": 37}, "S1": {"pass": True, "R20_doc": 41},
           "D2S": {"pass": True, "R20_doc": 41}, "D3": {"pass": False, "R20_doc": 30}}  # fmt: skip
    v = AE.verdicts(dec, sonly_macro=0.5, s1_macro=0.8)  # service alone carries > half
    assert (
        v["H2"] == "NOT SUPPORTED"
        and v["selected"] == "D2S"
        and v["model_candidate"] == "DEVELOPMENT GO"
    )
    v = AE.verdicts(dec, sonly_macro=0.2, s1_macro=0.8)
    assert v["H2"] == "SUPPORTED" and v["selected"] == "S1"  # tie on R20 -> the simpler
    none = {k: {"pass": False, "R20_doc": 0} for k in dec}
    assert AE.verdicts(none, 0.1, 0.8)["model_candidate"] == "DEVELOPMENT NO-GO"
