"""Phase 8v: enriched flow-window features on synthetic flows (definitions and causality only)."""

from __future__ import annotations

import importlib.util
import math
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


FF = _load("phase8v_ff_test", "scripts/phase8v/flow_features.py")
LF = _load("phase8v_lf_test", "scripts/phase8u/lowfpr.py")


def _flows(rows: list[dict]) -> pl.DataFrame:
    base = {
        "ipv4_src_addr": "h",
        "protocol": 6,
        "in_bytes": 100,
        "out_bytes": 100,
        "in_pkts": 3,
        "out_pkts": 3,
        "client_tcp_flags": 0x1B,
        "server_tcp_flags": 0x1B,
        "flow_duration_milliseconds": 500,
        "retransmitted_in_pkts": 0,
        "retransmitted_out_pkts": 0,
        "src_to_dst_iat_avg": 10.0,
        **{b: 0.0 for b in FF.BINS},
    }
    return pl.DataFrame([{**base, **r} for r in rows], infer_schema_length=None)


def _one(df: pl.DataFrame, key: str = "h", win: int = 0) -> dict:
    return (
        FF.window_features(df)
        .filter((pl.col("key") == key) & (pl.col("win") == win))
        .row(0, named=True)
    )


def test_flow_family_definitions():
    df = _flows(
        [
            {
                "flow_end_milliseconds": 1000,
                "in_pkts": 1,
                "out_pkts": 0,
                "in_bytes": 0,
                FF.BINS[0]: 1.0,
            },
            {
                "flow_end_milliseconds": 2000,
                "in_pkts": 5,
                "out_pkts": 5,
                "in_bytes": 0,
                FF.BINS[0]: 2.0,
                FF.BINS[4]: 8.0,
            },
        ]
    )
    r = _one(df)
    assert r["n_flows_v"] == 2 and r["tiny_flow_frac"] == 0.5
    assert r["mean_log_pkts"] == pytest.approx((math.log(2) + math.log(11)) / 2)
    assert r["sd_log_up"] == 0.0 and r["small_pkt_share"] == pytest.approx(3 / 11)
    assert r["p90_log_dur"] == pytest.approx(math.log(501))


def test_missing_stays_missing():
    r = _one(_flows([{"flow_end_milliseconds": 1000, "in_pkts": 1}]))
    assert r["small_pkt_share"] is None  # no size-binned packet
    assert r["mean_log_fwd_iat"] is None  # no flow with two forward packets
    assert r["gap_cv"] is None  # fewer than three flows


def test_time_family_and_simultaneous_ends():
    ends = [1000, 1000, 1000, 1500, 9000]
    r = _one(_flows([{"flow_end_milliseconds": e} for e in ends]))
    assert r["active_sec_frac"] == pytest.approx(2 / 30) and r["peak_sec_share"] == pytest.approx(
        4 / 5
    )
    gaps = np.diff(np.sort(ends)).astype(float)
    assert r["gap_cv"] == pytest.approx(gaps.std() / gaps.mean())
    same = _one(_flows([{"flow_end_milliseconds": 1000}] * 3))
    assert same["gap_cv"] == 0.0  # identical end times: no variation, not NaN
    long = _one(
        _flows(
            [
                {"flow_end_milliseconds": 1000, "flow_duration_milliseconds": 30_001},
                {"flow_end_milliseconds": 2000, "flow_duration_milliseconds": 30_000},
            ]
        )
    )
    assert long["long_flow_frac"] == 0.5


def test_bidirectional_family_and_non_tcp():
    df = _flows(
        [
            {
                "flow_end_milliseconds": 1000,
                "client_tcp_flags": 0x02,
                "server_tcp_flags": 0x14,
                "out_bytes": 0,
            },  # SYN -> RST
            {
                "flow_end_milliseconds": 2000,
                "client_tcp_flags": 0x13,
                "server_tcp_flags": 0x12,
                "retransmitted_in_pkts": 1,
            },
            {
                "flow_end_milliseconds": 3000,
                "protocol": 17,
                "client_tcp_flags": 0x02,
                "server_tcp_flags": 0x04,
            },  # UDP: ignored
            {"flow_end_milliseconds": 4000, "client_tcp_flags": 0x12},  # SYN and ACK: not SYN-only
        ]
    )
    r = _one(df)
    assert r["syn_only_frac"] == 0.25 and r["srv_rst_frac"] == 0.25 and r["cli_fin_frac"] == 0.25
    assert r["retrans_frac"] == 0.25
    assert r["mean_log_ratio"] == pytest.approx((math.log(1) - math.log(101)) / 4)


def test_windows_are_independent_and_keyed_by_end_time():
    a = _flows(
        [
            {"flow_end_milliseconds": 29_999},
            {"flow_end_milliseconds": 30_000, "in_pkts": 1, "out_pkts": 0},
        ]
    )
    assert _one(a, win=0)["n_flows_v"] == 1 and _one(a, win=1)["tiny_flow_frac"] == 1.0
    b = _flows(
        [
            {"flow_end_milliseconds": 29_999},
            {"flow_end_milliseconds": 30_000},
            {"flow_end_milliseconds": 500, "ipv4_src_addr": "other"},
        ]
    )
    r0 = {k: v for k, v in _one(a, win=0).items()}
    assert _one(b, win=0) == r0  # other hosts and later windows do not change a window


def test_context_uses_only_earlier_windows():
    w = pl.DataFrame(
        {"key": ["h"] * 4 + ["g"], "win": [10, 11, 13, 14, 14], "n_flows_v": [1, 3, 7, 2, 5]}
    )
    c = FF.context_features(w).sort("key", "win")
    h14 = c.filter((pl.col("key") == "h") & (pl.col("win") == 14)).row(0, named=True)
    lf = lambda n: math.log(n + 1)  # noqa: E731
    assert h14["prev4_mean_log_flows"] == pytest.approx((lf(7) + 0 + lf(3) + lf(1)) / 4)
    assert h14["d_log_flows"] == pytest.approx(lf(2) - lf(7)) and h14["active_prev4"] == 3
    g14 = c.filter(pl.col("key") == "g").row(0, named=True)
    assert g14["prev4_mean_log_flows"] == 0.0 and g14["active_prev4"] == 0  # new host: no history
    # changing a LATER window never changes an earlier window's context
    w2 = w.with_columns(
        pl.when(pl.col("win") == 14).then(99).otherwise(pl.col("n_flows_v")).alias("n_flows_v")
    )
    c2 = FF.context_features(w2).sort("key", "win")
    early = (pl.col("key") == "h") & (pl.col("win") <= 13)
    assert c.filter(early).equals(c2.filter(early))


def test_required_columns_and_null_end_time():
    with pytest.raises(ValueError):
        FF.window_features(pl.DataFrame({"ipv4_src_addr": ["h"]}))
    bad = _flows([{"flow_end_milliseconds": None}])
    with pytest.raises(ValueError):
        FF.window_features(bad)


def test_family_lists_are_consistent_and_use_no_identity_fields():
    assert (
        len(FF.ALL) == 18 and len(set(FF.ALL)) == 18 and set(FF.CONTEXT) <= set(FF.FAMILIES["TIME"])
    )
    banned = ("addr", "port", "ttl", "tcp_win", "label", "attack")
    assert not [c for c in FF.RAW_COLUMNS if any(b in c for b in banned) and c != "ipv4_src_addr"]


def test_exact_partial_auc_regression_case():
    """Phase 8u amendment U-1: benign [1, 0], attack [0.5] must score 0, never 0.5."""
    assert LF.partial_auc_exact(np.array([0.5]), np.array([1.0, 0.0]), 0.5) == 0.0
    assert LF.partial_auc_exact(np.array([0.5]), np.array([1.0, 0.0]), 0.01) == 0.0


SEL = _load("phase8v_sel_test", "scripts/phase8v/selection.py")


def test_invariant_selection_drops_conflicting_and_keeps_neutral_columns():
    rng = np.random.default_rng(0)
    n = 4000
    net = np.repeat(np.array(["a", "b"]), n // 2)
    y = rng.integers(0, 2, n)
    same = y + rng.normal(0, 1, n)  # attack higher in both networks
    flip = np.where(net == "a", y, -y) + rng.normal(0, 1, n)  # opposite directions
    noise = rng.normal(0, 1, n)  # no relation
    one = np.where(net == "a", y, 0) + rng.normal(0, 1, n)  # informative in one network only
    missing = same.copy()
    missing[rng.random(n) < 0.5] = np.nan
    keep, table = SEL.invariant_columns(np.column_stack([same, flip, noise, one, missing]), y, net)
    assert keep.tolist() == [True, False, True, True, True]
    assert table[1]["a"] > 0.6 and table[1]["b"] < 0.4


def test_invariant_selection_ignores_networks_without_both_classes():
    x = np.array([[0.0], [1.0], [1.0], [0.0], [5.0]])
    y = np.array([0, 1, 0, 1, 0])
    net = np.array(["a", "a", "b", "b", "c"])  # network c has no attack
    keep, table = SEL.invariant_columns(x, y, net)
    assert set(table[0]) == {"a", "b"} and keep.tolist() == [False]


def test_permutation_control_keeps_marginals_and_is_deterministic():
    x = np.arange(40, dtype=float).reshape(20, 2)
    a, b = SEL.permute_columns(x, "t"), SEL.permute_columns(x, "t")
    assert np.array_equal(a, b) and not np.array_equal(a, x)
    assert np.array_equal(np.sort(a, axis=0), np.sort(x, axis=0))
    assert not np.array_equal(SEL.permute_columns(x, "other"), a)


def _summ(pauc: dict, recall: dict, cal_recall=0.6, fpr=0.05, missed=8) -> dict:
    nets = {n: {"pauc_1pct": pauc[n], "recall_1pct": recall[n], "calT_fpr": fpr} for n in SEL.NETS}
    return {"networks": nets, "macro_calT_recall": cal_recall, "missed_calT": missed}


def test_registered_gates():
    base = _summ(dict.fromkeys(SEL.NETS, 0.1), dict.fromkeys(SEL.NETS, 0.1))
    hard = {"nfcic": 0.1, "nfunsw": 0.13, "nfton": 0.13, "nfbot": 0.1}
    good = _summ(hard, dict.fromkeys(SEL.NETS, 0.1))
    easy_only = _summ(
        {"nfcic": 0.5, "nfunsw": 0.1, "nfton": 0.1, "nfbot": 0.5}, dict.fromkeys(SEL.NETS, 0.1)
    )
    regress = _summ(hard, {"nfcic": -0.05, "nfunsw": 0.1, "nfton": 0.1, "nfbot": 0.1})
    quiet = _summ(
        hard, dict.fromkeys(SEL.NETS, 0.1), cal_recall=0.5
    )  # alerts less: recall guardrail
    s = {f"M2member|{k}": base for k in SEL.SEEDS}
    s.update({"FLOW|1060": good, "TIME|1060": easy_only, "BIDIR|1060": regress, "INV|1060": quiet})
    d = SEL.decide(s)
    assert d["screening"]["FLOW"]["passes"]
    assert not d["screening"]["TIME"]["passes"]  # gain on the easy networks alone does not pass
    assert not d["screening"]["BIDIR"]["passes"]  # catastrophic regression on one network
    assert not d["screening"]["INV"]["passes"]  # lower as-calibrated recall
    assert d["replicate_next"] == "FLOW" and d["replication"] == {}
    s.update({"FLOW|1061": good, "FLOW|1062": base})  # one seed without a gain
    r = SEL.decide(s)["replication"]["FLOW"]
    assert not r["replicated"] and r["mean_d_hard_pauc"] == pytest.approx(0.02)
    s["FLOW|1062"] = good
    r = SEL.decide(s)["replication"]["FLOW"]
    assert r["replicated"] and not r["g5_cross_network"]  # only two networks improve
    s["PERM_FLOW|1060"] = good
    assert not SEL.decide(s)["control"]["FLOW"][
        "shortcut_ruled_out"
    ]  # permuted columns keep the gain
