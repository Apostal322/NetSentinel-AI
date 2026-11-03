"""Phase 8o: feature-contract edge cases (docs/phase8o/FEATURE_SEMANTICS.md section 4), the F1
deployment scenario, the arm construction and the registered decision rules on synthetic
inputs."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.novelty import NoveltyMemory, contacts_from_flows
from netsentinel.behavior.windows import aggregate, prepare_flows

ROOT = Path(__file__).resolve().parents[2]
W = 30_000


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AD = _load("phase8o_analyze_t", "scripts/phase8o/analyze_d.py")
ED = _load("phase8o_experiment_t", "scripts/phase8o/experiment_d.py")


def raw(rows: list[tuple[int, str, str]], out_pkts=1) -> pl.DataFrame:
    """(end_ms, src, dst) -> canonical flow records."""
    n = len(rows)
    return pl.DataFrame({
        "flow_end_milliseconds": [r[0] for r in rows], "ipv4_src_addr": [r[1] for r in rows],
        "ipv4_dst_addr": [r[2] for r in rows], "dst_port": [443] * n, "protocol": [6] * n,
        "in_bytes": [100] * n, "out_bytes": [200] * n, "in_pkts": [2] * n,
        "out_pkts": [out_pkts] * n, "flow_duration_milliseconds": [10] * n,
    })  # fmt: skip


def stream(seed: int = 0, n: int = 600, span_ms: int = 40 * W) -> list[tuple[int, str, str]]:
    rng = np.random.default_rng(seed)
    t = np.sort(rng.integers(0, span_ms, n))
    return [(int(x), f"h{rng.integers(4)}", f"d{int(rng.zipf(1.5)) % 30}") for x in t]


def feats(df: pl.DataFrame, **kw) -> pl.DataFrame:
    return aggregate(prepare_flows(df), "device", 30, **kw).sort("win", "key")


# ---------------------------------------------------------------- feature contract


def test_frozen_vs_expanding_repeated_destination():
    rows = [
        (1_000, "a", "x"),
        (W + 1_000, "a", "x"),
        (2 * W + 1_000, "a", "y"),
        (3 * W + 1, "a", "y"),
    ]
    exp = feats(raw(rows))
    assert exp["new_dst_frac"].to_list() == [1.0, 0.0, 1.0, 0.0]  # new only in its first window
    frozen = feats(raw(rows), known_dst={"x"})
    assert frozen["new_dst_frac"].to_list() == [0.0, 0.0, 1.0, 1.0]  # y stays new for ever


def test_aggregate_input_order_invariant():
    df = raw(stream())
    shuffled = df.sample(fraction=1.0, shuffle=True, seed=3)
    assert feats(df).equals(feats(shuffled))


def test_window_aligned_chunks_equal_batch():
    df = raw(stream(1))
    cut = 20 * W  # a window boundary
    a, b = (
        df.filter(pl.col("flow_end_milliseconds") < cut),
        df.filter(pl.col("flow_end_milliseconds") >= cut),
    )
    prior = set(prepare_flows(a)["dst"].unique().to_list())
    both = pl.concat([feats(a), feats(b, prior_dst=prior)]).sort("win", "key")
    assert both.equals(feats(df))


def test_split_window_gives_partial_rows():
    rows = [(1_000, "a", "x"), (2_000, "a", "y")]
    whole = feats(raw(rows))
    parts = pl.concat([feats(raw(rows[:1])), feats(raw(rows[1:]))])
    assert whole.height == 1 and parts.height == 2  # G2.2: the caller must close whole windows


def test_duplicate_flow_counts():
    rows = [(1_000, "a", "x"), (2_000, "a", "y")]
    one, dup = feats(raw(rows)), feats(raw(rows + rows[:1]))
    assert dup["n_flows"][0] == 3 and one["n_flows"][0] == 2
    assert dup["new_dst_frac"][0] == one["new_dst_frac"][0]  # distinct-destination share unchanged


def test_missing_reply_counts_as_no_reply():
    rows = [(1_000, "a", "x"), (2_000, "a", "y")]
    df = raw(rows).with_columns(pl.lit(None, dtype=pl.Int64).alias("out_pkts"))
    assert feats(df)["no_reply_frac"][0] == 1.0  # G2.1: degraded telemetry looks like no reply


# ---------------------------------------------------------------- F1 scenario (build_aligned)


def test_freeze_inside_calibration_is_causal_and_reproduces_before_q():
    rows = stream(2)
    df = raw(rows)
    flows = prepare_flows(df)
    q, mid = 20 * W, 32 * W
    cal = flows.filter(pl.col("end_ms") < mid)
    f1 = NoveltyMemory(freeze_ms=q).process(contacts_from_flows(cal, 30, freeze_ms=q))
    f3 = NoveltyMemory(freeze_ms=mid).process(contacts_from_flows(cal, 30, freeze_ms=mid))
    hist = aggregate(cal, "device", 30).select("key", "win", "new_dst_frac")
    j3 = hist.join(f3, on=["key", "win"])
    assert j3.height == hist.height
    np.testing.assert_array_equal(j3["new_dst_frac"], j3["nov_frozen"])  # F3: bit-exact
    j1 = hist.join(f1, on=["key", "win"])
    before = j1.filter(pl.col("win") < q // W)
    np.testing.assert_array_equal(before["new_dst_frac"], before["nov_frozen"])
    # after q, the F1 value is the share of destinations not seen before q
    known = set(cal.filter(pl.col("end_ms") < q)["dst"].unique().to_list())
    ref = aggregate(cal.filter(pl.col("end_ms") >= q), "device", 30, known_dst=known)
    after = ref.select("key", "win", "new_dst_frac").join(f1, on=["key", "win"])
    np.testing.assert_array_equal(after["new_dst_frac"], after["nov_frozen"])
    # no row depends on later traffic
    early = cal.filter(pl.col("end_ms") < 26 * W)
    p = NoveltyMemory(freeze_ms=q).process(contacts_from_flows(early, 30, freeze_ms=q))
    assert p.sort("win", "key").equals(f1.filter(pl.col("win") < 26).sort("win", "key"))


def test_replace_column_keeps_order_and_requires_values():
    frame = pl.DataFrame(
        {"key": ["b", "a", "c"], "win": [2, 1, 3], "new_dst_frac": [0.1, 0.2, 0.3]}
    )
    vals = pl.DataFrame({"key": ["c", "b"], "win": [3, 2], "v": [0.9, 0.8]})
    out = ED.replace_column(frame, vals, "v", required=pl.col("win") >= 2)
    assert out["key"].to_list() == ["b", "a", "c"]
    assert out["new_dst_frac"].to_list() == [0.8, 0.2, 0.9]
    with pytest.raises(RuntimeError):
        ED.replace_column(frame, vals, "v", required=pl.lit(True))


def test_member_seeds_match_m2():
    assert [ED.member_seed(0, m) for m in range(5)] == [1000, 1001, 1002, 1003, 1004]
    assert ED.member_seed(7, 2) == 1072
    assert set(ED.REPS).isdisjoint({0, 1, 2, 3, 4, 5})  # fresh randomness only


# ---------------------------------------------------------------- metrics and decisions


def labels(n_benign: int = 200) -> SimpleNamespace:
    key = np.array(["a"] * 10 + ["b"] * 6 + [f"h{i % 20}" for i in range(n_benign)])
    y = np.r_[np.ones(16, bool), np.zeros(n_benign, bool)]
    lab = SimpleNamespace(key=key, y=y, benign=~y, end=np.arange(len(y)) * W)
    lab.entities = ["a", "b"]
    lab.masks = {e: y & (key == e) for e in lab.entities}
    return lab


def test_metrics_entity_levels_and_assessment_gate():
    lab = labels()
    s_hold = np.linspace(0, 1, 200)
    s_ev = np.r_[np.r_[np.full(1, 2.0), np.zeros(9)], np.full(6, 2.0), np.zeros(200)]
    m = AD.metrics(lab, s_hold, s_ev, hours=1.0)
    assert m["entity_frac"] == {"a": 0.1, "b": 1.0}
    assert AD.entity_detected(0.1, 10, 1) and not AD.entity_detected(0.1, 10, 20)
    assert m["false_alerts"] == 0 and m["window_recall"] == pytest.approx(7 / 16)
    gate = np.ones(lab.y.size, bool)
    gate[10:16] = False  # entity b in unassessed time
    g = AD.metrics(lab, s_hold, s_ev, hours=1.0, assessed=gate)
    assert g["entity_frac"]["b"] == 0.0 and g["attack_windows_unassessed"] == 6
    assert g["windows_assessed_share"] == pytest.approx(1 - 6 / lab.y.size)


def test_ensemble_prefix_is_member_mean():
    z = {"s_ev": np.arange(15, dtype=float).reshape(5, 3)}
    np.testing.assert_array_equal(AD.ens(z, "s_ev", (0, 1)), [1.5, 2.5, 3.5])


def summary(recall: float, fa: float, r20: int = 50, u20: int = 10, u1: int = 5,
            coll: int = 0, fpr: float = 0.01) -> dict:  # fmt: skip
    nets = {n: {"recall": recall, "fa": fa, "fpr": fpr} for n in AD.NETWORKS}
    return {"networks": nets, "macro_recall": recall, "R": {1: 60, 20: r20, 50: 40},
            "U": {1: u1, 20: u20, 50: 12}, "collapses": coll}  # fmt: skip


def test_h1_rule():
    f0, f4 = summary(0.70, 1000), summary(0.705, 1020)
    assert AD.decide_h1(f0, summary(0.74, 1000), f4, True)["verdict"] == "SUPPORTED"  # path R
    assert AD.decide_h1(f0, summary(0.71, 1000), f4, True)["verdict"] == "NOT SUPPORTED"
    assert AD.decide_h1(f0, summary(0.70, 700), f4, True)["verdict"] == "SUPPORTED"  # path F
    assert AD.decide_h1(f0, summary(0.74, 1200), f4, True)["verdict"] == "NOT SUPPORTED"  # FA guard
    assert AD.decide_h1(f0, summary(0.74, 1000, u20=13), f4, True)["verdict"] == "NOT SUPPORTED"
    assert (
        AD.decide_h1(f0, summary(0.74, 1000), summary(0.76, 1000), True)["verdict"]
        == "NOT EVALUABLE"
    )
    assert AD.decide_h1(f0, summary(0.74, 1000), f4, False)["verdict"] == "NOT EVALUABLE"


def test_h2_rule():
    k = {1: summary(0.70, 1000, u1=11, u20=14), 2: summary(0.71, 1000, u1=4, u20=11),
         3: summary(0.71, 1000, u1=2, u20=10), 5: summary(0.71, 1000, u1=1, u20=10)}  # fmt: skip
    d = AD.decide_h2(k)
    # U1: delta 10, K=2 keeps 7 < 7.5; K=3 keeps 9. U20: delta 4, K=3 keeps 4 >= 3
    assert d["informative"] == [1, 20] and d["selected_K"] == 3
    flat = {kk: summary(0.7, 1000, u1=2, u20=10) for kk in (1, 2, 3, 5)}
    assert AD.decide_h2(flat)["verdict"] == "NOT EVALUABLE"


def test_c1_rule():
    t0 = summary(0.70, 1000, fpr=0.04)
    t0["networks"]["nfcic"]["fpr"] = 0.012
    c1 = summary(0.68, 600, fpr=0.02)
    c1["networks"]["nfcic"]["fpr"] = 0.010
    assert AD.decide_c1(t0, c1)["verdict"] == "SUPPORTED"
    c1["networks"]["nfcic"]["recall"] = 0.60  # loses > 0.05 where T0 was already near alpha
    assert AD.decide_c1(t0, c1)["verdict"] == "NOT SUPPORTED"
