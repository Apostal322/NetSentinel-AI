"""Phase 8m decision rules (H1, H3, selection), threshold rank, paired bootstrap and the
contamination replay (synthetic data only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.novelty import NoveltyMemory, destination_state

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


CMP = _load("phase8m_compare", "scripts/phase8m/compare.py")
CON = _load("phase8m_contamination", "scripts/phase8m/contamination.py")
NETS = CMP.NETWORKS


def nm(rec: dict, fa: dict, fpr: dict | None = None) -> dict:
    fpr = fpr or {}
    return {
        n: {"window_recall": rec[n], "false_alerts": fa[n], "fpr": fpr.get(n, 0.01)} for n in NETS
    }


def test_t0_is_the_conformal_rank():
    hold = np.arange(1, 201, dtype=float)  # k = ceil(201 * 0.99) = 199
    assert CMP.t0_of(hold) == 199.0
    assert CMP.t0_of(np.array([3.0, 1.0])) == 3.0  # k capped at n


def test_h3_clauses():
    b0 = nm(dict.fromkeys(NETS, 0.5), dict.fromkeys(NETS, 100))
    good = nm({"nfcic": 0.6, "nfunsw": 0.6, "nfton": 0.6, "nfbot": 0.47}, dict.fromkeys(NETS, 120))
    r = CMP.h3({"B0": b0, "B2": good}, "B2")
    assert r["supported"] and r["networks_with_gain"] == 3
    two = nm({"nfcic": 0.6, "nfunsw": 0.6, "nfton": 0.5, "nfbot": 0.5}, dict.fromkeys(NETS, 100))
    assert not CMP.h3({"B0": b0, "B2": two}, "B2")["c1_gain_on_3_of_4"]
    loss = nm({"nfcic": 0.6, "nfunsw": 0.6, "nfton": 0.6, "nfbot": 0.44}, dict.fromkeys(NETS, 100))
    assert not CMP.h3({"B0": b0, "B2": loss}, "B2")["c2_no_loss"]
    load = nm(dict.fromkeys(NETS, 0.6), {**dict.fromkeys(NETS, 100), "nfton": 126})
    assert not CMP.h3({"B0": b0, "B2": load}, "B2")["c3_workload"]
    zero = nm(dict.fromkeys(NETS, 0.5), {**dict.fromkeys(NETS, 100), "nfbot": 0})
    assert CMP.h3(
        {"B0": zero, "B2": nm(dict.fromkeys(NETS, 0.6), {**dict.fromkeys(NETS, 100), "nfbot": 1})},
        "B2",
    )["false_alert_ratio"]["nfbot"] == float("inf")


def test_h1_uses_every_high_fpr_network():
    fpr0 = {"nfcic": 0.013, "nfunsw": 0.037, "nfton": 0.148, "nfbot": 0.119}
    b0 = nm(dict.fromkeys(NETS, 0.5), dict.fromkeys(NETS, 1), fpr0)
    ok = nm(dict.fromkeys(NETS, 0.5), dict.fromkeys(NETS, 1),
            {"nfcic": 0.015, "nfunsw": 0.036, "nfton": 0.10, "nfbot": 0.118})  # fmt: skip
    r = CMP.h1({"B0": b0, "B2": ok})
    assert r["high_fpr_networks"] == ["nfunsw", "nfton", "nfbot"] and r["supported"]
    flat = nm(
        dict.fromkeys(NETS, 0.5), dict.fromkeys(NETS, 1), {**fpr0, "nfunsw": 0.037, "nfton": 0.10}
    )
    assert not CMP.h1({"B0": b0, "B2": flat})["lower_on_every_high"]
    up = nm(dict.fromkeys(NETS, 0.5), dict.fromkeys(NETS, 1),
            {"nfcic": 0.021, "nfunsw": 0.03, "nfton": 0.10, "nfbot": 0.1})  # fmt: skip
    assert not CMP.h1({"B0": b0, "B2": up})["low_stay_within_2alpha"]


def test_selection_rule():
    yes, no = {"supported": True}, {"supported": False}
    m = {"B1": nm(dict.fromkeys(NETS, 0.6), dict.fromkeys(NETS, 1)),
         "B2": nm(dict.fromkeys(NETS, 0.62), dict.fromkeys(NETS, 1))}  # fmt: skip
    assert CMP.select(yes, yes, m)["candidate"] == "B1"  # B2 not 0.05 better on 3 networks
    m["B2"] = nm(dict.fromkeys(NETS, 0.7), dict.fromkeys(NETS, 1))
    assert CMP.select(yes, yes, m)["candidate"] == "B2"
    assert CMP.select(yes, no, m)["candidate"] == "B2"
    assert CMP.select(no, yes, m)["candidate"] is None
    assert CMP.select(no, no, m)["candidate"] is None


def test_paired_bootstrap_identical_and_shifted():
    rng = np.random.default_rng(0)
    key = np.repeat([f"h{i}" for i in range(30)], 20)
    hosts, idx = np.unique(key, return_inverse=True)
    y = np.zeros(key.size, bool)
    y[:100] = True
    dom = SimpleNamespace(hosts=hosts, host_idx=idx, benign=~y, y=y)
    a = [rng.random(key.size) < 0.2 for _ in range(3)]
    same = CMP.paired_bootstrap(dom, a, a)
    assert same["fpr"]["diff"] == 0 and same["fpr"]["lower95"] == 0 == same["fpr"]["upper95"]
    more = [x | y for x in a]  # B catches every attack window
    r = CMP.paired_bootstrap(dom, a, more)["window_recall"]
    assert r["diff"] > 0 and r["lower95"] > 0


def contacts(rows: list[tuple[int, str, str]]) -> pl.DataFrame:
    return (
        pl.DataFrame(
            {"win": [r[0] for r in rows], "src": [r[1] for r in rows], "dst": [r[2] for r in rows]}
        )
        .with_columns(((pl.col("win") + 1) * CON.W_MS).alias("window_end_ms"))
        .sort("win", "src", "dst")
    )


def test_replay_without_injection_equals_one_shot(tmp_path):
    rng = np.random.default_rng(1)
    rows = sorted(
        {
            (int(w), f"h{rng.integers(5)}", f"d{rng.integers(40)}")
            for w in rng.integers(0, 400, 2000)
        }
    )
    c = contacts(rows)
    d = tmp_path / "contacts_p1x"
    d.mkdir()
    for i, lo in enumerate(range(0, 400, 100)):
        c.filter((pl.col("win") >= lo) & (pl.col("win") < lo + 100)).write_parquet(
            d / f"part-{i:05d}.parquet"
        )
    mid, straddle = 150 * CON.W_MS + 7, 150
    one = NoveltyMemory(freeze_ms=mid)
    ref = one.process(c)
    state, rest = CON.checkpoint(tmp_path, mid, straddle)
    mem, out = CON.replay(state, rest, straddle, None, emit=frozenset({"h1", "h2"}))
    assert out.equals(
        ref.filter(pl.col("win") >= straddle).filter(pl.col("key").is_in(["h1", "h2"]))
    )
    assert destination_state(mem).equals(destination_state(one))
    inj = CON.beacon_frame(["h1"], straddle + 1, 399, 10)  # every 20 windows
    mem2, _ = CON.replay(state, rest, straddle, inj, emit=frozenset())
    s = mem2.dst[CON.BEACON]
    assert s.promoted_ms is None and s.sources == {"h1"}  # one host: never accepted
    assert inj.height == len(range(straddle + 1, 400, 20))
    two = CON.beacon_frame(["h1", "h2"], straddle + 1, 399, 10)
    mem3, _ = CON.replay(state, rest, straddle, two, emit=frozenset())
    assert mem3.dst[CON.BEACON].promoted_ms is not None  # two hosts over > 1 h: accepted


@pytest.mark.parametrize("period", CON.PERIODS_MIN)
def test_beacon_frame_spacing(period):
    f = CON.beacon_frame(["a"], 10, 10 + 2 * 120 * 6, period)
    steps = np.diff(f["win"].to_numpy())
    assert (steps == period * 2).all()
