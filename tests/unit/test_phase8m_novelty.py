"""Phase 8m adaptive destination novelty: causality, policies, equivalence with the deployed
`new_dst_frac`, streaming/batch agreement and checkpointing (synthetic data only)."""

from __future__ import annotations

import math
import pickle

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.novelty import (
    DAY_MS,
    FEATURES,
    NoveltyMemory,
    contacts_from_flows,
    destination_state,
)
from netsentinel.behavior.windows import aggregate

W = 30_000


def flows(rows: list[tuple[int, str, str]]) -> pl.DataFrame:
    """(end_ms, src, dst) -> the minimal prepared-flow columns `aggregate` needs."""
    n = len(rows)
    return pl.DataFrame({
        "end_ms": [r[0] for r in rows], "src": [r[1] for r in rows], "dst": [r[2] for r in rows],
        "dst_port": [443] * n, "protocol": [6] * n, "service": ["https"] * n,
        "up": [100.0] * n, "down": [100.0] * n, "pkts": [2.0] * n, "dur_ms": [10.0] * n,
        "no_reply": [False] * n, "rst": [False] * n, "udp": [False] * n,
    })  # fmt: skip


def random_stream(seed: int = 0, n: int = 3000, hosts: int = 6, dsts: int = 60, span_days: int = 6):
    rng = np.random.default_rng(seed)
    t = np.sort(rng.integers(0, span_days * DAY_MS, n))
    return [(int(x), f"h{rng.integers(hosts)}", f"d{int(rng.zipf(1.6)) % dsts}") for x in t]


def test_frozen_policy_reproduces_new_dst_frac():
    rows = random_stream()
    f = flows(rows)
    freeze = 3 * DAY_MS
    cal = f.filter(pl.col("end_ms") < freeze)
    ev = f.filter(pl.col("end_ms") >= freeze)
    ref_cal = aggregate(cal, "device", 30)
    known = set(cal["dst"].unique().to_list())
    ref_ev = aggregate(ev, "device", 30, known_dst=known)
    mem = NoveltyMemory(freeze_ms=freeze)
    out = mem.process(contacts_from_flows(f))
    for ref in (ref_cal, ref_ev):
        j = ref.select("key", "win", "new_dst_frac").join(out, on=["key", "win"])
        assert j.height == ref.height
        np.testing.assert_allclose(j["new_dst_frac"], j["nov_frozen"], atol=1e-12)


def test_features_are_causal():
    rows = random_stream(1)
    full = NoveltyMemory(freeze_ms=2 * DAY_MS).process(contacts_from_flows(flows(rows)))
    cut = rows[len(rows) // 2][0] // W
    prefix = [r for r in rows if r[0] // W <= cut]
    part = NoveltyMemory(freeze_ms=2 * DAY_MS).process(contacts_from_flows(flows(prefix)))
    a = full.filter(pl.col("win") <= cut).sort("win", "key")
    assert a.equals(part.sort("win", "key"))  # later traffic never changes earlier windows


def test_first_and_repeated_observation_and_guarded_promotion():
    h = 3_600_000
    rows = [(10, "a", "x"), (W + 10, "a", "x"),  # one source: never promoted
            (h + 10, "a", "x"),  # one source over an hour: still not (needs 2 sources)
            (h + W + 10, "b", "x"),  # second source, span >= 1 h: promoted after this window
            (h + 2 * W + 10, "c", "x")]  # fmt: skip
    out = NoveltyMemory().process(contacts_from_flows(flows(rows))).sort("win", "key")
    assert out["nov_unconditional"].to_list() == [1.0, 0.0, 0.0, 0.0, 0.0]
    assert out["nov_guarded"].to_list() == [1.0, 1.0, 1.0, 1.0, 0.0]
    assert out["nov_host"].to_list() == [1.0, 0.0, 0.0, 1.0, 1.0]  # first contact per source
    mem = NoveltyMemory()
    mem.process(contacts_from_flows(flows(rows)))
    st = destination_state(mem).row(0, named=True)
    assert st["sources"] == 3 and st["promoted_ms"] == 2 * W + h - 1  # end of b's window - 1 ms
    burst = [(10, "a", "y"), (W + 10, "b", "y"), (2 * W + 10, "c", "y")]  # 3 sources in 1 min
    assert NoveltyMemory().process(contacts_from_flows(flows(burst)))["nov_guarded"].min() == 1.0


def test_persistent_single_host_beacon_is_never_absorbed_by_guarded_memory():
    beacon = [(k * 300_000 + 5, "victim", "c2") for k in range(14 * 288)]  # every 5 min, 14 days
    out = NoveltyMemory().process(contacts_from_flows(flows(beacon)))
    assert out["nov_guarded"].min() == 1.0
    assert out["nov_unconditional"].sum() == 1.0  # unconditional absorbs it after one window


def test_decay_familiarity_and_prevalence():
    rows = [(10, "a", "x"), (10, "b", "x"), (DAY_MS + 10, "c", "x")]
    out = NoveltyMemory(tau_ms=DAY_MS).process(contacts_from_flows(flows(rows))).sort("win", "key")
    last = out.filter(pl.col("key") == "c")
    age = (DAY_MS + W - 1) - (W - 1)  # window ends minus 1 ms
    assert last["familiarity_decay"][0] == pytest.approx(math.exp(-age / DAY_MS))
    assert last["log_prevalence"][0] == pytest.approx(math.log1p(2))
    assert out.select([pl.col(f).is_nan().any() for f in FEATURES]).row(0) == (False,) * len(
        FEATURES
    )


def test_excluded_sources_only_before_freeze():
    rows = [(10, "atk", "x"), (DAY_MS + 10, "atk", "y"), (DAY_MS + W + 10, "h", "y"),
            (DAY_MS + 2 * W + 10, "h", "x")]  # fmt: skip
    mem = NoveltyMemory(freeze_ms=DAY_MS, excluded_sources=frozenset({"atk"}))
    out = mem.process(contacts_from_flows(flows(rows))).sort("win", "key")
    assert "x" not in mem.frozen  # the calibration attacker's destination never became known
    h = out.filter(pl.col("key") == "h")
    assert h["nov_unconditional"].to_list() == [0.0, 1.0]  # y learned after the freeze; x never


def test_chunked_equals_one_shot_and_checkpoint_resume():
    rows = random_stream(2)
    c = contacts_from_flows(flows(rows))
    one = NoveltyMemory(freeze_ms=3 * DAY_MS).process(c)
    wins = c["win"].unique().sort()
    cuts = [wins[len(wins) // 3], wins[2 * len(wins) // 3]]
    mem = NoveltyMemory(freeze_ms=3 * DAY_MS)
    parts = [mem.process(c.filter(pl.col("win") < cuts[0]))]
    mem = pickle.loads(pickle.dumps(mem))  # restart from a checkpoint
    parts.append(mem.process(c.filter((pl.col("win") >= cuts[0]) & (pl.col("win") < cuts[1]))))
    parts.append(mem.process(c.filter(pl.col("win") >= cuts[1])))
    assert pl.concat(parts).equals(one)
    with pytest.raises(ValueError):
        mem.process(c.filter(pl.col("win") == wins[0]))  # out-of-order input refused


def test_bounded_state_and_empty_input():
    rows = [(k * W + 1, f"s{k}", "popular") for k in range(100)]
    mem = NoveltyMemory(source_cap=8)
    mem.process(contacts_from_flows(flows(rows)))
    assert len(mem.dst["popular"].sources) == 8
    assert NoveltyMemory().process(contacts_from_flows(flows([]))).height == 0


def test_emit_subset_keeps_memory_and_rows_identical():
    rows = random_stream(3)
    c = contacts_from_flows(flows(rows))
    full_mem, sub_mem = NoveltyMemory(freeze_ms=3 * DAY_MS), NoveltyMemory(freeze_ms=3 * DAY_MS)
    full = full_mem.process(c)
    sub = sub_mem.process(c, emit=frozenset({"h1"}))
    assert sub.equals(full.filter(pl.col("key") == "h1"))
    assert destination_state(sub_mem).equals(destination_state(full_mem))
    assert NoveltyMemory().process(c, emit=frozenset({"nobody"})).height == 0


def test_window_straddling_the_freeze_adds_its_calibration_destinations():
    freeze = 10 * W + 15_000  # inside window 10
    rows = [(10 * W + 5, "a", "x"),  # calibration part of window 10
            (10 * W + 20_000, "b", "y"),  # evaluation part of the same window
            (11 * W + 5, "c", "x"), (11 * W + 6, "c", "y")]  # fmt: skip
    f = flows(rows)
    mem = NoveltyMemory(freeze_ms=freeze)
    out = mem.process(contacts_from_flows(f, freeze_ms=freeze)).sort("win", "key")
    assert mem.frozen == {"x"}  # x came from a calibration flow, y only after the freeze
    known = set(f.filter(pl.col("end_ms") < freeze)["dst"].to_list())
    ref = aggregate(f.filter(pl.col("end_ms") >= freeze), "device", 30, known_dst=known)
    j = ref.select("key", "win", "new_dst_frac").join(out, on=["key", "win"])
    later = j.filter(pl.col("win") > 10)
    np.testing.assert_allclose(later["new_dst_frac"], later["nov_frozen"])
    assert later["nov_frozen"].to_list() == [0.5]
