"""Phase 8p victim-side features (src/netsentinel/behavior/victim.py): direction, shared
destinations, missing reply fields, window boundaries, duplicates, ordering, causal history,
chunked equivalence and the source context."""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.victim import (
    CONTEXT_FEATURES,
    SERVICE_FEATURES,
    VICTIM_FEATURES,
    History,
    source_context,
    victim_windows,
)
from netsentinel.behavior.windows import prepare_flows

W = 30_000


def raw(rows: list[tuple], attack: list[int] | None = None) -> pl.DataFrame:
    """rows: (end_ms, src, dst, dst_port[, out_pkts, dur_ms])."""
    n = len(rows)
    df = pl.DataFrame({
        "flow_end_milliseconds": [r[0] for r in rows], "ipv4_src_addr": [r[1] for r in rows],
        "ipv4_dst_addr": [r[2] for r in rows], "dst_port": [r[3] for r in rows],
        "protocol": [6] * n, "in_bytes": [100] * n, "out_bytes": [300] * n, "in_pkts": [2] * n,
        "out_pkts": [r[4] if len(r) > 4 else 2 for r in rows],
        "flow_duration_milliseconds": [r[5] if len(r) > 5 else 10 for r in rows],
    })  # fmt: skip
    if attack is not None:
        df = df.with_columns(pl.Series("is_attack", attack, dtype=pl.Float64))
    return df


def vw(df: pl.DataFrame, **kw) -> pl.DataFrame:
    return victim_windows(prepare_flows(df), **kw)


def test_many_sources_one_destination_and_direction():
    rows = [(1_000, f"c{i}", "srv", 80) for i in range(5)] + [(2_000, "srv", "c0", 5000)]
    v = vw(raw(rows))
    srv = v.filter(pl.col("dst") == "srv").row(0, named=True)
    assert srv["flows"] == 5 and srv["srcs"] == 5
    assert srv["v_top_src_share"] == pytest.approx(0.2)
    assert srv["v_web_share"] == 1.0
    assert srv["v_resp_share"] == pytest.approx(
        1500 / (500 + 1500 + 1)
    )  # responder bytes = out_bytes
    c0 = v.filter(pl.col("dst") == "c0").row(0, named=True)  # the server answering is a flow to c0
    assert c0["flows"] == 1 and c0["v_web_share"] == 0.0


def test_missing_reverse_fields_are_not_imputed():
    df = raw([(1_000, "a", "srv", 80), (2_000, "b", "srv", 80)]).with_columns(
        pl.lit(None, dtype=pl.Int64).alias("out_pkts"),
        pl.lit(None, dtype=pl.Int64).alias("out_bytes"),
    )
    r = vw(df).row(0, named=True)
    assert r["v_no_reply_frac"] == 1.0 and r["v_resp_share"] == 0.0 and r["v_log_down"] == 0.0


def test_window_boundary_long_connection_and_short_share():
    rows = [
        (W - 1, "a", "srv", 80),
        (W, "a", "srv", 80, 2, 50_000),
    ]  # second: long, ends in window 1
    v = vw(raw(rows)).sort("win")
    assert v["win"].to_list() == [0, 1]
    assert v["v_short_frac"].to_list() == [1.0, 0.0]


def test_duplicates_count_and_order_invariance():
    rows = [(1_000, "a", "srv", 80), (2_000, "b", "srv", 443), (40_000, "a", "srv", 80)]
    df = raw(rows)
    dup = vw(pl.concat([df, df.head(1)]))
    assert dup.filter(pl.col("win") == 0)["flows"][0] == 3
    assert vw(df).equals(vw(df.sample(fraction=1.0, shuffle=True, seed=1)))


def test_history_is_causal_and_chunking_invariant():
    rng = np.random.default_rng(0)
    rows = [(int(t), f"c{rng.integers(5)}", f"s{rng.integers(3)}", 80)
            for t in np.sort(rng.integers(0, 40 * W, 800))]  # fmt: skip
    df = raw(rows)
    one = vw(df, history=History())
    h = History()
    cut = 20 * W
    parts = pl.concat([vw(df.filter(pl.col("flow_end_milliseconds") < cut), history=h),
                       vw(df.filter(pl.col("flow_end_milliseconds") >= cut), history=h)]
                      ).sort("win", "dst")  # fmt: skip
    np.testing.assert_allclose(one["v_hist_dev"], parts["v_hist_dev"], atol=1e-12)
    # first window of a host has no history; later traffic never changes earlier rows
    first = one.group_by("dst").agg(pl.col("v_hist_n").sort_by("win").first())
    assert (first["v_hist_n"] == 0).all()
    early = vw(df.filter(pl.col("flow_end_milliseconds") < 10 * W), history=History())
    a = one.filter(pl.col("win") < 10).sort("win", "dst")
    assert a.select(VICTIM_FEATURES).equals(early.sort("win", "dst").select(VICTIM_FEATURES))
    with pytest.raises(ValueError):
        vw(df.head(5), history=h)  # out of order after the history moved on


def test_history_deviation_value():
    rows = [(1_000, "a", "srv", 80)] + [(W + i, "a", "srv", 80) for i in range(3)]
    v = vw(raw(rows), history=History()).sort("win")
    assert v["v_hist_dev"][1] == pytest.approx(np.log(4) - np.log(2))


def test_labels_are_counts_not_features():
    df = raw([(1_000, "a", "srv", 80), (2_000, "evil", "srv", 80)], attack=[0, 1])
    r = vw(df).row(0, named=True)
    assert r["attack_flows"] == 1 and r["attack_srcs"] == 1 and r["flows"] == 2  # mixed window
    assert not set(VICTIM_FEATURES) & {"attack_flows", "attack_srcs"}


def test_source_context_fan_in_and_service_mix():
    rows = [(1_000, f"c{i}", "srv", 80) for i in range(4)] + [(2_000, "c0", "dns", 53)]
    f = prepare_flows(raw(rows))
    v = victim_windows(f)
    sx = source_context(f, v)
    c0 = sx.filter(pl.col("key") == "c0").row(0, named=True)
    assert c0["c_v_log_srcs_max"] == pytest.approx(np.log(5))  # srv has 4 sources
    assert c0["s_web_share"] == 0.5 and c0["s_dns_share"] == 0.5
    assert c0["s_log_services"] == pytest.approx(np.log(3))
    assert set(CONTEXT_FEATURES + SERVICE_FEATURES) <= set(sx.columns)
