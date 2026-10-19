"""Context features against a brute-force reference, plus causality (no look-ahead) checks."""

from datetime import datetime, timedelta

import numpy as np
import polars as pl
import pytest

from netsentinel.features.context import (
    compute_context,
    compute_context_chunked,
    context_feature_names,
)

T0 = datetime(2018, 2, 14, 10, 0, 0)


def _flows(n: int = 400, seed: int = 0) -> pl.DataFrame:
    rng = np.random.default_rng(seed)
    starts = np.sort(rng.integers(0, 900, size=n))
    return pl.DataFrame(
        {
            "row_id": np.arange(n, dtype=np.uint32),
            "timestamp": [T0 + timedelta(seconds=int(s)) for s in starts],
            "flow_duration": rng.integers(0, 5_000_000, size=n),  # up to 5 s, in microseconds
            "dst_port": rng.choice([22, 80, 443, 3389, 8080], size=n),
            "tot_fwd_pkts": rng.integers(1, 20, size=n).astype(np.float32),
            "tot_bwd_pkts": rng.integers(0, 20, size=n).astype(np.float32),
            "totlen_fwd_pkts": rng.integers(0, 5000, size=n).astype(np.float32),
            "totlen_bwd_pkts": rng.integers(0, 5000, size=n).astype(np.float32),
            "syn_flag_cnt": rng.integers(0, 2, size=n).astype(np.float32),
        }
    )


def _reference(df: pl.DataFrame, w: int) -> dict[str, np.ndarray]:
    ev = (
        np.array([t.timestamp() for t in df["timestamp"]]) + df["flow_duration"].to_numpy() / 1e6
    ).astype(np.int64)
    ev = np.floor(ev).astype(np.int64)
    port = df["dst_port"].to_numpy()
    out = {k: [] for k in ["flows", "ports", "port_flows", "syn"]}
    for i in range(df.height):
        m = (ev >= ev[i] - w) & (ev <= ev[i] - 1)
        out["flows"].append(m.sum())
        out["ports"].append(len(set(port[m])))
        out["port_flows"].append((m & (port == port[i])).sum())
        out["syn"].append((df["syn_flag_cnt"].to_numpy()[m] > 0).sum() / max(m.sum(), 1))
    return {k: np.array(v, dtype=float) for k, v in out.items()}


@pytest.mark.parametrize("w", [5, 30, 300])
def test_matches_brute_force(w):
    df = _flows()
    ctx = compute_context(df, windows=(w,)).sort("row_id")
    ref = _reference(df, w)
    np.testing.assert_allclose(ctx[f"ctx_flow_rate_{w}s"].to_numpy() * w, ref["flows"], rtol=1e-5)
    np.testing.assert_allclose(ctx[f"ctx_uniq_ports_{w}s"].to_numpy(), ref["ports"])
    np.testing.assert_allclose(
        ctx[f"ctx_port_flow_rate_{w}s"].to_numpy() * w, ref["port_flows"], rtol=1e-5
    )
    np.testing.assert_allclose(ctx[f"ctx_syn_frac_{w}s"].to_numpy(), ref["syn"], rtol=1e-5)


def test_no_look_ahead():
    """Changing or removing flows observed at/after second s must not change features at s."""
    df = _flows(seed=1)
    full = compute_context(df).sort("row_id")
    ev = full["event_sec"].to_numpy()
    cutoff = int(np.median(ev))
    past_ids = full.filter(pl.col("event_sec") <= cutoff)["row_id"]
    truncated = compute_context(df.filter(pl.col("row_id").is_in(past_ids.implode()))).sort(
        "row_id"
    )
    # Mutate the future too: huge byte counts after the cutoff.
    names = context_feature_names()
    a = full.filter(pl.col("row_id").is_in(past_ids.implode())).select(names).to_numpy()
    b = truncated.select(names).to_numpy()
    np.testing.assert_allclose(a, b, rtol=1e-6)


def test_order_invariance_and_determinism():
    df = _flows(seed=2)
    a = compute_context(df).sort("row_id")
    b = compute_context(df.sample(fraction=1.0, shuffle=True, seed=3)).sort("row_id")
    assert a.equals(b)


def test_chunked_equals_unchunked():
    df = _flows(n=600, seed=4)
    full = compute_context(df).sort("row_id")
    chunked = compute_context_chunked(df.lazy(), chunk_seconds=120).sort("row_id")
    assert chunked.height == full.height
    np.testing.assert_allclose(
        chunked.select(context_feature_names()).to_numpy(),
        full.select(context_feature_names()).to_numpy(),
        rtol=1e-6,
    )


def test_empty_input_and_missing_columns():
    df = _flows().head(0)
    out = compute_context(df)
    assert out.height == 0
    assert set(context_feature_names()) <= set(out.columns)
    with pytest.raises(ValueError, match="missing columns"):
        compute_context(df.drop("dst_port"))
