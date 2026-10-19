"""Causal per-port sequences vs a brute-force reference on SYNTHETIC flows."""

from datetime import datetime, timedelta

import numpy as np
import polars as pl
import pytest

from netsentinel.temporal.sequences import N_STEP, STEP_FEATURES, build_day_sequences


@pytest.fixture
def day(tmp_path):
    rng = np.random.default_rng(0)
    n = 500
    t0 = datetime(2018, 2, 14, 9)
    df = pl.DataFrame(
        {
            "row_id": np.arange(n, dtype=np.uint32),
            "timestamp": [t0 + timedelta(seconds=int(s)) for s in rng.integers(0, 600, n)],
            "dst_port": rng.choice([22, 80, 443], n),
            **{f: rng.random(n).astype(np.float32) for f in STEP_FEATURES if f != "flow_duration"},
            "flow_duration": rng.integers(0, 3_000_000, n),
        }
    )
    path = tmp_path / "day.parquet"
    df.write_parquet(path)
    return df, path


def test_sequences_are_causal_and_match_reference(day):
    df, path = day
    targets = np.arange(0, 500, 7)
    ids, X, mask = build_day_sequences(path, targets, length=5)  # noqa: N806
    assert X.shape == (len(targets), 5, N_STEP)
    ev = np.array([t.timestamp() for t in df["timestamp"]]).astype(np.int64) + (
        df["flow_duration"].to_numpy() // 1_000_000
    )
    port = df["dst_port"].to_numpy()
    for k, t in enumerate(ids):
        prev = np.flatnonzero((port == port[t]) & (ev < ev[t]))
        prev = prev[np.lexsort((prev, ev[prev]))][-5:]  # most recent 5, oldest first
        assert mask[k].sum() == len(prev)
        gaps = np.log1p(ev[t] - ev[prev]).astype(np.float32)
        np.testing.assert_allclose(X[k, 5 - len(prev) :, -1], gaps, rtol=1e-6)
        assert not mask[k, : 5 - len(prev)].any()  # padding first (right-aligned)


def test_unknown_target_rejected(day):
    _, path = day
    with pytest.raises((ValueError, IndexError)):
        build_day_sequences(path, np.array([10_000]), length=4)
