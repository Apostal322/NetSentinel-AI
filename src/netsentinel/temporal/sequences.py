"""Causal per-service flow sequences for temporal models.

For a target flow observed in second s (event time) the sequence is the previous `length`
flows to the SAME destination port observed in seconds < s, taken from the full day stream
(not the sample), ordered oldest -> newest. Same-second flows are excluded because their order
within a second is not observable (same rule as the context features). Missing positions are
zero-padded and flagged by a mask. Each step carries a compact, signed-log-scaled feature
vector plus the time gap to the target flow.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.features.context import event_seconds

log = logging.getLogger(__name__)
STEP_FEATURES: tuple[str, ...] = (
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_iat_mean", "syn_flag_cnt", "rst_flag_cnt",
    "ack_flag_cnt", "down_per_up_ratio",
)  # fmt: skip
N_STEP = len(STEP_FEATURES) + 1  # + log1p(gap seconds to the target)


def _slog(x: np.ndarray) -> np.ndarray:
    x = np.nan_to_num(x.astype(np.float64), nan=0.0, posinf=0.0, neginf=0.0)
    return (np.sign(x) * np.log1p(np.abs(x))).astype(np.float32)


def build_day_sequences(
    day_parquet: str | Path, target_row_ids: np.ndarray, length: int = 16
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (row_ids, X[n, length, N_STEP], mask[n, length]) for the requested targets."""
    stream = (
        pl.scan_parquet(day_parquet)
        .select("row_id", "timestamp", "dst_port", *STEP_FEATURES)
        .with_columns(event_seconds().alias("event_sec"))
        .drop("timestamp")
        .sort("dst_port", "event_sec", "row_id")
        .collect()
    )
    port = stream["dst_port"].to_numpy()
    sec = stream["event_sec"].to_numpy()
    feats = _slog(stream.select(STEP_FEATURES).to_numpy())
    row_ids = stream["row_id"].to_numpy()
    pos_of = np.full(int(row_ids.max()) + 1, -1, dtype=np.int64)
    pos_of[row_ids] = np.arange(len(row_ids))
    targets = np.asarray(target_row_ids, dtype=np.int64)
    tpos = pos_of[targets]
    if (tpos < 0).any():
        raise ValueError("some target row_ids are not in the day stream")
    # First position of each (port, second) run: everything before it in the same port group
    # is strictly earlier in time.
    key_change = np.r_[True, (port[1:] != port[:-1]) | (sec[1:] != sec[:-1])]
    run_start = np.maximum.accumulate(np.where(key_change, np.arange(len(port)), 0))
    port_start = np.maximum.accumulate(
        np.where(np.r_[True, port[1:] != port[:-1]], np.arange(len(port)), 0)
    )
    end = run_start[tpos]  # exclusive: strictly-earlier seconds of the same port
    begin = np.maximum(port_start[tpos], end - length)
    X = np.zeros((len(targets), length, N_STEP), dtype=np.float32)  # noqa: N806
    mask = np.zeros((len(targets), length), dtype=bool)
    for k in range(length):  # right-aligned: last slot = most recent previous flow
        src = end - length + k
        ok = src >= begin
        idx = src[ok]
        X[ok, k, :-1] = feats[idx]
        X[ok, k, -1] = np.log1p(np.maximum(sec[tpos[ok]] - sec[idx], 0)).astype(np.float32)
        mask[ok, k] = True
    return targets, X, mask
