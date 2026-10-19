"""Causal per-service flow sequences for temporal models.

For a target flow observed in second s (event time) the sequence is the previous `length`
flows to the SAME destination port observed in seconds < s, taken from the full day stream
(not the sample), ordered oldest -> newest. Same-second flows are excluded because their order
within a second is not observable (same rule as the context features). Missing positions are
zero-padded and flagged by a mask. Each step carries a compact, signed-log-scaled feature
vector plus the time gap to the target flow.

Memory: only (row_id, dst_port, event_sec) of the full stream are sorted; step features are
then read for the (at most targets x length) rows that actually appear in a sequence.
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
    x = np.nan_to_num(x.astype(np.float32), nan=0.0, posinf=0.0, neginf=0.0)
    return np.sign(x) * np.log1p(np.abs(x))


def build_day_sequences(
    day_parquet: str | Path, target_row_ids: np.ndarray, length: int = 16
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (row_ids, X[n, length, N_STEP], mask[n, length]) for the requested targets."""
    stream = (
        pl.scan_parquet(day_parquet)
        .select(
            pl.col("row_id").cast(pl.UInt32),
            pl.col("dst_port").cast(pl.Int32),
            event_seconds().alias("event_sec"),
        )  # fmt: skip
        .sort("dst_port", "event_sec", "row_id")
        .collect()
    )
    port = stream["dst_port"].to_numpy()
    sec = stream["event_sec"].to_numpy()
    row_ids = stream["row_id"].to_numpy()
    del stream
    pos_of = np.full(int(row_ids.max()) + 1, -1, dtype=np.int64)
    pos_of[row_ids] = np.arange(len(row_ids))
    targets = np.asarray(target_row_ids, dtype=np.int64)
    if targets.size and (targets.max() >= len(pos_of) or (pos_of[targets] < 0).any()):
        raise ValueError("some target row_ids are not in the day stream")
    tpos = pos_of[targets]
    del pos_of
    # First position of each (port, second) run: everything before it in the same port group
    # is strictly earlier in time.
    idx = np.arange(len(port))
    run_start = np.maximum.accumulate(
        np.where(np.r_[True, (port[1:] != port[:-1]) | (sec[1:] != sec[:-1])], idx, 0)
    )
    port_start = np.maximum.accumulate(np.where(np.r_[True, port[1:] != port[:-1]], idx, 0))
    del idx
    end = run_start[tpos]  # exclusive: strictly-earlier seconds of the same port
    begin = np.maximum(port_start[tpos], end - length)
    del run_start, port_start
    # Positions needed by any sequence -> read their step features only.
    src = end[:, None] - length + np.arange(length)[None, :]  # (n, length)
    valid = src >= begin[:, None]
    needed = np.unique(src[valid])
    feats_df = (
        pl.scan_parquet(day_parquet)
        .select(pl.col("row_id").cast(pl.UInt32), *STEP_FEATURES)
        .filter(pl.col("row_id").is_in(pl.Series(row_ids[needed]).implode()))
        .collect()
    )
    lookup = np.full(int(row_ids.max()) + 1, -1, dtype=np.int64)
    lookup[feats_df["row_id"].to_numpy()] = np.arange(feats_df.height)
    feats = _slog(feats_df.select(STEP_FEATURES).to_numpy())
    del feats_df
    X = np.zeros((len(targets), length, N_STEP), dtype=np.float32)  # noqa: N806
    mask = valid
    k_rows, k_cols = np.nonzero(valid)
    pos = src[k_rows, k_cols]
    X[k_rows, k_cols, :-1] = feats[lookup[row_ids[pos]]]
    X[k_rows, k_cols, -1] = np.log1p(np.maximum(sec[tpos[k_rows]] - sec[pos], 0))
    return targets, X, mask
