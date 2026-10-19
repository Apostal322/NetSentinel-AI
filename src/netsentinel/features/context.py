"""Causal temporal context features over trailing multi-scale windows.

Timing contract (this is what makes the features usable at inference time):
* A flow becomes observable at its *event time* = start timestamp + flow duration, i.e. when the
  flow record is exported. Event time is floored to whole seconds (the source resolution is 1 s).
* For a flow observed in second `s`, a window of `W` seconds covers the complete seconds
  `[s - W, s - 1]`. The current, still-incomplete second is excluded, so no feature depends on
  flows observed at or after the prediction time. Prediction latency introduced by this
  aggregation is at most 1 s on top of the flow's own duration.
* Context is computed on the full stream of a capture day (before any sampling or splitting),
  exactly as a sensor would see it. Labels are never used.

The processed IDS2018 CSVs carry no host addresses (except 2018-02-20), so context is
network-wide and per destination port, not per host. See docs/limitations.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import polars as pl

DEFAULT_WINDOWS: tuple[int, ...] = (5, 30, 300)
REQUIRED_COLUMNS = (
    "row_id",
    "timestamp",
    "flow_duration",
    "dst_port",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "syn_flag_cnt",
)


def event_seconds() -> pl.Expr:
    """Expression for whole-second event time (epoch seconds) = start + duration."""
    start_us = pl.col("timestamp").dt.epoch("us")
    dur_us = pl.col("flow_duration").clip(lower_bound=0)
    return ((start_us + dur_us) // 1_000_000).alias("event_sec")


def context_feature_names(windows: Sequence[int] = DEFAULT_WINDOWS) -> list[str]:
    names = []
    for w in windows:
        names += [
            f"ctx_flow_rate_{w}s",
            f"ctx_pkt_rate_{w}s",
            f"ctx_byte_rate_{w}s",
            f"ctx_syn_frac_{w}s",
            f"ctx_noreply_frac_{w}s",
            f"ctx_uniq_ports_{w}s",
            f"ctx_port_flow_rate_{w}s",
            f"ctx_port_share_{w}s",
        ]
    if len(windows) >= 2:
        lo, hi = min(windows), max(windows)
        names += [f"ctx_flow_surge_{lo}_{hi}", f"ctx_port_surge_{lo}_{hi}"]
    return names


def _window_sums(cum: np.ndarray, idx: np.ndarray, w: int) -> np.ndarray:
    """Sum over seconds [idx - w, idx - 1] given cum[k] = sum of values in seconds < k."""
    hi = idx  # exclusive end: seconds < idx
    lo = np.maximum(idx - w, 0)
    return cum[hi] - cum[lo]


def _distinct_in_window(sec_rel: np.ndarray, port: np.ndarray, n_sec: int, w: int) -> np.ndarray:
    """For each second s in [0, n_sec), the number of distinct ports seen in [s - w, s - 1].

    Each (port, second t) presence covers query seconds t+1 .. t+w. Intervals of the same port are
    merged so a port is counted once, then a difference array gives counts for every second."""
    pairs = np.unique(np.stack([port, sec_rel]), axis=1)  # sorted by port, then second
    p, t = pairs
    start, end = t + 1, t + w + 1  # half-open coverage [start, end)
    # Merge overlapping intervals within a port: a new run starts at a new port or a gap.
    # Within a port `end` increases with `t`, so end[i-1] is the current run's end.
    new_port = np.r_[True, p[1:] != p[:-1]]
    gap = np.r_[True, start[1:] > end[:-1]]
    run_start_mask = new_port | gap
    run_id = np.cumsum(run_start_mask) - 1
    run_starts = start[run_start_mask]
    run_ends = np.zeros(run_id[-1] + 1, dtype=np.int64)
    np.maximum.at(run_ends, run_id, end)
    diff = np.zeros(n_sec + w + 2, dtype=np.int64)
    np.add.at(diff, run_starts, 1)
    np.add.at(diff, run_ends, -1)
    return np.cumsum(diff)[:n_sec]


def compute_context(df: pl.DataFrame, windows: Sequence[int] = DEFAULT_WINDOWS) -> pl.DataFrame:
    """Return `row_id`, `event_sec` and causal context features for one capture day."""
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"compute_context: missing columns {missing}")
    windows = tuple(sorted({int(w) for w in windows}))
    if not windows or windows[0] < 1:
        raise ValueError("windows must be positive integers (seconds)")
    if df.height == 0:
        return pl.DataFrame(
            {"row_id": [], "event_sec": []}, schema={"row_id": pl.UInt32, "event_sec": pl.Int64}
        ).with_columns([pl.lit(None, pl.Float32).alias(n) for n in context_feature_names(windows)])

    base = df.select(
        "row_id",
        event_seconds(),
        pl.col("dst_port").cast(pl.Int64),
        (pl.col("tot_fwd_pkts") + pl.col("tot_bwd_pkts")).cast(pl.Float64).alias("pkts"),
        (pl.col("totlen_fwd_pkts") + pl.col("totlen_bwd_pkts")).cast(pl.Float64).alias("bytes"),
        (pl.col("syn_flag_cnt") > 0).cast(pl.Float64).alias("syn"),
        (pl.col("tot_bwd_pkts") == 0).cast(pl.Float64).alias("noreply"),
    )
    sec = base["event_sec"].to_numpy()
    s0 = int(sec.min())
    sec_rel = sec - s0
    n_sec = int(sec_rel.max()) + 1
    port = base["dst_port"].to_numpy()

    def per_second(values: np.ndarray | None) -> np.ndarray:
        """cum[k] = total over seconds < k (length n_sec + 1)."""
        counts = np.bincount(sec_rel, weights=values, minlength=n_sec)
        return np.r_[0.0, np.cumsum(counts)]

    cum_flows = per_second(None)
    cum_pkts = per_second(base["pkts"].to_numpy())
    cum_bytes = per_second(base["bytes"].to_numpy())
    cum_syn = per_second(base["syn"].to_numpy())
    cum_noreply = per_second(base["noreply"].to_numpy())

    # Per-(port, second) cumulative counts with a composite sorted key; a single global cumsum
    # works because the query range [p, s-w] .. [p, s-1] never spans another port's keys.
    key = port * (n_sec + 1) + sec_rel
    uniq_key, key_counts = np.unique(key, return_counts=True)
    cum_key = np.r_[0.0, np.cumsum(key_counts)]

    def port_window(w: int) -> np.ndarray:
        hi = port * (n_sec + 1) + sec_rel  # exclusive: seconds < s for the same port
        lo = port * (n_sec + 1) + np.maximum(sec_rel - w, 0)
        return (
            cum_key[np.searchsorted(uniq_key, hi, "left")]
            - cum_key[np.searchsorted(uniq_key, lo, "left")]
        )

    out: dict[str, np.ndarray] = {}
    for w in windows:
        flows = _window_sums(cum_flows, sec_rel, w)
        denom = np.maximum(flows, 1.0)
        port_flows = port_window(w)
        distinct = _distinct_in_window(sec_rel, port, n_sec, w)[sec_rel]
        out[f"ctx_flow_rate_{w}s"] = flows / w
        out[f"ctx_pkt_rate_{w}s"] = _window_sums(cum_pkts, sec_rel, w) / w
        out[f"ctx_byte_rate_{w}s"] = _window_sums(cum_bytes, sec_rel, w) / w
        out[f"ctx_syn_frac_{w}s"] = _window_sums(cum_syn, sec_rel, w) / denom
        out[f"ctx_noreply_frac_{w}s"] = _window_sums(cum_noreply, sec_rel, w) / denom
        out[f"ctx_uniq_ports_{w}s"] = distinct.astype(np.float64)
        out[f"ctx_port_flow_rate_{w}s"] = port_flows / w
        out[f"ctx_port_share_{w}s"] = port_flows / denom
    if len(windows) >= 2:
        lo, hi = windows[0], windows[-1]
        out[f"ctx_flow_surge_{lo}_{hi}"] = (out[f"ctx_flow_rate_{lo}s"] + 1.0) / (
            out[f"ctx_flow_rate_{hi}s"] + 1.0
        )
        out[f"ctx_port_surge_{lo}_{hi}"] = (out[f"ctx_port_flow_rate_{lo}s"] + 1.0) / (
            out[f"ctx_port_flow_rate_{hi}s"] + 1.0
        )
    return base.select("row_id", "event_sec").with_columns(
        [pl.Series(name, values, dtype=pl.Float32) for name, values in out.items()]
    )


def compute_context_chunked(
    lf: pl.LazyFrame,
    windows: Sequence[int] = DEFAULT_WINDOWS,
    chunk_seconds: int = 3600,
) -> pl.DataFrame:
    """Same result as `compute_context(lf.collect())` with bounded memory.

    Each chunk [a, b) is computed from flows in [a - max(windows), b); since no window looks
    further back than max(windows) seconds, the result is exact. Rows are processed per chunk,
    so peak memory scales with the busiest hour instead of the whole day."""
    lookback = max(windows)
    narrow = lf.select(*REQUIRED_COLUMNS).with_columns(event_seconds())
    lo, hi = (
        narrow.select(pl.col("event_sec").min().alias("lo"), pl.col("event_sec").max().alias("hi"))
        .collect()
        .row(0)
    )
    if lo is None:
        return compute_context(lf.select(*REQUIRED_COLUMNS).collect(), windows)
    parts = []
    for a in range(int(lo), int(hi) + 1, chunk_seconds):
        b = a + chunk_seconds
        chunk = narrow.filter(pl.col("event_sec").is_between(a - lookback, b, closed="left"))
        chunk = chunk.drop("event_sec").collect()
        if chunk.height == 0:
            continue
        ctx = compute_context(chunk, windows)
        parts.append(ctx.filter(pl.col("event_sec").is_between(a, b, closed="left")))
    return pl.concat(parts)
