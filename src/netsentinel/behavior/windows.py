"""Causal window aggregation of flow records into entity-window behaviour features.

Time semantics: a flow exists as a record only when it ends, so it is assigned to the tumbling
window that contains its END time (`flow_end_milliseconds`). A window's features are available
when the window closes; no window uses information from a later window. The detection delay of
a window-level alert is therefore (window length) + (time the triggering flows took to end).

Entities (levels):
* global   - all flows of the capture; windows without any flow are kept (n_flows = 0), so
             silence is observable.
* device   - flows ORIGINATED by a host (`ipv4_src_addr`): only windows in which the host was
             active are emitted (activity-conditioned profile).
* service  - flows of one service category (port heuristic or ML application class).

Features need only fields that BOTH Zeek conn logs and PCAP flows provide (counts, bytes,
packets, duration, TCP flags, endpoints, ports). Byte direction: `in_*` = originator->responder
(upload from the originating device), `out_*` = responder->originator.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from netsentinel.models.service import service_category_expr

WINDOW_FEATURES: tuple[str, ...] = (
    "log_flows", "log_up_bytes", "log_down_bytes", "log_pkts", "log_dst_hosts",
    "log_dst_ports", "no_reply_frac", "rst_frac", "udp_share", "med_log_dur", "upload_share",
    "new_dst_frac",
)  # fmt: skip
# Human-readable explanation stems per feature (direction appended at scoring time).
EXPLAIN = {
    "log_flows": "connection_rate", "log_up_bytes": "upload_volume",
    "log_down_bytes": "download_volume", "log_pkts": "packet_rate",
    "log_dst_hosts": "destination_diversity", "log_dst_ports": "destination_port_diversity",
    "no_reply_frac": "unanswered_connection_share", "rst_frac": "reset_connection_share",
    "udp_share": "udp_share", "med_log_dur": "typical_connection_duration",
    "upload_share": "upload_download_balance", "new_dst_frac": "previously_unseen_destinations",
}  # fmt: skip
LEVELS = ("global", "device", "service")
REQUIRED = ("ipv4_src_addr", "ipv4_dst_addr", "dst_port", "protocol", "in_bytes", "out_bytes",
            "in_pkts", "out_pkts", "flow_duration_milliseconds")  # fmt: skip


def prepare_flows(df: pl.DataFrame, service_col: str | None = None) -> pl.DataFrame:
    """Canonical flow frame -> minimal columns with event time and helper flags."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"flow frame lacks required columns {missing}")
    if "flow_end_milliseconds" in df.columns:
        end = pl.col("flow_end_milliseconds").cast(pl.Int64)
    elif "flow_start_milliseconds" in df.columns:
        end = pl.col("flow_start_milliseconds").cast(pl.Int64) + pl.col(
            "flow_duration_milliseconds"
        ).cast(pl.Int64)
    else:
        raise ValueError("flow frame needs flow_end_milliseconds or flow_start_milliseconds")
    rst = pl.lit(False)
    for c in ("cli_rst", "srv_rst"):
        if c in df.columns:
            rst = rst | (pl.col(c).fill_null(0) > 0)
    svc = pl.col(service_col) if service_col else service_category_expr()
    out = df.with_columns(svc.alias("service"))
    return out.select(
        end.alias("end_ms"),
        pl.col("ipv4_src_addr").cast(pl.Utf8).alias("src"),
        pl.col("ipv4_dst_addr").cast(pl.Utf8).alias("dst"),
        pl.col("dst_port").cast(pl.Int64),
        pl.col("protocol").cast(pl.Int64),
        pl.col("service").cast(pl.Utf8),
        pl.col("in_bytes").cast(pl.Float64).fill_null(0).alias("up"),
        pl.col("out_bytes").cast(pl.Float64).fill_null(0).alias("down"),
        (
            pl.col("in_pkts").cast(pl.Float64).fill_null(0)
            + pl.col("out_pkts").cast(pl.Float64).fill_null(0)
        ).alias("pkts"),  # fmt: skip
        (pl.col("out_pkts").fill_null(0) == 0).cast(pl.Float64).alias("no_reply"),
        ((pl.col("protocol") == 6) & rst).cast(pl.Float64).alias("rst"),
        (pl.col("protocol") == 17).cast(pl.Float64).alias("udp"),
        pl.col("flow_duration_milliseconds").cast(pl.Float64).fill_null(0).alias("dur_ms"),
    ).sort("end_ms")


def _key_expr(level: str) -> pl.Expr:
    if level == "global":
        return pl.lit("*").alias("key")
    if level == "device":
        return pl.col("src").alias("key")
    if level == "service":
        return pl.col("service").alias("key")
    raise ValueError(f"unknown level {level!r}")


def aggregate(flows: pl.DataFrame, level: str, window_s: int,
              known_dst: set[str] | None = None) -> pl.DataFrame:  # fmt: skip
    """Entity-window features. `known_dst`: destinations considered already seen (frozen
    calibration set at scoring time); if None, the set expands causally over the stream
    (a destination is 'new' in a window if it never appeared in an EARLIER window)."""
    w_ms = window_s * 1000
    f = flows.with_columns((pl.col("end_ms") // w_ms).alias("win"), _key_expr(level))
    if known_dst is None:
        first = f.group_by("dst").agg(pl.col("win").min().alias("first_win"))
        f = f.join(first, on="dst").with_columns(
            (pl.col("win") == pl.col("first_win")).cast(pl.Float64).alias("is_new")
        )
    else:
        f = f.with_columns((~pl.col("dst").is_in(list(known_dst))).cast(pl.Float64).alias("is_new"))
    g = f.group_by("key", "win").agg(
        pl.len().alias("n_flows"),
        pl.col("up").sum(), pl.col("down").sum(), pl.col("pkts").sum(),
        pl.col("dst").n_unique().alias("dst_hosts"),
        pl.col("dst_port").n_unique().alias("dst_ports"),
        pl.col("no_reply").mean().alias("no_reply_frac"),
        pl.col("rst").mean().alias("rst_frac"),
        pl.col("udp").mean().alias("udp_share"),
        (pl.col("dur_ms") + 1).log().median().alias("med_log_dur"),
        # share of DISTINCT destinations in this window that are new
        (pl.col("dst").filter(pl.col("is_new") > 0).n_unique()
         / pl.col("dst").n_unique()).alias("new_dst_frac"),
    )  # fmt: skip
    if level == "global" and g.height:
        lo, hi = int(g["win"].min()), int(g["win"].max())
        full = pl.DataFrame({"win": np.arange(lo, hi + 1, dtype=np.int64)}).with_columns(
            pl.lit("*").alias("key")
        )
        # Silent windows: flow count 0; every other feature is undefined (null -> ignored by
        # the profile) rather than 0, which would make the distributions bimodal.
        g = full.join(g, on=["key", "win"], how="left").with_columns(pl.col("n_flows").fill_null(0))
    return g.with_columns(
        pl.lit(level).alias("level"),
        (pl.col("win") * w_ms).alias("window_start_ms"),
        ((pl.col("win") + 1) * w_ms).alias("window_end_ms"),
        (pl.col("n_flows").cast(pl.Float64) + 1).log().alias("log_flows"),
        (pl.col("up") + 1).log().alias("log_up_bytes"),
        (pl.col("down") + 1).log().alias("log_down_bytes"),
        (pl.col("pkts") + 1).log().alias("log_pkts"),
        (pl.col("dst_hosts").cast(pl.Float64) + 1).log().alias("log_dst_hosts"),
        (pl.col("dst_ports").cast(pl.Float64) + 1).log().alias("log_dst_ports"),
        (pl.col("up") / (pl.col("up") + pl.col("down") + 1)).alias("upload_share"),
    ).sort("win", "key")


def window_labels(flows_with_label: pl.DataFrame, level: str, window_s: int) -> pl.DataFrame:
    """(key, win) -> attack indicator (any flow in the entity-window is labelled malicious).
    `flows_with_label` = prepare_flows output plus a boolean `is_attack` column."""
    w_ms = window_s * 1000
    return (
        flows_with_label.with_columns((pl.col("end_ms") // w_ms).alias("win"), _key_expr(level))
        .group_by("key", "win")
        .agg(
            pl.col("is_attack").max().alias("is_attack"),
            pl.col("is_attack").sum().alias("attack_flows"),
        )  # fmt: skip
    )
