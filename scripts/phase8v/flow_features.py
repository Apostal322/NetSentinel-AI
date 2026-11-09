"""Phase 8v enriched flow-window features (docs/phase8v/FEATURE_SCHEMA.md).

**Telemetry level:** B (completed NetFlow v3 / nProbe flow records). Nothing here is packet-level.

**Unit:** the existing (source host, 30 s) window, keyed by the flow END time. Every per-flow
field used is final when the flow record is exported, so a window's features are available when
the window closes (plus the exporter's delay, which these datasets do not record).

**Families** (18 features; no address, port number, TTL or TCP-window field is used, because
those identify topology or operating systems):

| family | feature | definition |
|---|---|---|
| FLOW | `tiny_flow_frac` | share of flows with ≤ 2 packets (both directions) |
| FLOW | `mean_log_pkts` | mean over flows of log(1 + packets) |
| FLOW | `sd_log_up` | population SD over flows of log(1 + forward bytes) (0 for one flow) |
| FLOW | `p90_log_dur` | 90th percentile over flows of log(1 + duration ms) |
| FLOW | `small_pkt_share` | packets ≤ 128 bytes / all size-binned packets (missing if none binned) |
| TIME | `active_sec_frac` | distinct seconds with a flow end / 30 |
| TIME | `peak_sec_share` | flows ending in the busiest second / flows |
| TIME | `gap_cv` | SD / mean of the gaps between consecutive flow ends (missing for < 3 flows) |
| TIME | `long_flow_frac` | share of flows lasting > 30 s (they began before the window) |
| TIME | `mean_log_fwd_iat` | mean over flows with ≥ 2 forward packets of log(1 + forward inter-arrival mean, ms); missing if none |
| TIME | `prev4_mean_log_flows` | mean `log_flows` of the host's previous 4 windows (silent = 0) |
| TIME | `d_log_flows` | `log_flows` minus the previous window's (silent = 0) |
| TIME | `active_prev4` | how many of the previous 4 windows the host was active in |
| BIDIR | `syn_only_frac` | share of flows that are TCP with a client SYN and no client ACK |
| BIDIR | `srv_rst_frac` | share of flows that are TCP with a server RST |
| BIDIR | `cli_fin_frac` | share of flows that are TCP with a client FIN |
| BIDIR | `mean_log_ratio` | mean over flows of log(1 + reverse bytes) − log(1 + forward bytes) |
| BIDIR | `retrans_frac` | share of flows with any retransmitted packet |

"Forward" is the exporter's IN direction (source → destination), "reverse" its OUT direction.
The source is the flow's first-packet sender as nProbe recorded it; no label is used to orient a
flow. **Missing stays missing (NaN):** LightGBM treats it natively; it is never replaced by 0.
"""

from __future__ import annotations

import polars as pl

W_MS = 30_000
FAMILIES = {
    "FLOW": ("tiny_flow_frac", "mean_log_pkts", "sd_log_up", "p90_log_dur", "small_pkt_share"),
    "TIME": ("active_sec_frac", "peak_sec_share", "gap_cv", "long_flow_frac", "mean_log_fwd_iat",
             "prev4_mean_log_flows", "d_log_flows", "active_prev4"),
    "BIDIR": ("syn_only_frac", "srv_rst_frac", "cli_fin_frac", "mean_log_ratio", "retrans_frac"),
}  # fmt: skip
CONTEXT = ("prev4_mean_log_flows", "d_log_flows", "active_prev4")
ALL = tuple(f for fam in FAMILIES.values() for f in fam)
BINS = ("num_pkts_up_to_128_bytes", "num_pkts_128_to_256_bytes", "num_pkts_256_to_512_bytes",
        "num_pkts_512_to_1024_bytes", "num_pkts_1024_to_1514_bytes")  # fmt: skip
RAW_COLUMNS = ("flow_end_milliseconds", "ipv4_src_addr", "protocol", "in_bytes", "out_bytes", "in_pkts",
               "out_pkts", "client_tcp_flags", "server_tcp_flags", "flow_duration_milliseconds",
               "retransmitted_in_pkts", "retransmitted_out_pkts", "src_to_dst_iat_avg", *BINS)  # fmt: skip
SCHEMA_VERSION = "flowwin-1.0.0"


def window_features(flows: pl.DataFrame) -> pl.DataFrame:
    """Per (key, win) features of the within-window families from complete windows of flows.
    Returns key, win, n_flows_v and every non-context feature."""
    missing = [c for c in RAW_COLUMNS if c not in flows.columns]
    if missing:
        raise ValueError(f"flow frame lacks {missing}")
    end = pl.col("flow_end_milliseconds").cast(pl.Int64)
    if flows["flow_end_milliseconds"].null_count():
        raise ValueError("flow end time missing")
    pk = pl.col("in_pkts").fill_null(0) + pl.col("out_pkts").fill_null(0)
    cli, srv = pl.col("client_tcp_flags").fill_null(0), pl.col("server_tcp_flags").fill_null(0)
    tcp = pl.col("protocol") == 6
    dur = pl.col("flow_duration_milliseconds").cast(pl.Float64).fill_null(0)
    bins = sum(pl.col(b).cast(pl.Float64).fill_null(0) for b in BINS)
    retr = pl.col("retransmitted_in_pkts").fill_null(0) + pl.col(
        "retransmitted_out_pkts"
    ).fill_null(0)
    f = flows.select(
        pl.col("ipv4_src_addr").cast(pl.Utf8).alias("key"),
        (end // W_MS).alias("win"),
        end.alias("end_ms"),
        (end // 1000).alias("sec"),
        (pk <= 2).cast(pl.Float64).alias("tiny"),
        (pk.cast(pl.Float64) + 1).log().alias("lp"),
        (pl.col("in_bytes").cast(pl.Float64).fill_null(0) + 1).log().alias("lup"),
        (dur + 1).log().alias("ldur"),
        pl.col(BINS[0]).cast(pl.Float64).fill_null(0).alias("small"),
        bins.alias("binned"),
        (dur > W_MS).cast(pl.Float64).alias("long"),
        (tcp & ((cli & 2) > 0) & ((cli & 16) == 0)).cast(pl.Float64).alias("syn_only"),
        (tcp & ((srv & 4) > 0)).cast(pl.Float64).alias("srv_rst"),
        (tcp & ((cli & 1) > 0)).cast(pl.Float64).alias("cli_fin"),
        ((pl.col("out_bytes").cast(pl.Float64).fill_null(0) + 1).log()
         - (pl.col("in_bytes").cast(pl.Float64).fill_null(0) + 1).log()).alias("lratio"),
        (retr > 0).cast(pl.Float64).alias("retrans"),
        pl.when(pl.col("in_pkts").fill_null(0) >= 2)
        .then((pl.col("src_to_dst_iat_avg").cast(pl.Float64) + 1).log())
        .otherwise(None).alias("lfiat"),
    )  # fmt: skip
    gaps = pl.col("end_ms").sort().diff().drop_nulls().cast(pl.Float64)
    g = f.group_by("key", "win").agg(
        pl.len().alias("n_flows_v"),
        pl.col("tiny").mean().alias("tiny_flow_frac"),
        pl.col("lp").mean().alias("mean_log_pkts"),
        pl.col("lup").std(ddof=0).fill_null(0.0).alias("sd_log_up"),
        pl.col("ldur").quantile(0.9, interpolation="nearest").alias("p90_log_dur"),
        pl.when(pl.col("binned").sum() > 0).then(pl.col("small").sum() / pl.col("binned").sum())
        .otherwise(None).alias("small_pkt_share"),
        (pl.col("sec").n_unique() / 30.0).alias("active_sec_frac"),
        pl.when(pl.len() >= 3).then(gaps.std(ddof=0) / gaps.mean()).otherwise(None).alias("gap_cv"),
        pl.col("long").mean().alias("long_flow_frac"),
        pl.col("lfiat").mean().alias("mean_log_fwd_iat"),
        pl.col("syn_only").mean().alias("syn_only_frac"),
        pl.col("srv_rst").mean().alias("srv_rst_frac"),
        pl.col("cli_fin").mean().alias("cli_fin_frac"),
        pl.col("lratio").mean().alias("mean_log_ratio"),
        pl.col("retrans").mean().alias("retrans_frac"),
    )  # fmt: skip
    peak = (
        f.group_by("key", "win", "sec")
        .len()
        .group_by("key", "win")
        .agg(pl.col("len").max().alias("peak"))
    )
    g = g.join(peak, on=["key", "win"], how="left").with_columns(
        (pl.col("peak") / pl.col("n_flows_v")).alias("peak_sec_share"),
        # all gaps zero (simultaneous ends) gives 0/0: the gaps do not vary, so the CV is 0
        pl.col("gap_cv").fill_nan(0.0),
    ).drop("peak")  # fmt: skip
    return g


def context_features(windows: pl.DataFrame) -> pl.DataFrame:
    """The three causal context features from a domain's complete (key, win, n_flows_v) table.
    Only strictly earlier windows of the same host are used; a silent window counts as 0."""
    base = windows.select(
        "key", "win", ((pl.col("n_flows_v").cast(pl.Float64) + 1).log()).alias("lf")
    )
    out = base
    for k in (1, 2, 3, 4):
        lag = base.select("key", (pl.col("win") + k).alias("win"), pl.col("lf").alias(f"lf{k}"))
        out = out.join(lag, on=["key", "win"], how="left")
    lags = [pl.col(f"lf{k}") for k in (1, 2, 3, 4)]
    return out.select(
        "key", "win",
        (sum(c.fill_null(0.0) for c in lags) / 4.0).alias("prev4_mean_log_flows"),
        (pl.col("lf") - pl.col("lf1").fill_null(0.0)).alias("d_log_flows"),
        sum(c.is_not_null().cast(pl.Float64) for c in lags).alias("active_prev4"),
    )  # fmt: skip
