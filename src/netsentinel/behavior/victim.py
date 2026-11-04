"""Victim-side (destination-keyed) window features and source-window context (Phase 8p research
module; not used by the monitor).

Input: `windows.prepare_flows` output, optionally with `is_attack` (evaluation only, never a
feature). The time semantics are those of `windows.aggregate`: a flow belongs to the 30 s window
of its END time, and windows are closed in time order.

**Victim window (VW)** = all flows whose responder is one host (`dst`) in one window. The host
is the *observed responder*, not a ground-truth victim: servers, resolvers, gateways and NAT
addresses are responders too.

Features (ln = natural log):

- `v_log_flows`, `v_log_srcs`, `v_log_ports`: ln(1 + inbound flows / distinct originators /
  distinct service ports).
- `v_log_up`, `v_log_down`, `v_log_pkts`: ln(1 + originator->responder bytes /
  responder->originator bytes / packets).
- `v_no_reply_frac`, `v_rst_frac`, `v_udp_share`, `v_short_frac`: shares of flows with no reply
  packets / a TCP reset / UDP / a duration under 1 s.
- `v_med_log_dur`: median ln(1 + duration ms).
- `v_resp_share`: down / (up + down + 1).
- `v_top_src_share`: largest share of the window's flows from one originator (concentration).
- `v_web_share`: share of flows to web ports (`models.service.SERVICE_PORTS["web"]`).
- `v_hist_dev`: `v_log_flows` minus the host's mean `v_log_flows` over its EARLIER windows
  (0 if none).
- `v_hist_n`: ln(1 + number of earlier windows of the host).

**History semantics.** The history is causal and expanding everywhere: it is updated after each
window and never frozen, so calibration and evaluation windows use one semantics (the Phase 8o
lesson). Its state per host is (sum of `v_log_flows`, window count). It absorbs persistent
traffic, attacks included; that contamination is measured in Phase 8p, not assumed away.

**Source-window context (SX)**, keyed by (src, win):

- `c_v_log_flows_max`, `c_v_log_srcs_max`, `c_v_hist_dev_max`, `c_v_no_reply_max`,
  `c_v_resp_share_min`: over the distinct responders the source contacted in the window, the
  extreme of their VW features (fan-in context: "the hosts I talk to are under load").
- `s_web_share`, `s_dns_share`, `s_wellknown_share`: service context, the share of the source's
  flows to web ports / DNS ports / any port < 1024.
- `s_log_services`: ln(1 + distinct port-derived service categories, `models.service`).

A port is the service a flow *claims*, not its application (port 443 carries everything).

**Missing fields.** Responder bytes and packets that are null arrive as 0 (`prepare_flows`), so
`v_resp_share` is 0 and `v_no_reply_frac` is 1. Callers must mark such telemetry degraded;
nothing is imputed here.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from netsentinel.models.service import SERVICE_PORTS

VICTIM_FEATURES: tuple[str, ...] = (
    "v_log_flows", "v_log_srcs", "v_log_ports", "v_log_up", "v_log_down", "v_log_pkts",
    "v_no_reply_frac", "v_rst_frac", "v_udp_share", "v_short_frac", "v_med_log_dur",
    "v_resp_share", "v_top_src_share", "v_web_share", "v_hist_dev", "v_hist_n",
)  # fmt: skip
CONTEXT_FEATURES: tuple[str, ...] = (
    "c_v_log_flows_max", "c_v_log_srcs_max", "c_v_hist_dev_max", "c_v_no_reply_max",
    "c_v_resp_share_min",
)  # fmt: skip
SERVICE_FEATURES: tuple[str, ...] = (
    "s_web_share",
    "s_dns_share",
    "s_wellknown_share",
    "s_log_services",
)
SCHEMA_VERSION = "victim-1.0.0"
WEB_PORTS = list(SERVICE_PORTS["web"])
DNS_PORTS = list(SERVICE_PORTS["dns"])


class History:
    """Per-host running (sum of v_log_flows, window count) over earlier windows."""

    def __init__(self) -> None:
        self.sum: dict[str, float] = {}
        self.n: dict[str, int] = {}
        self.last_win: int | None = None

    def frame(self) -> pl.DataFrame:
        return pl.DataFrame({"dst": list(self.sum), "h_sum": list(self.sum.values()),
                             "h_n": [self.n[k] for k in self.sum]},
                            schema={"dst": pl.Utf8, "h_sum": pl.Float64,
                                    "h_n": pl.Int64})  # fmt: skip


def victim_windows(
    flows: pl.DataFrame, window_s: int = 30, history: History | None = None
) -> pl.DataFrame:
    """VW rows of `flows` (whole windows, later than any window `history` has seen). With a
    `history`, `v_hist_*` use it plus this call's earlier windows, and the history is updated."""
    w_ms = window_s * 1000
    f = flows.with_columns((pl.col("end_ms") // w_ms).alias("win"))
    if f.height == 0:
        return pl.DataFrame()
    if (
        history is not None
        and history.last_win is not None
        and int(f["win"].min()) <= history.last_win
    ):
        raise ValueError("victim_windows: windows must arrive in time order")
    top = (f.group_by("dst", "win", "src").len()
           .group_by("dst", "win").agg(pl.col("len").max().alias("top_src_flows")))  # fmt: skip
    lab = []
    if "is_attack" in f.columns:
        a = pl.col("is_attack") > 0
        lab = [
            a.sum().alias("attack_flows"),
            pl.col("src").filter(a).n_unique().alias("attack_srcs"),
        ]
    g = f.group_by("dst", "win").agg(
        pl.len().alias("flows"), pl.col("src").n_unique().alias("srcs"),
        pl.col("dst_port").n_unique().alias("ports"), pl.col("up").sum(), pl.col("down").sum(),
        pl.col("pkts").sum(), pl.col("no_reply").mean().alias("v_no_reply_frac"),
        pl.col("rst").mean().alias("v_rst_frac"), pl.col("udp").mean().alias("v_udp_share"),
        (pl.col("dur_ms") < 1000).mean().alias("v_short_frac"),
        (pl.col("dur_ms") + 1).log().median().alias("v_med_log_dur"),
        pl.col("dst_port").is_in(WEB_PORTS).mean().alias("v_web_share"), *lab,
    ).join(top, on=["dst", "win"])  # fmt: skip
    g = g.with_columns(
        (pl.col("flows").cast(pl.Float64) + 1).log().alias("v_log_flows"),
        (pl.col("srcs").cast(pl.Float64) + 1).log().alias("v_log_srcs"),
        (pl.col("ports").cast(pl.Float64) + 1).log().alias("v_log_ports"),
        (pl.col("up") + 1).log().alias("v_log_up"), (pl.col("down") + 1).log().alias("v_log_down"),
        (pl.col("pkts") + 1).log().alias("v_log_pkts"),
        (pl.col("down") / (pl.col("up") + pl.col("down") + 1)).alias("v_resp_share"),
        (pl.col("top_src_flows") / pl.col("flows")).alias("v_top_src_share"),
    ).sort("dst", "win")  # fmt: skip
    # history: mean of the host's v_log_flows over strictly earlier windows (prior calls + this one)
    prior = history.frame() if history is not None else pl.DataFrame(
        schema={"dst": pl.Utf8, "h_sum": pl.Float64, "h_n": pl.Int64})  # fmt: skip
    # the cumulative history below needs the (dst, win) order kept through the join
    g = g.join(prior, on="dst", how="left", maintain_order="left").with_columns(
        pl.col("h_sum").fill_null(0.0), pl.col("h_n").fill_null(0)
    )
    g = g.with_columns(
        (pl.col("h_sum") + pl.col("v_log_flows").cum_sum().over("dst")
         - pl.col("v_log_flows")).alias("_s"),
        (pl.col("h_n") + pl.int_range(pl.len()).over("dst")).alias("_n"),
    )  # fmt: skip
    g = g.with_columns(
        pl.when(pl.col("_n") > 0).then(pl.col("v_log_flows") - pl.col("_s") / pl.col("_n"))
        .otherwise(0.0).alias("v_hist_dev"),
        (pl.col("_n").cast(pl.Float64) + 1).log().alias("v_hist_n"),
    )  # fmt: skip
    if history is not None:
        last = g.group_by("dst").agg(
            (pl.col("_s") + pl.col("v_log_flows")).sort_by("win").last().alias("s"),
            (pl.col("_n") + 1).sort_by("win").last().alias("n"))  # fmt: skip
        for d, s, n in last.iter_rows():
            history.sum[d], history.n[d] = float(s), int(n)
        history.last_win = int(g["win"].max())
    keep = ["dst", "win", *VICTIM_FEATURES, "flows", "srcs"] + (
        ["attack_flows", "attack_srcs"] if lab else []
    )
    return g.select(keep).sort("win", "dst")


def source_context(flows: pl.DataFrame, vw: pl.DataFrame, window_s: int = 30) -> pl.DataFrame:
    """SX rows keyed (key = src, win): fan-in context of the responders a source contacted in a
    window (from `vw` of the same flows) and the source's service mix."""
    w_ms = window_s * 1000
    f = flows.with_columns((pl.col("end_ms") // w_ms).alias("win"))
    contacts = f.select("src", "dst", "win").unique().join(
        vw.select("dst", "win", "v_log_flows", "v_log_srcs", "v_hist_dev", "v_no_reply_frac",
                  "v_resp_share"),
        on=["dst", "win"], how="left")  # fmt: skip
    c = contacts.group_by("src", "win").agg(
        pl.col("v_log_flows").max().alias("c_v_log_flows_max"),
        pl.col("v_log_srcs").max().alias("c_v_log_srcs_max"),
        pl.col("v_hist_dev").max().alias("c_v_hist_dev_max"),
        pl.col("v_no_reply_frac").max().alias("c_v_no_reply_max"),
        pl.col("v_resp_share").min().alias("c_v_resp_share_min"),
    )  # fmt: skip
    s = f.group_by("src", "win").agg(
        pl.col("dst_port").is_in(WEB_PORTS).mean().alias("s_web_share"),
        pl.col("dst_port").is_in(DNS_PORTS).mean().alias("s_dns_share"),
        (pl.col("dst_port") < 1024).mean().alias("s_wellknown_share"),
        (pl.col("service").n_unique().cast(pl.Float64) + 1).log().alias("s_log_services"),
    )  # fmt: skip
    return c.join(s, on=["src", "win"]).rename({"src": "key"}).sort("win", "key")


def as_array(frame: pl.DataFrame, names: tuple[str, ...]) -> np.ndarray:
    return np.nan_to_num(frame.select([pl.col(n).cast(pl.Float64) for n in names]).to_numpy())
