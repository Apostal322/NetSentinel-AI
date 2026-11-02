"""Phase 8k telemetry mappings: fresh-family flow records -> the canonical flow frame of
`netsentinel.behavior.windows.prepare_flows` (docs/phase8k/PREREGISTRATION.md section 8).

Canonical columns: flow_start_milliseconds, flow_end_milliseconds, ipv4_src_addr (originator),
ipv4_dst_addr, dst_port, protocol (6 / 17 / 1), in_bytes / in_pkts (originator -> responder),
out_bytes / out_pkts (responder -> originator), flow_duration_milliseconds, cli_rst / srv_rst
(a reset sent by that side), label (the source's own label text) and is_attack.

F1, AIT Netflow v2 (Tstat `tcp_complete`, `tcp_nocomplete`, `udp_complete`, labelled by the AIT
notebooks): client = originator. Tstat counts PAYLOAD bytes; nProbe NetFlow v3 (development)
counts IP bytes, so the mapping adds the minimal header per packet (TCP/IPv4 40 B, UDP/IPv4
28 B). Labels: the published `label_info.txt` lists; a label in neither list counts as an attack
(conservative for the calibration-period exclusion) and is reported.

F2, UWF-ZeekData24 (Zeek `conn` in parquet): orig = originator; IP-level byte counts
(`orig_ip_bytes` / `resp_ip_bytes`) match nProbe's; resets from `history` ('R' originator,
'r' responder); is_attack from `label_binary`.
"""

from __future__ import annotations

import re
from pathlib import Path

import polars as pl

AIT_BENIGN = {
    "browsing/update", "benign_share", "broken flow - benign", "mail", "monitoring",
    "HTTP(S) intra", "HTTP(S) DMZ", "HTTP", "HTTPS", "DNS", "SSH", "proxy",
    "update/command on unassigned port", "mDNSv6", "mDNS", "bootp", "NTP",
    "systemd-resolver (local)", "benign DNS - attacker requesting updates", "benign DNS",
    "OpenVPN", "QUIC", "STUN VoIP", "NetBIOS", "GoogleDNS",
}  # fmt: skip
AIT_MALICIOUS = {
    "service_scan", "online_cracking", "host_discover_dmz", "host_discover_local", "wpscan",
    "dirb_scan", "upload_rce_shell", "check_user_id", "check_netstat_t", "read_resolv",
    "check_network_config", "check_ps_a", "check_release", "read_group", "read_passwd",
    "check_date", "list_web_dir", "check_wp_config", "dump_wp_users", "read_profile",
    "dns_brute_force_start", "list_www", "check_who", "clear", "check_last", "check_id",
    "vpn_connect", "check_whoami", "check_uname_r", "check_meminfo", "check_uname_a", "check_df",
    "check_netstat_nat", "list_home", "check_netstat_l", "check_cpuinfo", "check_uptime",
    "check_pwd", "list_l", "data exfiltration",
}  # fmt: skip
CANON = ("flow_start_milliseconds", "flow_end_milliseconds", "ipv4_src_addr", "ipv4_dst_addr",
         "dst_port", "protocol", "in_bytes", "out_bytes", "in_pkts", "out_pkts",
         "flow_duration_milliseconds", "cli_rst", "srv_rst", "label", "is_attack")  # fmt: skip


def tstat_columns(path: Path) -> list[str]:
    """Tstat header names without the '#15#' / '#' prefix and the ':N' position suffix."""
    with open(path, encoding="utf-8") as f:
        head = f.readline().strip()
    return [re.sub(r":\d+$", "", c) for c in re.sub(r"^#(\d+#)?", "", head).split(",")]


def ait_is_attack(label: pl.Expr) -> pl.Expr:
    return ~label.is_in(sorted(AIT_BENIGN))


def tstat_tcp(df: pl.DataFrame) -> pl.DataFrame:
    """Tstat tcp_complete / tcp_nocomplete rows (cleaned names) -> canonical frame."""
    num = lambda c: pl.col(c).cast(pl.Float64)  # noqa: E731
    return df.select(
        num("first").cast(pl.Int64).alias("flow_start_milliseconds"),
        num("last").cast(pl.Int64).alias("flow_end_milliseconds"),
        pl.col("c_ip").cast(pl.Utf8).alias("ipv4_src_addr"),
        pl.col("s_ip").cast(pl.Utf8).alias("ipv4_dst_addr"),
        pl.col("s_port").cast(pl.Int64).alias("dst_port"),
        pl.lit(6, pl.Int64).alias("protocol"),
        (num("c_bytes_all") + 40 * num("c_pkts_all")).alias("in_bytes"),
        (num("s_bytes_all") + 40 * num("s_pkts_all")).alias("out_bytes"),
        num("c_pkts_all").alias("in_pkts"),
        num("s_pkts_all").alias("out_pkts"),
        num("durat").alias("flow_duration_milliseconds"),
        (num("c_rst_cnt") > 0).cast(pl.Int8).alias("cli_rst"),
        (num("s_rst_cnt") > 0).cast(pl.Int8).alias("srv_rst"),
        pl.col("label").cast(pl.Utf8),
        ait_is_attack(pl.col("label").cast(pl.Utf8)).cast(pl.Float64).alias("is_attack"),
    )


def tstat_udp(df: pl.DataFrame) -> pl.DataFrame:
    """Tstat udp_complete rows -> canonical frame. A side that sent nothing has first = 0."""
    num = lambda c: pl.col(c).cast(pl.Float64)  # noqa: E731
    c_end = num("c_first_abs") + num("c_durat")
    s_has = num("s_pkts_all") > 0
    s_end = pl.when(s_has).then(num("s_first_abs") + num("s_durat")).otherwise(c_end)
    end = pl.max_horizontal(c_end, s_end)
    return df.select(
        num("c_first_abs").cast(pl.Int64).alias("flow_start_milliseconds"),
        end.cast(pl.Int64).alias("flow_end_milliseconds"),
        pl.col("c_ip").cast(pl.Utf8).alias("ipv4_src_addr"),
        pl.col("s_ip").cast(pl.Utf8).alias("ipv4_dst_addr"),
        pl.col("s_port").cast(pl.Int64).alias("dst_port"),
        pl.lit(17, pl.Int64).alias("protocol"),
        (num("c_bytes_all") + 28 * num("c_pkts_all")).alias("in_bytes"),
        (num("s_bytes_all") + 28 * num("s_pkts_all")).alias("out_bytes"),
        num("c_pkts_all").alias("in_pkts"),
        num("s_pkts_all").alias("out_pkts"),
        (end - num("c_first_abs")).alias("flow_duration_milliseconds"),
        pl.lit(0, pl.Int8).alias("cli_rst"),
        pl.lit(0, pl.Int8).alias("srv_rst"),
        pl.col("label").cast(pl.Utf8),
        ait_is_attack(pl.col("label").cast(pl.Utf8)).cast(pl.Float64).alias("is_attack"),
    )


def read_ait(folder: Path) -> pl.DataFrame:
    """All three Tstat files of one AIT network -> one canonical frame sorted by flow end."""
    parts = []
    for name, fn in (
        ("tcp_complete", tstat_tcp),
        ("tcp_nocomplete", tstat_tcp),
        ("udp_complete", tstat_udp),
    ):
        p = folder / f"{name}.csv"
        if p.exists():
            cols = tstat_columns(p)
            df = pl.read_csv(
                p, has_header=False, skip_rows=1, new_columns=cols, infer_schema_length=0
            )
            parts.append(fn(df))
    return pl.concat(parts).sort("flow_end_milliseconds")


def zeek_conn(df: pl.DataFrame) -> pl.DataFrame:
    """UWF-ZeekData24 conn rows -> canonical frame."""
    proto = pl.col("proto").str.to_lowercase()
    dur_ms = pl.col("duration").fill_null(0.0) * 1000
    start = pl.col("ts") * 1000
    hist = pl.col("history").fill_null("")
    return df.select(
        start.cast(pl.Int64).alias("flow_start_milliseconds"),
        (start + dur_ms).cast(pl.Int64).alias("flow_end_milliseconds"),
        pl.col("src_ip_zeek").cast(pl.Utf8).alias("ipv4_src_addr"),
        pl.col("dest_ip_zeek").cast(pl.Utf8).alias("ipv4_dst_addr"),
        pl.col("dest_port_zeek").cast(pl.Int64).alias("dst_port"),
        pl.when(proto == "tcp").then(6).when(proto == "udp").then(17).when(proto == "icmp").then(1)
        .otherwise(0).cast(pl.Int64).alias("protocol"),
        pl.col("orig_ip_bytes").cast(pl.Float64).alias("in_bytes"),
        pl.col("resp_ip_bytes").cast(pl.Float64).alias("out_bytes"),
        pl.col("orig_pkts").cast(pl.Float64).alias("in_pkts"),
        pl.col("resp_pkts").cast(pl.Float64).alias("out_pkts"),
        dur_ms.alias("flow_duration_milliseconds"),
        hist.str.contains("R", literal=True).cast(pl.Int8).alias("cli_rst"),
        hist.str.contains("r", literal=True).cast(pl.Int8).alias("srv_rst"),
        pl.col("label_binary").cast(pl.Utf8).alias("label"),
        (pl.col("label_binary").cast(pl.Utf8).str.to_lowercase().is_in(["true", "1", "malicious"]))
        .cast(pl.Float64).alias("is_attack"),
    ).sort("flow_end_milliseconds")  # fmt: skip
