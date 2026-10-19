"""Versioned feature definitions for NetFlow v3 (nProbe) datasets.

Never features: IPs, source port, timestamps, L7_PROTO (an nDPI DPI label - used only as a
target in the application experiment), DNS query ids/types/TTLs and FTP return codes
(application-layer fields a flow-only sensor would not have), ICMP_IPV4_TYPE (duplicate).
The raw destination port enters only as `port_class` (derived, like IDS2018).
TTL and TCP max-window fields are kept but flagged as shortcut suspects (they reflect the
attackers' OS / tooling, analogous to CICFlowMeter's init-window fields).
"""

from __future__ import annotations

from netsentinel.features.context import DEFAULT_WINDOWS, context_feature_names

NF_FEATURE_SCHEMA_VERSION = "nf-1.0.0"

NF_FLOW_COLUMNS: tuple[str, ...] = (
    "in_bytes", "in_pkts", "out_bytes", "out_pkts", "flow_duration_milliseconds", "duration_in",
    "duration_out", "min_ttl", "max_ttl", "longest_flow_pkt", "shortest_flow_pkt",
    "min_ip_pkt_len", "max_ip_pkt_len", "src_to_dst_second_bytes", "dst_to_src_second_bytes",
    "retransmitted_in_bytes", "retransmitted_in_pkts", "retransmitted_out_bytes",
    "retransmitted_out_pkts", "src_to_dst_avg_throughput", "dst_to_src_avg_throughput",
    "num_pkts_up_to_128_bytes", "num_pkts_128_to_256_bytes", "num_pkts_256_to_512_bytes",
    "num_pkts_512_to_1024_bytes", "num_pkts_1024_to_1514_bytes", "tcp_win_max_in",
    "tcp_win_max_out", "icmp_type", "src_to_dst_iat_min", "src_to_dst_iat_max",
    "src_to_dst_iat_avg", "src_to_dst_iat_stddev", "dst_to_src_iat_min", "dst_to_src_iat_max",
    "dst_to_src_iat_avg", "dst_to_src_iat_stddev",
    "cli_fin", "cli_syn", "cli_rst", "cli_psh", "cli_ack", "cli_urg",
    "srv_fin", "srv_syn", "srv_rst", "srv_psh", "srv_ack", "srv_urg",
)  # fmt: skip
NF_SHORTCUT_SUSPECTS: tuple[str, ...] = ("min_ttl", "max_ttl", "tcp_win_max_in", "tcp_win_max_out")
DERIVED: tuple[str, ...] = ("proto_tcp", "proto_udp", "proto_other", "port_class")

NF_FEATURE_SETS = ("nf_flow", "nf_flow_noshortcut", "nf_flow_ctx", "nf_flow_ctx_inv",
                   "nf_flow_noshortcut_ctx", "nf_portable", "nf_portable_ctx")  # fmt: skip
# Fields every supported source provides: NF-v3 CSVs, PCAP flows (telemetry.flows) and Zeek
# conn.log (telemetry.zeek). Models for the offline PCAP/Zeek application use these only.
NF_PORTABLE_COLUMNS: tuple[str, ...] = (
    "in_bytes", "in_pkts", "out_bytes", "out_pkts", "flow_duration_milliseconds",
    "cli_fin", "cli_syn", "cli_rst", "cli_psh", "cli_ack",
    "srv_fin", "srv_syn", "srv_rst", "srv_psh", "srv_ack",
)  # fmt: skip


def nf_flow_feature_columns() -> list[str]:
    return list(NF_FLOW_COLUMNS)


def nf_feature_set(name: str, windows: tuple[int, ...] = DEFAULT_WINDOWS) -> list[str]:
    flow = [*NF_FLOW_COLUMNS, *DERIVED]
    clean = [c for c in flow if c not in NF_SHORTCUT_SUSPECTS]
    ctx = context_feature_names(windows)
    inv = [c for c in ctx if any(m in c for m in ("_frac_", "_share_", "_surge_"))]
    sets = {
        "nf_flow": flow,
        "nf_flow_noshortcut": clean,
        "nf_flow_ctx": flow + ctx,
        "nf_flow_ctx_inv": flow + inv,
        "nf_flow_noshortcut_ctx": clean + ctx,
        "nf_portable": [*NF_PORTABLE_COLUMNS, *DERIVED],
        "nf_portable_ctx": [*NF_PORTABLE_COLUMNS, *DERIVED, *ctx],
    }
    if name not in sets:
        raise ValueError(f"unknown NF feature set {name!r}; choose from {NF_FEATURE_SETS}")
    return sets[name]
