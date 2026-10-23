"""ToN_IoT network-dataset adapter (Zeek-derived CSV) -> NetSentinel flow records.

ToN_IoT (UNSW Canberra, Moustafa et al.) distributes its network data as CSV files generated
by Zeek with columns including: ts, src_ip, src_port, dst_ip, dst_port, proto, service,
duration, src_bytes, dst_bytes, conn_state, missed_bytes, src_pkts, src_ip_bytes, dst_pkts,
dst_ip_bytes, ..., label, type. This maps them onto the same NF-v3-style record the Zeek reader
produces (telemetry/zeek.py), so the Phase 8b harness applies unchanged:
* ts -> FLOW_START (s -> ms); duration -> FLOW_DURATION / FLOW_END;
* src_ip_bytes / dst_ip_bytes -> IN_BYTES / OUT_BYTES (IP-level, as for conn.log);
* src_pkts / dst_pkts -> IN_PKTS / OUT_PKTS;
* no `history` column: resets come from conn_state (Zeek semantics) - RSTO, RSTOS0 =
  originator reset; REJ, RSTR, RSTRH = responder reset;
* label (0/1) -> IS_ATTACK (metrics only); `type` (attack class) is kept only as a count.
Rows are yielded in file order; files must be passed in their numeric order.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
ORIG_RST, RESP_RST = {"RSTO", "RSTOS0"}, {"REJ", "RSTR", "RSTRH"}


def _num(v, cast=float, default=0):
    if v in (None, "", "-", "(empty)"):
        return default
    try:
        return cast(float(v))
    except ValueError:
        return default


def records(paths: list[str | Path], stats: dict | None = None) -> Iterator[dict]:
    stats = stats if stats is not None else {}
    for p in paths:
        with Path(p).open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                stats["rows"] = stats.get("rows", 0) + 1
                try:
                    start = int(round(float(row["ts"]) * 1000))
                except (KeyError, ValueError):
                    stats["skipped"] = stats.get("skipped", 0) + 1
                    continue
                dur = int(round(_num(row.get("duration")) * 1000))
                cs = str(row.get("conn_state", "")).strip()
                proto = PROTO.get(str(row.get("proto", "")).lower(), 0)
                cli = 4 if proto == 6 and cs in ORIG_RST else 0
                srv = 4 if proto == 6 and cs in RESP_RST else 0
                yield {
                    "FLOW_START_MILLISECONDS": start, "FLOW_END_MILLISECONDS": start + dur,
                    "IPV4_SRC_ADDR": row.get("src_ip"), "L4_SRC_PORT": _num(row.get("src_port"), int),
                    "IPV4_DST_ADDR": row.get("dst_ip"), "L4_DST_PORT": _num(row.get("dst_port"), int),
                    "PROTOCOL": proto,
                    "IN_BYTES": _num(row.get("src_ip_bytes"), int),
                    "OUT_BYTES": _num(row.get("dst_ip_bytes"), int),
                    "IN_PKTS": _num(row.get("src_pkts"), int),
                    "OUT_PKTS": _num(row.get("dst_pkts"), int),
                    "TCP_FLAGS": cli | srv, "CLIENT_TCP_FLAGS": cli, "SERVER_TCP_FLAGS": srv,
                    "FLOW_DURATION_MILLISECONDS": dur,
                    "IS_ATTACK": 1.0 if str(row.get("label", "0")).strip() in ("1", "1.0") else 0.0,
                }  # fmt: skip
