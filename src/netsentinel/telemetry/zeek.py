"""Zeek `conn.log` reader (TSV with #fields header, or JSON lines) -> NF-v3-style records.

Mapping (only fields Zeek actually provides; everything else stays missing):
  ts -> FLOW_START_MILLISECONDS; duration -> FLOW_DURATION_MILLISECONDS / FLOW_END
  id.orig_h/p -> IPV4_SRC_ADDR / L4_SRC_PORT;  id.resp_h/p -> IPV4_DST_ADDR / L4_DST_PORT
  proto tcp/udp/icmp -> 6/17/1
  orig_ip_bytes / resp_ip_bytes -> IN_BYTES / OUT_BYTES (IP-level, like NF-v3)
  orig_pkts / resp_pkts -> IN_PKTS / OUT_PKTS
  history -> CLIENT/SERVER_TCP_FLAGS: uppercase = originator, lowercase = responder;
            S/s,h SYN (h = SYN+ACK), A/a ACK, D/d PSH (data seen - an approximation),
            F/f FIN, R/r RST.
Unparseable lines are counted and skipped. IoT-23 `conn.log.labeled` files separate their
last three columns (tunnel_parents, label, detailed-label) by spaces instead of tabs; such
lines are repaired. `extras` maps output names to functions of the raw field dict (numeric
values only, e.g. an attack flag from `label`), so labels stay aligned with their records.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

IDLE = object()  # follow mode: 'no new data' marker, passed through parse_conn_lines
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
ORIG = {"S": 2, "A": 16, "D": 8, "F": 1, "R": 4}
RESP = {"s": 2, "h": 18, "a": 16, "d": 8, "f": 1, "r": 4}


@dataclass
class ZeekStats:
    lines: int = 0
    records: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1


def _num(v, cast=float, default=0):
    if v in (None, "-", "", "(empty)"):
        return default
    return cast(v)


def _flags(history: str | None) -> tuple[int, int]:
    cli = srv = 0
    for ch in history or "":
        cli |= ORIG.get(ch, 0)
        srv |= RESP.get(ch, 0)
    return cli, srv


def _record(d: dict) -> dict:
    start_ms = int(round(float(d["ts"]) * 1000))
    dur_ms = int(round(_num(d.get("duration")) * 1000))
    cli, srv = _flags(d.get("history"))
    proto = PROTO.get(str(d.get("proto", "")).lower(), 0)
    return {
        "FLOW_START_MILLISECONDS": start_ms,
        "FLOW_END_MILLISECONDS": start_ms + dur_ms,
        "IPV4_SRC_ADDR": d.get("id.orig_h"), "L4_SRC_PORT": _num(d.get("id.orig_p"), int),
        "IPV4_DST_ADDR": d.get("id.resp_h"), "L4_DST_PORT": _num(d.get("id.resp_p"), int),
        "PROTOCOL": proto,
        "IN_BYTES": _num(d.get("orig_ip_bytes"), int), "IN_PKTS": _num(d.get("orig_pkts"), int),
        "OUT_BYTES": _num(d.get("resp_ip_bytes"), int), "OUT_PKTS": _num(d.get("resp_pkts"), int),
        "TCP_FLAGS": cli | srv, "CLIENT_TCP_FLAGS": cli, "SERVER_TCP_FLAGS": srv,
        "FLOW_DURATION_MILLISECONDS": dur_ms,
    }  # fmt: skip


def parse_conn_lines(lines, stats: ZeekStats | None = None,
                     extras: dict[str, Callable[[dict], float]] | None = None,
                     ) -> Iterator[dict]:  # fmt: skip
    """Zeek conn.log lines (TSV with headers, or JSON) -> records. Shared by the file reader
    and the opt-in follow mode of the streaming monitor."""
    stats = stats if stats is not None else ZeekStats()
    fields: list[str] | None = None
    sep = "\t"
    for line in lines:
        if line is IDLE:  # follow mode idle tick: let the consumer advance wall-clock time
            yield IDLE
            continue
        stats.lines += 1
        line = line.rstrip("\n\r")
        if not line:
            continue
        try:
            if line.startswith("{"):
                d = json.loads(line)
            elif line.startswith("#"):
                if line.startswith("#separator"):
                    sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
                elif line.startswith("#fields"):
                    # IoT-23 headers also join their last columns with spaces
                    fields = [f for part in line.split(sep)[1:] for f in part.split()]
                continue
            else:
                if fields is None:
                    stats.skip("no_fields_header")
                    continue
                vals = line.split(sep)
                if len(vals) < len(fields) and " " in vals[-1]:  # IoT-23 label columns
                    vals = vals[:-1] + vals[-1].split()
                if len(vals) != len(fields):
                    stats.skip("field_count")
                    continue
                d = dict(zip(fields, vals, strict=True))
            if "ts" not in d or "id.resp_p" not in d:
                stats.skip("missing_core_fields")
                continue
            rec = _record(d)
            for name, fn in (extras or {}).items():
                rec[name] = fn(d)
        except (ValueError, KeyError, TypeError):
            stats.skip("unparseable")
            continue
        stats.records += 1
        yield rec


def read_conn_log(
    path: str | Path,
    stats: ZeekStats | None = None,
    max_bytes: int = 2 * 1024**3,
    extras: dict[str, Callable[[dict], float]] | None = None,
) -> Iterator[dict]:
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes}-byte limit")
    with path.open(encoding="utf-8", errors="replace") as fh:
        yield from parse_conn_lines(fh, stats, extras)
