"""Bidirectional flow assembly from packets, emitting NetFlow-v3-style records.

Conventions (chosen to match NF-v3 / nProbe as documented in NetFlow_v3_Features.csv):
* A flow is identified by (protocol, endpoints); the endpoint that sent the first packet is
  the client; IN_* = client->server, OUT_* = server->client. Byte counts are IP-level
  (`ip_len`), packet lengths are IP packet lengths.
* Flows end on idle timeout (default 30 s, nProbe's default), active timeout (120 s), or 5 s
  after a TCP RST is seen / both directions have sent FIN (close linger, as Zeek's
  tcp_close_delay; validated against Zeek on CTU-Normal-26, reports/audit/pcap_vs_zeek.json).
* IAT statistics are per direction in milliseconds; retransmissions = TCP data segments whose
  (seq, payload length) was already seen in that direction (bounded set).

This is an approximation of nProbe, not a re-implementation: field-level agreement with the
NF-v3 datasets is NOT verified (no paired PCAP + NF-v3 data was available). Models applied to
PCAP-derived flows inherit that uncertainty; see docs/limitations.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from netsentinel.telemetry.pcap import Packet

FIN, SYN, RST = 1, 2, 4
SIZE_BINS = ((128, "num_pkts_up_to_128_bytes"), (256, "num_pkts_128_to_256_bytes"),
             (512, "num_pkts_256_to_512_bytes"), (1024, "num_pkts_512_to_1024_bytes"),
             (1514, "num_pkts_1024_to_1514_bytes"))  # fmt: skip


@dataclass
class _Dir:
    pkts: int = 0
    bytes: int = 0
    first: float = math.inf
    last: float = -math.inf
    flags: int = 0
    win_max: int = 0
    retrans_pkts: int = 0
    retrans_bytes: int = 0
    iat_n: int = 0
    iat_mean: float = 0.0
    iat_m2: float = 0.0
    iat_min: float = math.inf
    iat_max: float = 0.0
    seen: set = field(default_factory=set)

    def add(self, p: Packet) -> None:
        if self.pkts:
            iat = (p.ts - self.last) * 1000.0
            self.iat_n += 1
            d = iat - self.iat_mean
            self.iat_mean += d / self.iat_n
            self.iat_m2 += d * (iat - self.iat_mean)
            self.iat_min, self.iat_max = min(self.iat_min, iat), max(self.iat_max, iat)
        self.pkts += 1
        self.bytes += p.ip_len
        self.first, self.last = min(self.first, p.ts), max(self.last, p.ts)
        self.flags |= p.tcp_flags
        self.win_max = max(self.win_max, p.tcp_window)
        if p.proto == 6 and p.payload_len > 0:
            key = (p.tcp_seq, p.payload_len)
            if key in self.seen:
                self.retrans_pkts += 1
                self.retrans_bytes += p.ip_len
            elif len(self.seen) < 4096:
                self.seen.add(key)

    def iat_stats(self) -> tuple[float, float, float, float]:
        if self.iat_n == 0:
            return 0.0, 0.0, 0.0, 0.0
        std = math.sqrt(self.iat_m2 / self.iat_n) if self.iat_n > 1 else 0.0
        return self.iat_min, self.iat_max, self.iat_mean, std


@dataclass
class _Flow:
    client: tuple[str, int]
    server: tuple[str, int]
    proto: int
    start: float
    last: float
    fwd: _Dir = field(default_factory=_Dir)
    bwd: _Dir = field(default_factory=_Dir)
    ttl_min: int = 255
    ttl_max: int = 0
    len_min: int = 1 << 30
    len_max: int = 0
    sizes: dict = field(default_factory=lambda: {name: 0 for _, name in SIZE_BINS})
    icmp_type: int = 0
    closed_at: float | None = None  # time TCP termination (FIN both / RST) was first seen

    def add(self, p: Packet, forward: bool) -> None:
        (self.fwd if forward else self.bwd).add(p)
        self.last = max(self.last, p.ts)
        self.ttl_min, self.ttl_max = min(self.ttl_min, p.ttl), max(self.ttl_max, p.ttl)
        self.len_min, self.len_max = min(self.len_min, p.ip_len), max(self.len_max, p.ip_len)
        for limit, name in SIZE_BINS:
            if p.ip_len <= limit:
                self.sizes[name] += 1
                break
        if p.proto in (1, 58) and forward and not self.icmp_type:
            self.icmp_type = p.icmp_type

    def finished_by_tcp(self) -> bool:
        both_fin = (self.fwd.flags & FIN) and (self.bwd.flags & FIN)
        return bool(self.proto == 6 and ((self.fwd.flags | self.bwd.flags) & RST or both_fin))

    def record(self) -> dict:
        dur_ms = max(int(round((self.last - self.start) * 1000)), 0)
        secs = max(self.last - self.start, 1e-3)
        f_iat, b_iat = self.fwd.iat_stats(), self.bwd.iat_stats()

        def span(d: _Dir) -> int:
            return int(round((d.last - d.first) * 1000)) if d.pkts else 0

        return {
            "FLOW_START_MILLISECONDS": int(self.start * 1000),
            "FLOW_END_MILLISECONDS": int(self.last * 1000),
            "IPV4_SRC_ADDR": self.client[0], "L4_SRC_PORT": self.client[1],
            "IPV4_DST_ADDR": self.server[0], "L4_DST_PORT": self.server[1],
            "PROTOCOL": self.proto,
            "IN_BYTES": self.fwd.bytes, "IN_PKTS": self.fwd.pkts,
            "OUT_BYTES": self.bwd.bytes, "OUT_PKTS": self.bwd.pkts,
            "TCP_FLAGS": self.fwd.flags | self.bwd.flags,
            "CLIENT_TCP_FLAGS": self.fwd.flags, "SERVER_TCP_FLAGS": self.bwd.flags,
            "FLOW_DURATION_MILLISECONDS": dur_ms,
            "DURATION_IN": span(self.fwd), "DURATION_OUT": span(self.bwd),
            "MIN_TTL": self.ttl_min, "MAX_TTL": self.ttl_max,
            "LONGEST_FLOW_PKT": self.len_max, "SHORTEST_FLOW_PKT": self.len_min,
            "MIN_IP_PKT_LEN": self.len_min, "MAX_IP_PKT_LEN": self.len_max,
            "SRC_TO_DST_SECOND_BYTES": self.fwd.bytes / secs,
            "DST_TO_SRC_SECOND_BYTES": self.bwd.bytes / secs,
            "RETRANSMITTED_IN_BYTES": self.fwd.retrans_bytes,
            "RETRANSMITTED_IN_PKTS": self.fwd.retrans_pkts,
            "RETRANSMITTED_OUT_BYTES": self.bwd.retrans_bytes,
            "RETRANSMITTED_OUT_PKTS": self.bwd.retrans_pkts,
            "SRC_TO_DST_AVG_THROUGHPUT": 8 * self.fwd.bytes / secs,
            "DST_TO_SRC_AVG_THROUGHPUT": 8 * self.bwd.bytes / secs,
            **{name.upper(): n for name, n in self.sizes.items()},
            "TCP_WIN_MAX_IN": self.fwd.win_max, "TCP_WIN_MAX_OUT": self.bwd.win_max,
            "ICMP_TYPE": self.icmp_type,
            "SRC_TO_DST_IAT_MIN": f_iat[0], "SRC_TO_DST_IAT_MAX": f_iat[1],
            "SRC_TO_DST_IAT_AVG": f_iat[2], "SRC_TO_DST_IAT_STDDEV": f_iat[3],
            "DST_TO_SRC_IAT_MIN": b_iat[0], "DST_TO_SRC_IAT_MAX": b_iat[1],
            "DST_TO_SRC_IAT_AVG": b_iat[2], "DST_TO_SRC_IAT_STDDEV": b_iat[3],
        }  # fmt: skip


def assemble_flows(
    packets: Iterable[Packet],
    idle_timeout: float = 30.0,
    active_timeout: float = 120.0,
    max_active: int = 200_000,
    idle_by_proto: dict[int, float] | None = None,
    close_linger: float = 5.0,
) -> Iterator[dict]:
    """Yield NF-v3-style flow records in order of expiry. Memory is bounded by `max_active`
    concurrent flows (the oldest is force-expired beyond that). `idle_by_proto` overrides the
    idle timeout per IP protocol (e.g. Zeek defaults {6: 300, 17: 60, 1: 60}). A terminated TCP
    flow lingers `close_linger` seconds (Zeek's tcp_close_delay) so the final ACK / late FIN is
    counted in it instead of opening a spurious tail flow; a new SYN ends the linger at once."""
    idle_map = idle_by_proto or {}

    def idle(proto: int) -> float:
        return idle_map.get(proto, idle_timeout)

    active: dict[tuple, _Flow] = {}
    last_sweep = -math.inf

    def expired(f: _Flow, now: float) -> bool:
        if f.closed_at is not None and now - f.closed_at > close_linger:
            return True
        return now - f.last > idle(f.proto) or now - f.start > active_timeout

    for p in packets:
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (p.proto, *sorted((a, b)))
        flow = active.get(key)
        if flow is not None and (expired(flow, p.ts) or (
                flow.closed_at is not None and p.tcp_flags & SYN and not p.tcp_flags & 16)):
            yield active.pop(key).record()
            flow = None
        if flow is None:
            if len(active) >= max_active:
                oldest = min(active, key=lambda k: active[k].last)
                yield active.pop(oldest).record()
            flow = active[key] = _Flow(client=a, server=b, proto=p.proto, start=p.ts, last=p.ts)
        flow.add(p, forward=(a == flow.client))
        if flow.closed_at is None and flow.finished_by_tcp():
            flow.closed_at = p.ts
            if close_linger <= 0:
                yield active.pop(key).record()
        if p.ts - last_sweep > 1.0:  # periodic expiry sweep
            last_sweep = p.ts
            for k in [k for k, f in active.items() if expired(f, p.ts)]:
                yield active.pop(k).record()
    for f in sorted(active.values(), key=lambda f: f.start):
        yield f.record()
