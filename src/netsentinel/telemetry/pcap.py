"""Minimal, defensive packet reader for offline analysis (no third-party dependencies).

Formats: classic libpcap (microsecond 0xa1b2c3d4 and nanosecond 0xa1b23c4d, both byte
orders) and pcapng (SHB / IDB / EPB / SPB blocks). Link types: Ethernet (1, with 802.1Q/ad
VLAN tags), raw IP (101, 228, 229) and Linux cooked SLL (113). Network: IPv4 (no fragment
reassembly) and IPv6 (fixed header; extension headers are not walked). Transport: TCP, UDP,
ICMP/ICMPv6.

Untrusted input: every length field is bounds-checked; malformed or unsupported packets are
counted and skipped, never raised; files larger than `max_bytes` are refused. Payload bytes
are never retained - only header metadata is yielded.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAX_BYTES = 2 * 1024**3  # 2 GiB


@dataclass(frozen=True)
class Packet:
    ts: float  # seconds since epoch (UTC)
    src: str
    dst: str
    proto: int  # 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6, other
    sport: int
    dport: int
    ip_len: int  # IP total length (L3 bytes)
    payload_len: int  # L4 payload bytes
    ttl: int
    tcp_flags: int = 0
    tcp_window: int = 0
    tcp_seq: int = 0
    icmp_type: int = 0  # type * 256 + code


@dataclass
class ReadStats:
    packets: int = 0
    parsed: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def _parse_l3(data: bytes, ts: float, stats: ReadStats) -> Packet | None:
    if len(data) < 1:
        stats.skip("empty")
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            stats.skip("short_ipv4")
            return None
        ihl = (data[0] & 0x0F) * 4
        total = struct.unpack_from("!H", data, 2)[0]
        if ihl < 20 or len(data) < ihl or total < ihl:
            stats.skip("bad_ipv4_header")
            return None
        frag = struct.unpack_from("!H", data, 6)[0]
        if frag & 0x1FFF:  # non-first fragment: no L4 header
            stats.skip("ipv4_fragment")
            return None
        ttl, proto = data[8], data[9]
        src = str(ipaddress.IPv4Address(data[12:16]))
        dst = str(ipaddress.IPv4Address(data[16:20]))
        l4 = data[ihl:total] if total <= len(data) else data[ihl:]  # snaplen-truncated ok
        ip_len, hdr = total, ihl
    elif version == 6:
        if len(data) < 40:
            stats.skip("short_ipv6")
            return None
        plen = struct.unpack_from("!H", data, 4)[0]
        proto, ttl = data[6], data[7]
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        l4 = data[40 : 40 + plen]
        ip_len, hdr = 40 + plen, 40
    else:
        stats.skip("not_ip")
        return None
    sport = dport = flags = window = seq = icmp = 0
    if proto == 6:
        if len(l4) < 20:
            stats.skip("short_tcp")
            return None
        sport, dport, seq = struct.unpack_from("!HHI", l4, 0)
        off = (l4[12] >> 4) * 4
        flags, window = l4[13], struct.unpack_from("!H", l4, 14)[0]
        if off < 20:
            stats.skip("bad_tcp_offset")
            return None
        l4_hdr = off
    elif proto == 17:
        if len(l4) < 8:
            stats.skip("short_udp")
            return None
        sport, dport = struct.unpack_from("!HH", l4, 0)
        l4_hdr = 8
    elif proto in (1, 58):
        if len(l4) < 4:
            stats.skip("short_icmp")
            return None
        icmp = l4[0] * 256 + l4[1]
        l4_hdr = 4
    else:
        l4_hdr = 0
    payload = max(ip_len - hdr - l4_hdr, 0)
    return Packet(ts, src, dst, proto, sport, dport, ip_len, payload, ttl, flags, window, seq,
                  icmp)  # fmt: skip


def _parse_link(linktype: int, frame: bytes, ts: float, stats: ReadStats) -> Packet | None:
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            stats.skip("short_ethernet")
            return None
        etype, off = struct.unpack_from("!H", frame, 12)[0], 14
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN tags
            etype, off = struct.unpack_from("!H", frame, off + 2)[0], off + 4
        if etype not in (0x0800, 0x86DD):
            stats.skip("non_ip_ethertype")
            return None
        return _parse_l3(frame[off:], ts, stats)
    if linktype in (101, 228, 229):  # raw IP
        return _parse_l3(frame, ts, stats)
    if linktype == 113:  # Linux SLL
        if len(frame) < 16:
            stats.skip("short_sll")
            return None
        if struct.unpack_from("!H", frame, 14)[0] not in (0x0800, 0x86DD):
            stats.skip("non_ip_sll")
            return None
        return _parse_l3(frame[16:], ts, stats)
    stats.skip(f"linktype_{linktype}")
    return None


def _classic(fh, magic: bytes, stats: ReadStats) -> Iterator[Packet]:
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        endian = ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    rest = fh.read(20)
    if len(rest) < 20:
        raise ValueError("truncated pcap global header")
    _major, _minor, _tz, _sigfigs, _snaplen, linktype = struct.unpack(endian + "HHiIII", rest)
    while True:
        hdr = fh.read(16)
        if len(hdr) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", hdr)
        if incl > 262144:
            stats.skip("oversized_record")
            return  # corrupt length: stop rather than read garbage
        frame = fh.read(incl)
        if len(frame) < incl:
            stats.skip("truncated_record")
            return
        stats.packets += 1
        ts = sec + frac / (1e9 if nano else 1e6)
        if (p := _parse_link(linktype & 0x0FFFFFFF, frame, ts, stats)) is not None:
            stats.parsed += 1
            yield p


def _pcapng(fh, stats: ReadStats) -> Iterator[Packet]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, ts resolution in seconds)
    first = True
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        if first:
            btype = struct.unpack("<I", head[:4])[0]
            if btype != 0x0A0D0D0A:
                raise ValueError("not a pcapng section header")
        btype, blen = struct.unpack(endian + "II", head)
        if first or btype == 0x0A0D0D0A:
            body_start = fh.read(4)
            bom = body_start
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:])[0]
            if blen < 28 or blen > 1 << 24:
                raise ValueError("bad pcapng section length")
            fh.read(blen - 12)
            interfaces = []
            first = False
            continue
        if blen < 12 or blen > 1 << 24 or blen % 4:
            stats.skip("bad_block_length")
            return
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            stats.skip("truncated_block")
            return
        if btype == 1:  # IDB
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            res = 1e-6
            opts = body[8:-4]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack_from(endian + "HH", opts, i)
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = opts[i + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0**-v
                i += 4 + ((olen + 3) // 4) * 4
            interfaces.append((linktype, res))
        elif btype == 6:  # EPB
            if len(body) < 20:
                stats.skip("short_epb")
                continue
            iface, hi, lo, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface >= len(interfaces) or cap > len(body) - 20:
                stats.skip("bad_epb")
                continue
            linktype, res = interfaces[iface]
            stats.packets += 1
            ts = ((hi << 32) | lo) * res
            if (p := _parse_link(linktype, body[20 : 20 + cap], ts, stats)) is not None:
                stats.parsed += 1
                yield p
        elif btype == 3:  # SPB (no timestamp; rare) - skipped explicitly
            stats.packets += 1
            stats.skip("simple_packet_block_no_timestamp")


def read_packets(path: str | Path, stats: ReadStats | None = None,
                 max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[Packet]:  # fmt: skip
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes}-byte limit")
    stats = stats if stats is not None else ReadStats()
    with path.open("rb") as fh:
        magic = fh.read(4)
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                     b"\x4d\x3c\xb2\xa1"):  # fmt: skip
            yield from _classic(fh, magic, stats)
        elif magic == b"\x0a\x0d\x0d\x0a":
            fh.seek(0)
            yield from _pcapng(fh, stats)
        else:
            raise ValueError(f"{path.name}: not a pcap/pcapng file")
