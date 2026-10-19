"""PCAP / pcapng / Zeek parsing and flow assembly on SYNTHETIC captures built byte by byte."""

import struct

import pytest

from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.pcap import ReadStats, read_packets
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log


def ipv4(src, dst, proto, l4, ttl=64):
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, ttl, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))  # fmt: skip
    return hdr + l4


def tcp(sport, dport, flags, seq=0, payload=b"", window=1000):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, window, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(ip):
    return b"\x00" * 12 + b"\x08\x00" + ip


def write_pcap(path, frames, nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec, frac = int(ts), round((ts - int(ts)) * (1e9 if nano else 1e6))
            f.write(struct.pack("<IIII", sec, frac, len(frame), len(frame)) + frame)
    return path


def write_pcapng(path, frames):
    def block(btype, body):
        pad = b"\x00" * ((4 - len(body) % 4) % 4)
        n = 12 + len(body) + len(pad)
        return struct.pack("<II", btype, n) + body + pad + struct.pack("<I", n)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 0, 0))
    out = shb + idb
    for ts, frame in frames:
        t = int(ts * 1e6)
        out += block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame))
                     + frame)  # fmt: skip
    path.write_bytes(out)
    return path


T0 = 1518631260.0  # 2018-02-14 18:01:00 UTC
C, S = "10.0.0.5", "10.0.0.9"
SESSION = [
    (T0 + 0.000, eth(ipv4(C, S, 6, tcp(40000, 22, 0x02, seq=1)))),            # SYN
    (T0 + 0.010, eth(ipv4(S, C, 6, tcp(22, 40000, 0x12, seq=7)))),            # SYN-ACK
    (T0 + 0.020, eth(ipv4(C, S, 6, tcp(40000, 22, 0x18, seq=2, payload=b"x" * 100)))),
    (T0 + 0.030, eth(ipv4(C, S, 6, tcp(40000, 22, 0x18, seq=2, payload=b"x" * 100)))),  # retx
    (T0 + 0.050, eth(ipv4(S, C, 6, tcp(22, 40000, 0x11, seq=8), ttl=50))),    # FIN-ACK
    (T0 + 0.060, eth(ipv4(C, S, 6, tcp(40000, 22, 0x11, seq=102)))),          # FIN-ACK -> end
    (T0 + 1.000, eth(ipv4(C, "8.8.8.8", 17, udp(5353, 53, b"q" * 30)))),      # DNS query
    (T0 + 1.020, eth(ipv4("8.8.8.8", C, 17, udp(53, 5353, b"a" * 60)))),      # DNS answer
    (T0 + 2.000, b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28),                   # ARP: skipped
    (T0 + 2.500, eth(b"\x45\x00\x00")),                                       # malformed IPv4
]  # fmt: skip


@pytest.mark.parametrize("fmt", ["pcap", "pcap_ns", "pcapng"])
def test_read_and_assemble_flows(tmp_path, fmt):
    path = tmp_path / f"c.{fmt}"
    if fmt == "pcapng":
        write_pcapng(path, SESSION)
    else:
        write_pcap(path, SESSION, nano=fmt == "pcap_ns")
    stats = ReadStats()
    flows = list(assemble_flows(read_packets(path, stats)))
    assert stats.packets == 10 and stats.parsed == 8
    assert stats.skipped == {"non_ip_ethertype": 1, "short_ipv4": 1}
    tcpf = next(f for f in flows if f["PROTOCOL"] == 6)
    assert (tcpf["IPV4_SRC_ADDR"], tcpf["L4_DST_PORT"]) == (C, 22)  # first sender = client
    assert (tcpf["IN_PKTS"], tcpf["OUT_PKTS"]) == (4, 2)
    assert tcpf["IN_BYTES"] == 40 + 140 + 140 + 40 and tcpf["OUT_BYTES"] == 80
    assert tcpf["CLIENT_TCP_FLAGS"] == 0x02 | 0x18 | 0x11 and tcpf["SERVER_TCP_FLAGS"] == 0x13
    assert tcpf["FLOW_DURATION_MILLISECONDS"] == 60
    assert tcpf["RETRANSMITTED_IN_PKTS"] == 1
    assert (tcpf["MIN_TTL"], tcpf["MAX_TTL"]) == (50, 64)
    assert tcpf["SRC_TO_DST_IAT_MAX"] == pytest.approx(30, abs=0.01)
    dns = next(f for f in flows if f["PROTOCOL"] == 17)
    assert (dns["L4_DST_PORT"], dns["IN_BYTES"], dns["OUT_BYTES"]) == (53, 58, 88)


def test_frame_and_aliases(tmp_path):
    flows = list(assemble_flows(read_packets(write_pcap(tmp_path / "c.pcap", SESSION))))
    df = records_to_frame(flows, utc_offset_hours=-4)
    assert df["timestamp"][0].strftime("%H:%M") == "14:01"
    assert set(df["dst_port"].to_list()) == {22, 53}
    tcp_row = df.filter(df["protocol"] == 6)
    assert tcp_row["cli_syn"][0] == 1 and tcp_row["srv_fin"][0] == 1
    assert tcp_row["flow_duration"][0] == 60_000  # microseconds alias


def test_idle_timeout_splits_flows(tmp_path):
    frames = [(T0, eth(ipv4(C, S, 17, udp(1, 2)))), (T0 + 100, eth(ipv4(C, S, 17, udp(1, 2))))]
    flows = list(assemble_flows(read_packets(write_pcap(tmp_path / "u.pcap", frames))))
    assert len(flows) == 2


def test_close_linger_absorbs_final_ack_and_new_syn_restarts(tmp_path):
    # FIN/FIN then the final ACK: one flow (the ACK used to open a spurious tail flow);
    # a fresh SYN on the same 5-tuple 1 s later starts a new flow despite the linger.
    seq = [(0.00, C, S, 1000, 22, 0x02), (0.01, S, C, 22, 1000, 0x12), (0.02, C, S, 1000, 22, 0x11),
           (0.03, S, C, 22, 1000, 0x11), (0.04, C, S, 1000, 22, 0x10),
           (1.04, C, S, 1000, 22, 0x02), (1.05, S, C, 22, 1000, 0x12)]  # fmt: skip
    frames = [(T0 + t, eth(ipv4(a, b, 6, tcp(sp, dp, fl)))) for t, a, b, sp, dp, fl in seq]
    path = write_pcap(tmp_path / "f.pcap", frames)
    flows = list(assemble_flows(read_packets(path)))
    assert [f["IN_PKTS"] + f["OUT_PKTS"] for f in flows] == [5, 2]
    legacy = list(assemble_flows(read_packets(path), close_linger=0))
    assert [f["IN_PKTS"] + f["OUT_PKTS"] for f in legacy] == [4, 3]  # stray ACK + next SYN merged


def test_rejects_non_pcap_and_oversized(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"NOTAPCAP" * 10)
    with pytest.raises(ValueError, match="not a pcap"):
        list(read_packets(bad))
    good = write_pcap(tmp_path / "g.pcap", SESSION)
    with pytest.raises(ValueError, match="limit"):
        list(read_packets(good, max_bytes=10))


def test_corrupt_record_length_stops_cleanly(tmp_path):
    path = write_pcap(tmp_path / "c.pcap", SESSION[:2])
    with open(path, "ab") as f:
        f.write(struct.pack("<IIII", 0, 0, 10_000_000, 10_000_000))
    stats = ReadStats()
    assert len(list(read_packets(path, stats))) == 2
    assert stats.skipped.get("oversized_record") == 1


ZEEK_TSV = """#separator \\x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes
1518631260.000000\tC1\t10.0.0.5\t40000\t10.0.0.9\t22\ttcp\tssh\t0.060000\t200\t0\tSF\tShADadFf\t4\t360\t2\t80
1518631261.000000\tC2\t10.0.0.5\t5353\t8.8.8.8\t53\tudp\tdns\t-\t-\t-\tS0\t-\t1\t58\t0\t0
garbage line
"""


def test_zeek_tsv_and_json(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_TSV, encoding="utf-8")
    stats = ZeekStats()
    recs = list(read_conn_log(p, stats))
    assert stats.records == 2 and stats.skipped == {"field_count": 1}
    r = recs[0]
    assert (r["IN_BYTES"], r["OUT_BYTES"], r["IN_PKTS"], r["OUT_PKTS"]) == (360, 80, 4, 2)
    assert r["CLIENT_TCP_FLAGS"] == 2 | 16 | 8 | 1 and r["SERVER_TCP_FLAGS"] == 18 | 8 | 1
    assert r["FLOW_DURATION_MILLISECONDS"] == 60 and recs[1]["FLOW_DURATION_MILLISECONDS"] == 0
    j = tmp_path / "conn.json"
    j.write_text('{"ts": 1518631260.0, "id.orig_h": "a", "id.orig_p": 1, "id.resp_h": "b", '
                 '"id.resp_p": 80, "proto": "tcp", "orig_ip_bytes": 10, "resp_ip_bytes": 5, '
                 '"orig_pkts": 1, "resp_pkts": 1, "history": "S"}\n', encoding="utf-8")  # fmt: skip
    df = records_to_frame(read_conn_log(j))
    assert df["min_ttl"].null_count() == 1  # Zeek has no TTL: stays missing, not invented
