"""Write a SYNTHETIC demo capture (classic pcap) for exercising `netsentinel analyze`.

Contents: 10 minutes of benign-looking HTTPS/DNS exchanges plus, from minute 5, a burst of
short SSH connection attempts (SYN, SYN-ACK, a small exchange, RST) from one source.
This is generated traffic for a functional demonstration only - it is NOT evidence of
detection performance. Usage: uv run python scripts/make_demo_pcap.py artifacts/demo.pcap
"""

import random
import struct
import sys
from pathlib import Path


def ipv4(src, dst, proto, l4, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, ttl, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))  # fmt: skip
    return b"\x00" * 12 + b"\x08\x00" + hdr + l4


def tcp(sp, dp, flags, seq, payload=b"", win=64240):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 5 << 4, flags, win, 0, 0) + payload


def udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def main(out: str) -> None:
    rng = random.Random(7)
    t0 = 1518631260.0  # arbitrary epoch; analyze with --utc-offset as appropriate
    pkts = []
    for i in range(600):  # benign: one HTTPS exchange and one DNS lookup per second
        t = t0 + i
        c, s, sp = f"10.0.1.{rng.randint(2, 60)}", "93.184.216.34", rng.randint(40000, 60000)
        pkts += [(t, ipv4(c, s, 6, tcp(sp, 443, 0x02, 1))),
                 (t + 0.01, ipv4(s, c, 6, tcp(443, sp, 0x12, 7))),
                 (t + 0.02, ipv4(c, s, 6, tcp(sp, 443, 0x18, 2, b"x" * rng.randint(200, 900)))),
                 (t + 0.05, ipv4(s, c, 6, tcp(443, sp, 0x18, 8, b"y" * rng.randint(500, 1400)))),
                 (t + 0.06, ipv4(c, s, 6, tcp(sp, 443, 0x11, 900))),
                 (t + 0.07, ipv4(s, c, 6, tcp(443, sp, 0x11, 1500))),
                 (t + 0.3, ipv4(c, "10.0.0.53", 17, udp(sp, 53, b"q" * 32))),
                 (t + 0.31, ipv4("10.0.0.53", c, 17, udp(53, sp, b"a" * 80)))]  # fmt: skip
    for j in range(3000):  # SSH attempts from one host, 10 per second from minute 5
        t = t0 + 300 + j * 0.1
        a, v, sp = "10.9.9.9", "10.0.0.22", 30000 + j
        pkts += [(t, ipv4(a, v, 6, tcp(sp, 22, 0x02, 1))),
                 (t + 0.002, ipv4(v, a, 6, tcp(22, sp, 0x12, 5))),
                 (t + 0.004, ipv4(a, v, 6, tcp(sp, 22, 0x18, 2, b"k" * 40))),
                 (t + 0.006, ipv4(v, a, 6, tcp(22, sp, 0x18, 6, b"s" * 40))),
                 (t + 0.008, ipv4(a, v, 6, tcp(sp, 22, 0x04, 42)))]  # fmt: skip
    pkts.sort(key=lambda p: p[0])
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in pkts:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)))
            f.write(frame)
    print(f"wrote {path} ({len(pkts)} packets)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "artifacts/demo.pcap")
