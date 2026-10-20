"""Deterministic SYNTHETIC fixtures for `netsentinel demo` and tests.

Everything here is generated from fixed seeds: no real network data, freely distributable.
It exercises the software; it is NOT evidence of detection performance on real attacks.
"""

from __future__ import annotations

import hashlib
import random
import struct
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

NF_HEADER = ("FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,"
             "IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,L7_PROTO,IN_BYTES,IN_PKTS,OUT_BYTES,OUT_PKTS,"
             "TCP_FLAGS,CLIENT_TCP_FLAGS,SERVER_TCP_FLAGS,FLOW_DURATION_MILLISECONDS,MIN_TTL,"
             "MAX_TTL,Label,Attack")  # fmt: skip
DEMO_T0 = 1_760_000_000.0  # 2025-10-09 08:53:20 UTC (arbitrary, fixed)


def nf_rows(day: datetime, n: int, seed: int) -> list[str]:
    """NetFlow-v3-style rows: benign web/DNS flows plus SSH brute-force bursts every ~10 min."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        t = int((day + timedelta(seconds=i * 7200 / n)).timestamp() * 1000)
        if (i // 40) % 3 == 1:  # brute force: short flows, small replies, many per second
            vals = (t, t + 50, "10.9.9.9", 40000 + i % 1000, "10.0.0.5", 22, 6, 92,
                    int(rng.integers(300, 600)), int(rng.integers(8, 14)), 200, 6, 27, 26, 25,
                    50, 64, 64, 1, "brute_force")  # fmt: skip
        else:
            port = int(rng.choice([443, 53, 80]))
            vals = (
                t,
                t + int(rng.integers(5, 5000)),
                f"10.0.1.{i % 200}",
                50000 + i % 9000,
                "93.184.216.34",
                port,
                17 if port == 53 else 6,
                {443: 91, 53: 5, 80: 7}[port],
                int(rng.integers(100, 9000)),
                int(rng.integers(1, 30)),
                int(rng.integers(100, 90000)),
                int(rng.integers(1, 60)),
                0 if port == 53 else 27,
                0 if port == 53 else 27,
                0 if port == 53 else 27,
                int(rng.integers(5, 5000)),
                60,
                64,
                0,
                "Benign",
            )
        rows.append(",".join(map(str, vals)))
    return rows


def write_nf_archive(path: Path, days: int = 2, rows_per_day: int = 1500, seed: int = 0) -> Path:
    """A BagIt-style zip like the NF-v3 releases (CSV + SHA-1 manifest)."""
    rows: list[str] = []
    for d in range(days):
        rows += nf_rows(datetime(2018, 2, 14 + d, 13, 0), rows_per_day, seed + d)
    csv = (NF_HEADER + "\n" + "\n".join(rows) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("bag/data/NF-demo.csv", csv)
        z.writestr("bag/manifest-sha1.txt", f"{hashlib.sha1(csv).hexdigest()} data/NF-demo.csv\n")
    return path


def _ipv4(src, dst, proto, l4, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, ttl, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))  # fmt: skip
    return b"\x00" * 12 + b"\x08\x00" + hdr + l4


def _tcp(sp, dp, flags, seq, payload=b"", win=64240):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 5 << 4, flags, win, 0, 0) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def write_demo_pcap(out: str | Path, minutes: int = 25, attack_at_min: float = 18.0,
                    scan_at_min: float = 21.0, seed: int = 7) -> Path:  # fmt: skip
    """Classic pcap: benign HTTPS + DNS from 60 hosts for `minutes`; from `attack_at_min` a 3-min
    SSH brute-force burst (10 attempts/s) from 10.9.9.9; from `scan_at_min` a 1-min TCP port
    scan (SYN, RST replies) from 10.9.9.8. Returns the path."""
    rng = random.Random(seed)
    t0 = DEMO_T0
    pkts = []
    for i in range(minutes * 60):
        t = t0 + i
        c, s, sp = f"10.0.1.{rng.randint(2, 60)}", "93.184.216.34", rng.randint(40000, 60000)
        pkts += [(t, _ipv4(c, s, 6, _tcp(sp, 443, 0x02, 1))),
                 (t + 0.01, _ipv4(s, c, 6, _tcp(443, sp, 0x12, 7))),
                 (t + 0.02, _ipv4(c, s, 6, _tcp(sp, 443, 0x18, 2, b"x" * rng.randint(200, 900)))),
                 (t + 0.05, _ipv4(s, c, 6, _tcp(443, sp, 0x18, 8, b"y" * rng.randint(500, 1400)))),
                 (t + 0.06, _ipv4(c, s, 6, _tcp(sp, 443, 0x11, 900))),
                 (t + 0.07, _ipv4(s, c, 6, _tcp(443, sp, 0x11, 1500))),
                 (t + 0.3, _ipv4(c, "10.0.0.53", 17, _udp(sp, 53, b"q" * 32))),
                 (t + 0.31, _ipv4("10.0.0.53", c, 17, _udp(53, sp, b"a" * 80)))]  # fmt: skip
    for j in range(1800):  # SSH brute force
        t = t0 + attack_at_min * 60 + j * 0.1
        a, v, sp = "10.9.9.9", "10.0.0.22", 30000 + j
        pkts += [(t, _ipv4(a, v, 6, _tcp(sp, 22, 0x02, 1))),
                 (t + 0.002, _ipv4(v, a, 6, _tcp(22, sp, 0x12, 5))),
                 (t + 0.004, _ipv4(a, v, 6, _tcp(sp, 22, 0x18, 2, b"k" * 40))),
                 (t + 0.006, _ipv4(v, a, 6, _tcp(22, sp, 0x18, 6, b"s" * 40))),
                 (t + 0.008, _ipv4(a, v, 6, _tcp(sp, 22, 0x04, 42)))]  # fmt: skip
    for j in range(600):  # port scan: SYN to many ports, RST back
        t = t0 + scan_at_min * 60 + j * 0.1
        a, v, sp = "10.9.9.8", f"10.0.2.{1 + j % 20}", 61000
        pkts += [(t, _ipv4(a, v, 6, _tcp(sp, 1 + j, 0x02, 1))),
                 (t + 0.001, _ipv4(v, a, 6, _tcp(1 + j, sp, 0x14, 0)))]  # fmt: skip
    pkts.sort(key=lambda p: p[0])
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in pkts:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)))
            f.write(frame)
    return path


def demo_labels() -> dict:
    """Ground truth of the synthetic demo capture (for tests and incident evaluation)."""
    return {"ssh_bruteforce": {"src": "10.9.9.9", "start_s": 18 * 60, "end_s": 21 * 60},
            "port_scan": {"src": "10.9.9.8", "start_s": 21 * 60, "end_s": 22 * 60},
            "t0": DEMO_T0}  # fmt: skip
