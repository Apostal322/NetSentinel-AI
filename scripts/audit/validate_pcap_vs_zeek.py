"""Mission 6: validate the pure-Python PCAP reader + flow assembler against a reference extractor
(Zeek conn.log produced from the same capture by the dataset authors).

Flows are matched one-to-one on (protocol, unordered endpoints) and start time (|dt| <= tol);
ICMP is matched on hosts only (Zeek puts type/code in the port fields). Two assembler settings
are compared: the nProbe-style defaults used for the models (idle 30 s, active 120 s) and Zeek
defaults (TCP inactivity 300 s, UDP/ICMP 60 s, no active timeout), so that disagreements caused
by timeout policy can be separated from disagreements in packet accounting. `v0_no_close_linger`
reproduces the assembler before the close-linger fix that this validation motivated.

Usage: uv run python scripts/audit/validate_pcap_vs_zeek.py PCAP CONN_LOG [--out JSON]
"""

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.pcap import ReadStats, read_packets
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log

PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
CONFIGS = {
    "v0_no_close_linger": {"idle_timeout": 30.0, "active_timeout": 120.0, "close_linger": 0.0},
    "nprobe_defaults": {"idle_timeout": 30.0, "active_timeout": 120.0},
    "zeek_defaults": {"idle_timeout": 60.0, "active_timeout": math.inf,
                      "idle_by_proto": {6: 300.0, 17: 60.0, 1: 60.0}},
}  # fmt: skip
FIN, SYN, RST = 1, 2, 4


def load_zeek(path: Path) -> list[dict]:
    rows, fields, sep = [], None, "\t"
    for line in path.open(encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if line.startswith("#separator"):
            sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
        elif line.startswith("#fields"):
            fields = line.split(sep)[1:]
        elif line and not line.startswith("#"):
            d = dict(zip(fields, line.split(sep), strict=True))
            num = lambda k, c=int, d=d: c(d[k]) if d[k] not in ("-", "(empty)") else None  # noqa: E731
            rows.append({"ts": float(d["ts"]), "proto": PROTO.get(d["proto"], 0),
                         "a": (d["id.orig_h"], int(d["id.orig_p"])),
                         "b": (d["id.resp_h"], int(d["id.resp_p"])),
                         "dur": num("duration", float), "state": d["conn_state"],
                         "history": d["history"], "service": d["service"],
                         "opkts": num("orig_pkts"), "rpkts": num("resp_pkts"),
                         "obytes": num("orig_ip_bytes"), "rbytes": num("resp_ip_bytes"),
                         "missed": num("missed_bytes")})  # fmt: skip
    return rows


def key(proto, a, b):
    if proto in (1, 58):
        return proto, frozenset((a[0], b[0]))
    return proto, frozenset((a, b))


def match(ours: list[dict], zeek: list[dict], tol: float):
    idx = defaultdict(list)
    for j, z in enumerate(zeek):
        idx[key(z["proto"], z["a"], z["b"])].append(j)
    used, pairs = set(), []
    for i, r in enumerate(ours):
        a, b = (r["IPV4_SRC_ADDR"], r["L4_SRC_PORT"]), (r["IPV4_DST_ADDR"], r["L4_DST_PORT"])
        best, bd = None, tol
        for j in idx.get(key(r["PROTOCOL"], a, b), ()):
            d = abs(zeek[j]["ts"] - r["_start"])
            if j not in used and d <= bd:
                best, bd = j, d
        if best is not None:
            used.add(best)
            pairs.append((i, best))
    return pairs, used


def classify_unmatched(r: dict) -> str:
    pk = r["IN_PKTS"] + r["OUT_PKTS"]
    if r["PROTOCOL"] == 6:
        if not (r["CLIENT_TCP_FLAGS"] & SYN) and pk <= 2:
            return "tcp_tail_after_close(<=2 pkts, no SYN)"
        if not (r["CLIENT_TCP_FLAGS"] & SYN):
            return "tcp_no_syn_continuation"
        return "tcp_other"
    return {17: "udp", 1: "icmp", 58: "icmpv6"}.get(r["PROTOCOL"], f"proto_{r['PROTOCOL']}")


def rate(xs) -> float | None:
    xs = list(xs)
    return round(sum(xs) / len(xs), 4) if xs else None


def evaluate(pcap: Path, zeek: list[dict], cfg: dict, tol: float) -> dict:
    stats = ReadStats()
    ours = []
    for r in assemble_flows(read_packets(pcap, stats), **cfg):
        r = dict(r)
        r["_start"] = r["FLOW_START_MILLISECONDS"] / 1000.0  # ms-truncated start
        ours.append(r)
    pairs, used = match(ours, zeek, tol)
    m_ours = {i for i, _ in pairs}
    res = {
        "packets": {"read": stats.packets, "parsed": stats.parsed, "skipped": stats.skipped},
        "flows": {"ours": len(ours), "zeek": len(zeek), "matched": len(pairs),
                  "ours_by_proto": dict(Counter(r["PROTOCOL"] for r in ours)),
                  "zeek_by_proto": dict(Counter(z["proto"] for z in zeek)),
                  "match_rate_of_zeek": rate(j in used for j in range(len(zeek))),
                  "match_rate_of_ours": rate(i in m_ours for i in range(len(ours)))},
        "packets_in_flows": {"ours": sum(r["IN_PKTS"] + r["OUT_PKTS"] for r in ours),
                             "zeek": sum((z["opkts"] or 0) + (z["rpkts"] or 0) for z in zeek)},
    }  # fmt: skip
    agree = defaultdict(list)
    dur_err, mism = [], Counter()
    for i, j in pairs:
        r, z = ours[i], zeek[j]
        same_dir = (r["IPV4_SRC_ADDR"], r["L4_SRC_PORT"]) == z["a"] or (
            r["PROTOCOL"] in (1, 58) and r["IPV4_SRC_ADDR"] == z["a"][0])
        agree["direction"].append(same_dir)
        ip, op = (r["IN_PKTS"], r["OUT_PKTS"]) if same_dir else (r["OUT_PKTS"], r["IN_PKTS"])
        ib, ob = (r["IN_BYTES"], r["OUT_BYTES"]) if same_dir else (r["OUT_BYTES"], r["IN_BYTES"])
        agree["orig_pkts"].append(ip == z["opkts"])
        agree["resp_pkts"].append(op == z["rpkts"])
        agree["orig_ip_bytes"].append(ib == z["obytes"])
        agree["resp_ip_bytes"].append(ob == z["rbytes"])
        agree["total_pkts"].append(ip + op == (z["opkts"] or 0) + (z["rpkts"] or 0))
        zd = (z["dur"] or 0.0) * 1000.0
        dur_err.append(abs(r["FLOW_DURATION_MILLISECONDS"] - zd))
        agree["duration_within_1ms"].append(dur_err[-1] <= 1.0)
        agree["start_within_1ms"].append(abs(r["_start"] - z["ts"]) <= 1e-3)
        if r["PROTOCOL"] == 6:
            fl = r["CLIENT_TCP_FLAGS"] | r["SERVER_TCP_FLAGS"]
            both_fin = r["CLIENT_TCP_FLAGS"] & FIN and r["SERVER_TCP_FLAGS"] & FIN
            # Zeek keeps SF when the FIN handshake completed before a trailing RST
            ours_term = "fin_both" if both_fin else ("rst" if fl & RST else "open")
            zt = {"SF": "fin_both", "RSTO": "rst", "RSTR": "rst", "RSTOS0": "rst",
                  "RSTRH": "rst"}.get(z["state"], "open")  # fmt: skip
            agree["tcp_termination"].append(ours_term == zt)
            if ours_term != zt:
                mism[f"{z['state']}->ours:{ours_term}"] += 1
        if ip + op != (z["opkts"] or 0) + (z["rpkts"] or 0):
            mism[f"pktcount_{'tcp' if r['PROTOCOL'] == 6 else r['PROTOCOL']}"] += 1
    res["matched_agreement"] = {k: rate(v) for k, v in agree.items()}
    dur_err.sort()
    if dur_err:
        res["duration_abs_err_ms"] = {
            "median": round(dur_err[len(dur_err) // 2], 3),
            "p99": round(dur_err[int(0.99 * (len(dur_err) - 1))], 3), "max": round(dur_err[-1], 3)}
    res["mismatch_kinds"] = dict(mism.most_common(15))
    res["unmatched_ours"] = dict(Counter(classify_unmatched(ours[i]) for i in range(len(ours))
                                         if i not in m_ours).most_common())  # fmt: skip
    res["unmatched_zeek"] = dict(Counter(f"{z['proto']}:{z['state']}" for j, z in enumerate(zeek)
                                         if j not in used).most_common(12))  # fmt: skip
    # model-feature compatibility of the assembled records
    frame = records_to_frame([{k: v for k, v in r.items() if k != "_start"} for r in ours])
    num = [c for c, t in frame.schema.items() if t.is_numeric()]
    res["frame"] = {"rows": frame.height, "columns": frame.width,
                    "null_cells": int(sum(frame[c].null_count() for c in frame.columns)),
                    "nonfinite_cells": int(sum((~frame[c].cast(float).is_finite()).sum()
                                               for c in num)),
                    "negative_cells": int(sum((frame[c] < 0).sum() for c in num)),
                    "ts_min_ms": int(frame["flow_start_milliseconds"].min()),
                    "ts_max_ms": int(frame["flow_end_milliseconds"].max())}  # fmt: skip
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("conn_log", type=Path)
    ap.add_argument("--tol", type=float, default=0.002, help="start-time match tolerance (s)")
    ap.add_argument("--out", type=Path, default=Path("reports/audit/pcap_vs_zeek.json"))
    a = ap.parse_args()
    zeek = load_zeek(a.conn_log)
    zs = ZeekStats()
    n_reader = sum(1 for _ in read_conn_log(a.conn_log, zs))
    out = {"pcap": a.pcap.name, "conn_log": a.conn_log.name, "tolerance_s": a.tol,
           "zeek_reader": {"records": n_reader, "lines": zs.lines, "skipped": zs.skipped},
           "zeek_conn_states": dict(Counter(z["state"] for z in zeek).most_common()),
           "zeek_missed_bytes_conns": sum(1 for z in zeek if z["missed"]),
           "configs": {}}  # fmt: skip
    for name, cfg in CONFIGS.items():
        out["configs"][name] = evaluate(a.pcap, zeek, cfg, a.tol)
        print(name, json.dumps(out["configs"][name]["flows"]), flush=True)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
