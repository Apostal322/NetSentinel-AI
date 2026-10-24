"""Phase 8e, Mission 2: deterministic adversarial scenarios for the streaming watermark logic.

Each scenario interleaves GENUINE records (1 record/s per host, 3 hosts, 30 s windows) with
anomalies. Every record carries a `genuine` tag (ignored by the stream) so the harness can
compare the emitted windows with a reference built from the genuine records alone:
* genuine_lost        genuine records not in any emitted window (late, quarantine-dropped, ...)
* windows_differing   reference windows whose emitted genuine membership differs
* forged_emitted      anomalous records that reached an emitted window (integrity leak)
* peak_held           max records held (buffer + quarantine): memory bound
* recovery_records    genuine records after the LAST anomaly until the last genuine loss
* health              the stream's reported health flags
Usage: uv run python scripts/phase8e/stream_robustness.py [--json OUT]
Also imported by tests/integration/test_stream_robustness.py.
"""

from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from netsentinel.streaming.live import END, START, WindowStream

W_MS, HOSTS = 30_000, ("10.0.0.1", "10.0.0.2", "10.0.0.3")
DAY = 86_400_000


def rec(t, host, port, genuine=True, dur=5):
    return {START: t, END: t + dur, "IPV4_SRC_ADDR": host, "IPV4_DST_ADDR": "10.0.9.9",
            "L4_SRC_PORT": port, "L4_DST_PORT": 443, "PROTOCOL": 6, "IN_BYTES": 100,
            "OUT_BYTES": 200, "_genuine": genuine}  # fmt: skip


def genuine_stream(t0, seconds, port0=0):
    out = []
    for s in range(seconds):
        for h_i, h in enumerate(HOSTS):
            out.append(rec(t0 + s * 1000 + h_i * 7, h, port0 + s * 3 + h_i))
    return out


def forged(t, n, port0=900_000, step=1):
    return [rec(t + i * step, "10.0.0.66", port0 + i, genuine=False) for i in range(n)]


def scenarios() -> dict[str, list[dict]]:
    sc: dict[str, list[dict]] = {}
    g = genuine_stream(0, 3600)
    sc["baseline"] = g
    # single forged burst of 1,000 records 30 days ahead after 30 min
    sc["single_future_burst"] = g[:5400] + forged(30 * DAY, 1000) + g[5400:]
    # 5 bursts, 10 min apart
    s = []
    for i in range(6):
        s += g[i * 1800 : (i + 1) * 1800]
        if i < 5:
            s += forged((30 + i) * DAY, 1000, port0=900_000 + i * 10_000)
    sc["repeated_future_bursts"] = s
    # alternating valid / invalid timestamps (every genuine record followed by a forged one)
    alt = []
    for i, r in enumerate(g):
        alt.append(r)
        alt.append(rec(30 * DAY + i, "10.0.0.66", 800_000 + i, genuine=False))
    sc["alternating_valid_invalid"] = alt
    # long idle period (8 h without traffic), then traffic resumes (genuine gap)
    sc["long_idle_gap"] = genuine_stream(0, 1800) + genuine_stream(8 * 3600_000, 1800, port0=10**6)
    # backward clock reset: after 30 min the sensor clock jumps back by one day
    sc["clock_reset_backward"] = genuine_stream(DAY, 1800) + genuine_stream(0, 1800, port0=10**6)
    # out-of-order within lateness (+/- 20 s) and 5% duplicates
    rng = random.Random(7)
    j = sorted(g, key=lambda r: r[START] + rng.uniform(-20_000, 20_000))
    dup = []
    for r in j:
        dup.append(r)
        if rng.random() < 0.05:
            dup.append(dict(r))
    sc["out_of_order_and_duplicates"] = dup
    # repeated resync attempts to DIFFERENT future times, each 1,000 records
    rr = list(g[:1800])
    for k in range(4):
        rr += forged((10 + k) * DAY, 1000, port0=700_000 + k * 10_000)
        rr += g[1800 + k * 900 : 1800 + (k + 1) * 900]
    rr += g[1800 + 4 * 900 :]
    sc["repeated_resync_attempts"] = rr
    # forged flood DOMINATING the stream: 10 forged records per genuine record for 20 min
    fl = list(g[:1800])
    for i, r in enumerate(g[1800:5400]):
        fl.append(r)
        fl += forged(30 * DAY + i * 10, 10, port0=10**7 + i * 10)
    fl += g[5400:]
    sc["forged_flood_dominant"] = fl
    return sc


SPECIAL = {"buffer_exhaustion": ("baseline", {"max_buffer": 100})}


def run(records: list[dict], **kw) -> dict:
    params = {"window_s": 30, "lateness_s": 60, "max_buffer": 50_000, "max_skew_s": 3600,
              "resync_after": 1000} | kw  # fmt: skip
    ws = WindowStream(**params)
    emitted: dict[int, set] = defaultdict(set)
    forged_emitted = 0
    peak = 0
    last_anomaly = max((i for i, r in enumerate(records) if not r["_genuine"]), default=-1)
    lost_index = []
    seen_genuine = set()
    for i, r in enumerate(records):
        closed = ws.push(r)
        for w, rs in closed:
            for x in rs:
                if x["_genuine"]:
                    emitted[w].add((x[START], x["IPV4_SRC_ADDR"], x["L4_SRC_PORT"]))
                else:
                    forged_emitted += 1
        held = ws.n_buffered + len(getattr(ws, "quarantine", ()) or ())
        peak = max(peak, held)
        if r["_genuine"]:
            seen_genuine.add(i)
    for w, rs in ws.flush():
        for x in rs:
            if x["_genuine"]:
                emitted[w].add((x[START], x["IPV4_SRC_ADDR"], x["L4_SRC_PORT"]))
            else:
                forged_emitted += 1
    ref: dict[int, set] = defaultdict(set)
    for r in records:
        if r["_genuine"]:
            ref[r[END] // W_MS].add((r[START], r["IPV4_SRC_ADDR"], r["L4_SRC_PORT"]))
    in_emitted = set().union(*emitted.values()) if emitted else set()
    genuine_keys = [(i, (r[START], r["IPV4_SRC_ADDR"], r["L4_SRC_PORT"])) for i, r in enumerate(records)
                    if r["_genuine"]]  # fmt: skip
    lost = [i for i, k in genuine_keys if k not in in_emitted]
    lost_index = lost
    n_genuine = len({k for _, k in genuine_keys})
    differing = sum(1 for w in ref if emitted.get(w, set()) != ref[w])
    st = ws.stats.as_dict()
    after = [i for i in lost_index if i > last_anomaly]
    return {"genuine_records": n_genuine, "genuine_lost": len(set(k for i, k in genuine_keys if i in set(lost))),
            "windows_reference": len(ref), "windows_differing": differing,
            "forged_emitted": forged_emitted, "peak_held": peak,
            "recovery_records": (max(after) - last_anomaly) if after else 0,
            "health": st.get("health"), "health_flags": st.get("health_flags"),
            "stats": {k: st[k] for k in st if k not in ("health", "health_flags")}}  # fmt: skip


def run_all() -> dict:
    sc = scenarios()
    res = {name: run(recs) for name, recs in sc.items()}
    for name, (base, kw) in SPECIAL.items():
        res[name] = run(sc[base], **kw)
    return res


def main() -> None:
    res = run_all()
    for name, r in res.items():
        print(f"{name:28s} lost={r['genuine_lost']:6d}/{r['genuine_records']} differing="
              f"{r['windows_differing']:4d}/{r['windows_reference']} forged_emitted={r['forged_emitted']:5d} "
              f"peak={r['peak_held']:6d} recovery={r['recovery_records']:6d} health={r['health']} {r['health_flags']}")  # fmt: skip
    if "--json" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--json") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, indent=1, default=str), "utf-8")


if __name__ == "__main__":
    main()
