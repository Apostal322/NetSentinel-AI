"""Phase 8f M4: adversarial timestamp scenarios near the WindowStream decision boundaries
(synthetic, defensive test inputs; extends scripts/phase8e/stream_robustness.py).

* forged future share of 85 / 89 / 90 / 91 / 95% sustained over a period (trigger = 90%);
* a share oscillating around the trigger (88% <-> 92%);
* five anomaly cycles followed by clean traffic (recovery);
* a long sustained 89% stream (quarantine memory bound);
* the same near the BACKWARD boundary;
* in-skew forgery: timestamps just inside max_skew (accepted as in range) that pull the
  watermark ahead of genuine traffic.
Metrics as in Phase 8e: genuine records lost, windows differing from the genuine-only reference,
forged records emitted, peak records held, health flags.
Usage: uv run python scripts/phase8f/stream_near_trigger.py -> reports/phase8f/stream_near_trigger.json
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "stream_robustness", ROOT / "scripts/phase8e/stream_robustness.py"
)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

DAY = sr.DAY
OUT = Path("reports/phase8f/stream_near_trigger.json")


def mix(genuine: list[dict], share: float, t_forged, port0: int) -> list[dict]:
    """Interleave forged records so that they form `share` of the mixed records."""
    out, debt, j = [], 0.0, 0
    ratio = share / (1 - share)
    for r in genuine:
        out.append(r)
        debt += ratio
        while debt >= 1:
            out.append(sr.rec(t_forged(j), "10.0.0.66", port0 + j, genuine=False))
            j += 1
            debt -= 1
    return out


def scenarios() -> dict[str, list[dict]]:
    g = sr.genuine_stream(0, 3600)  # 10,800 genuine records over 1 h
    sc: dict[str, list[dict]] = {}
    for share in (0.85, 0.89, 0.90, 0.91, 0.95):
        # forged share sustained over 20 min of the hour, future timestamps 30 days ahead
        sc[f"future_share_{int(share * 100)}"] = (
            g[:1800] + mix(g[1800:5400], share, lambda j: 30 * DAY + j, 10**7) + g[5400:]
        )
    osc, port = list(g[:900]), 2 * 10**7
    for i in range(10):  # 10 alternations of 88% / 92% over 300 genuine records each
        part = g[900 + i * 300 : 900 + (i + 1) * 300]
        share = 0.88 if i % 2 == 0 else 0.92
        osc += mix(part, share, lambda j, p=port: 30 * DAY + p + j, port)
        port += 100_000
    osc += g[3900:]
    sc["oscillating_88_92"] = osc
    cyc, port = list(g[:600]), 3 * 10**7
    for i in range(5):  # 5 cycles: 92% forged for 300 genuine records, then 1,500 clean
        base = 600 + i * 1800
        cyc += mix(g[base : base + 300], 0.92, lambda j, i=i: (40 + i) * DAY + j, port)
        cyc += g[base + 300 : base + 1800]
        port += 100_000
    cyc += g[600 + 5 * 1800 :]
    sc["repeated_cycles_then_clean"] = cyc
    long = sr.genuine_stream(0, 4 * 3600)  # 4 h, 89% forged throughout the middle 3 h
    sc["sustained_89_long"] = (long[:5400] + mix(long[5400:5400 + 32_400], 0.89,
                                                  lambda j: 30 * DAY + j, 4 * 10**7)
                               + long[5400 + 32_400:])  # fmt: skip
    gd = sr.genuine_stream(DAY, 3600)  # genuine at day 1; forged one day BEHIND
    sc["backward_share_89"] = (
        gd[:1800] + mix(gd[1800:5400], 0.89, lambda j: j, 5 * 10**7) + gd[5400:]
    )
    sc["backward_share_95"] = (
        gd[:1800] + mix(gd[1800:5400], 0.95, lambda j: j, 6 * 10**7) + gd[5400:]
    )
    # in-skew forgery: a small share of records stamped 3,500 s ahead of the CURRENT genuine time
    # (inside max_skew_s = 3,600), i.e. accepted as in range
    insk = []
    for i, r in enumerate(g):
        insk.append(r)
        if 1800 <= i < 5400 and i % 50 == 0:  # 2% of records
            insk.append(sr.rec(r[sr.START] + 3_500_000, "10.0.0.66", 7 * 10**7 + i, genuine=False))
    sc["in_skew_future_2pct"] = insk
    one = list(g)
    one.insert(1800, sr.rec(g[1800][sr.START] + 3_500_000, "10.0.0.66", 8 * 10**7, genuine=False))
    sc["in_skew_single_record"] = one
    return sc


def run_all() -> dict:
    return {name: sr.run(recs) for name, recs in scenarios().items()}


def main() -> None:
    res = run_all()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for name, r in res.items():
        st = r["stats"]
        print(f"{name:28s} lost={r['genuine_lost']:6d}/{r['genuine_records']} "
              f"differing={r['windows_differing']:4d} forged_emitted={r['forged_emitted']:6d} "
              f"peak={r['peak_held']:6d} health={r['health']} flags={r['health_flags']} "
              f"late={st.get('late')} rejected={st.get('quarantine_rejected')} "
              f"evicted={st.get('quarantine_evicted')} reverts={st.get('clock_reverts')}")  # fmt: skip


if __name__ == "__main__":
    main()
