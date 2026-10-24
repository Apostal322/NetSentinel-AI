"""Phase 8d, Mission 1 (POST-HOC sensitivity analysis on the consumed ToN_IoT input).

Record-level streaming equivalence audit on the same four ToN_IoT files:
  ref    - no streaming: every record goes to window END // 30 s, de-duplicated per window with
           the same key as WindowStream (DEDUP_KEY);
  old    - WindowStream as in the frozen run (resync disabled: the clock froze after the 460 h
           gap; lateness 3,700 s, buffer cap 1.5M, skew limit 1 h);
  fixed  - WindowStream with the Phase 8c clock re-synchronisation (resync_after = 1,000).
Per window: an order-independent fingerprint of its member records (count, sum and xor of the
record hashes), how the window was closed (watermark / forced by the buffer cap / final flush),
and the record index at which it closed. Reported: windows that differ in membership, the 334
forced closures, duplicates and late records.
Labels are not read. Usage: uv run python scripts/phase8d/stream_audit.py
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "phase8c"))
import toniot  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.live import DEDUP_KEY, END, WindowStream  # noqa: E402

FILES = [f"data/raw/toniot/Network_dataset_{i}.csv" for i in range(1, 5)]
OUT = Path("reports/phase8d/stream_audit.json")
W_MS = 30_000
MASK = (1 << 64) - 1


def rhash(rec: dict) -> int:
    return hash(tuple(rec.get(c) for c in DEDUP_KEY)) & MASK


def reference() -> dict[int, tuple[int, int, int]]:
    sets: dict[int, set] = defaultdict(set)
    dups = 0
    for rec in toniot.records(FILES):
        h = rhash(rec)
        s = sets[int(rec[END]) // W_MS]
        if h in s:
            dups += 1
        s.add(h)
    fp = {w: (len(s), sum(s) & MASK, _xor(s)) for w, s in sets.items()}
    fp[-1] = (dups, 0, 0)  # carried separately
    return fp


def _xor(s) -> int:
    x = 0
    for h in s:
        x ^= h
    return x


def stream(resync_after: int) -> tuple[dict, dict, dict]:
    ws = WindowStream(30, lateness_s=3700, max_buffer=1_500_000, max_skew_s=3600,
                      resync_after=resync_after)  # fmt: skip
    fp, how = {}, {}
    n = 0

    def record(closed, kind_for):
        for w, recs in closed:
            hs = [rhash(r) for r in recs]
            fp[w] = (len(hs), sum(hs) & MASK, _xor(hs))
            how[w] = (kind_for(w), n)

    for rec in toniot.records(FILES):
        n += 1
        before_wm = None
        closed = ws.push(rec)
        if closed:
            before_wm = ws.stats.watermark_ms
            record(
                closed, lambda w, wm=before_wm: "watermark" if (w + 1) * W_MS <= wm else "forced"
            )
    record(ws.flush(), lambda w: "flush")
    return fp, how, ws.stats.as_dict()


def compare(a: dict, b: dict) -> dict:
    keys = set(a) | set(b)
    keys.discard(-1)
    only_a = sorted(k for k in keys if k not in b)
    only_b = sorted(k for k in keys if k not in a)
    diff = sorted(k for k in keys if k in a and k in b and a[k] != b[k])
    return {"windows_a": len([k for k in a if k != -1]), "windows_b": len([k for k in b if k != -1]),
            "only_in_a": len(only_a), "only_in_b": len(only_b), "membership_differs": len(diff),
            "examples": (only_a + only_b + diff)[:10]}  # fmt: skip


def main() -> None:
    t0 = time.perf_counter()
    ref = reference()
    print("reference windows", len(ref) - 1, "duplicates", ref[-1][0], flush=True)
    old_fp, old_how, old_stats = stream(resync_after=10**15)
    print("old", old_stats, flush=True)
    new_fp, new_how, new_stats = stream(resync_after=1000)
    print("fixed", new_stats, flush=True)
    forced_old = sorted(w for w, (k, _) in old_how.items() if k == "forced")
    forced_new = sorted(w for w, (k, _) in new_how.items() if k == "forced")
    kinds = {name: {k: sum(1 for v in h.values() if v[0] == k) for k in ("watermark", "forced", "flush")}
             for name, h in (("old", old_how), ("fixed", new_how))}  # fmt: skip
    forced_detail = [{"win": w, "window_end_ms": (w + 1) * W_MS, "records": old_fp[w][0],
                      "same_as_reference": old_fp[w] == ref.get(w),
                      "same_as_fixed": old_fp[w] == new_fp.get(w),
                      "closed_by_fixed_as": new_how.get(w, ("missing",))[0]}
                     for w in forced_old]  # fmt: skip
    res = {"role": "post-hoc sensitivity analysis (consumed ToN_IoT input); labels not read",
           "reference_duplicates": ref[-1][0],
           "old_stats": old_stats, "fixed_stats": new_stats, "close_kinds": kinds,
           "old_vs_reference": compare(old_fp, ref), "fixed_vs_reference": compare(new_fp, ref),
           "old_vs_fixed": compare(old_fp, new_fp),
           "forced_closures_old": len(forced_old), "forced_closures_fixed": len(forced_new),
           "forced_windows_identical_to_reference": sum(d["same_as_reference"] for d in forced_detail),
           "forced_detail_first": forced_detail[:20],
           "meta": {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for k in ("close_kinds", "old_vs_reference", "fixed_vs_reference", "old_vs_fixed",
              "forced_closures_old", "forced_closures_fixed",
              "forced_windows_identical_to_reference", "meta"):  # fmt: skip
        print(k, res[k])


if __name__ == "__main__":
    main()
