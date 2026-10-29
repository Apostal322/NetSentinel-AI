"""Phase 8g post-hoc [R]: spill throughput of 9e526ca (eager flush, unshared keys) vs the
current code (lazy flush, shared keys) on the same real-data slice
(docs/phase8g/REAL_DATA_STREAMING_AUDIT.md, section 4). The audit runs of the two codes were
made at different times on a shared machine and differed by 2x; this replays one slice
through both, alternating, so the difference can be attributed.

Input: the first `--records` records of the scenario 9 arrival cache (stream_audit.py cache).
Usage: uv run python scripts/phase8g_post/spill_bench.py [--records N] [--repeats R]
"""

from __future__ import annotations

import argparse
import gc
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
POST = Path("data/derived/phase8g_post")
OUT = Path("reports/phase8g_post/spill_bench.json")
OLD_SHA = "9e526ca"


def old_module():
    path = POST / "_code" / f"live_{OLD_SHA}.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    src = subprocess.run(["git", "show", f"{OLD_SHA}:src/netsentinel/streaming/live.py"],
                         capture_output=True, text=True, check=True, cwd=ROOT).stdout  # fmt: skip
    path.write_text(src, "utf-8")
    spec = importlib.util.spec_from_file_location(f"live_{OLD_SHA}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def load(n: int) -> list[dict]:
    recs: list[dict] = []
    for part in sorted((POST / "scenario_9" / "arrival").glob("part_*.parquet")):
        recs += pl.read_parquet(part).drop("keyhash").to_dicts()
        if len(recs) >= n:
            break
    return recs[:n]


def one(mod, recs: list[dict], max_buffer: int, max_spill: int) -> dict:
    gc.collect()
    ws = mod.WindowStream(30, lateness_s=3700, max_buffer=max_buffer, max_spill=max_spill)
    take = [0.0, 0]
    real = ws.spill.take

    def timed(*a, **k):
        t = time.perf_counter()
        r = real(*a, **k)
        take[0] += time.perf_counter() - t
        take[1] += 1
        return r

    ws.spill.take = timed
    n_out = 0
    t0 = time.perf_counter()
    for r in recs:
        for _, rs in ws.push(r):
            n_out += len(rs)
    t_push = time.perf_counter() - t0
    flush = getattr(ws, "flush_iter", ws.flush)
    for _, rs in flush():
        n_out += len(rs)
    total = time.perf_counter() - t0
    st = ws.stats
    return {"total_s": total, "push_s": t_push, "flush_s": total - t_push, "take_s": take[0],
            "takes": take[1], "records_per_s": len(recs) / total, "emitted": n_out,
            "spilled_windows": st.spilled_windows, "late": st.late,
            "forced_closes": st.forced_closes}  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=500_000)
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--max-buffer", type=int, default=20_000)
    ap.add_argument("--max-spill", type=int, default=2_000_000)
    a = ap.parse_args()
    from netsentinel.streaming import live

    codes = {OLD_SHA: old_module(), "current": live}
    recs = load(a.records)
    runs = {c: [] for c in codes}
    for _ in range(a.repeats):  # alternate, so drift in machine load hits both codes
        for c, mod in codes.items():
            runs[c].append(one(mod, recs, a.max_buffer, a.max_spill))
            print(c, json.dumps(runs[c][-1]))
    out = {"label": "[R] engineering micro-benchmark on consumed CTU-13 scenario 9 data",
           "records": len(recs), "max_buffer": a.max_buffer, "max_spill": a.max_spill,
           "runs": runs}  # fmt: skip
    OUT.write_text(json.dumps(out, indent=1), "utf-8")


if __name__ == "__main__":
    main()
