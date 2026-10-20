"""Phase 8 (development data): how late do Zeek conn.log records arrive relative to the
streaming watermark clock (largest flow START seen so far)? For each record:
lateness = max(0, clock_before_record - flow_end). A record is dropped as late by
`WindowStream` iff its window closed, i.e. (roughly) lateness > allowed lateness.

Usage: uv run python scripts/phase8/zeek_lateness.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from netsentinel.telemetry.zeek import read_conn_log

OUT = Path("reports/phase8/zeek_lateness.json")


def main() -> None:
    files = [*sorted(Path("data/raw/iot23").glob("*/conn.log.labeled")),
             *sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log")),
             Path("data/raw/ctu_normal_26/bro/conn.log")]  # fmt: skip
    res = {}
    for f in files:
        if not f.exists():
            continue
        clock, late = None, []
        for r in read_conn_log(f):
            s, e = r["FLOW_START_MILLISECONDS"], r["FLOW_END_MILLISECONDS"]
            if clock is not None:
                late.append(max(0, clock - e))
            clock = s if clock is None else max(clock, s)
        a = np.array(late) / 1000
        name = f.parent.name if f.parent.name != "bro" else "CTU-Normal-26"
        res[name] = {"records": len(a) + 1,
                     **{f"share_late_over_{t}s": float((a > t).mean()) for t in (60, 600, 3600)},
                     "p99_s": float(np.quantile(a, 0.99)), "p999_s": float(np.quantile(a, 0.999)),
                     "max_s": float(a.max())}  # fmt: skip
        print(name, res[name], flush=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")


if __name__ == "__main__":
    main()
