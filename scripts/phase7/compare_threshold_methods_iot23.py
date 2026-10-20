"""Phase 7 P2: does cross-fitting (lower FPR) cost recall? EXPLORATORY on IoT-23 (inspected in
Phase 6). Same protocol as scripts/phase6/eval_iot23.py, robust-z only, split vs crossfit.

Usage: uv run python scripts/phase7/compare_threshold_methods_iot23.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase6"))
from common import evaluate  # noqa: E402
from eval_iot23 import is_attack  # noqa: E402

from netsentinel.streaming.offline import load_capture  # noqa: E402


def main() -> None:
    res = {}
    for f in sorted(Path("data/raw/iot23").glob("*/conn.log.labeled")):
        frame, _, _ = load_capture(f, "zeek", zeek_extras={"IS_ATTACK": is_attack})
        end = frame["flow_end_milliseconds"]
        mid = int(end.min() + (end.max() - end.min()) // 2)
        cal = frame.filter(pl.col("flow_end_milliseconds") < mid)
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        r = {}
        for m in ("split", "crossfit"):
            e = evaluate(cal, ev, with_iforest=False, threshold_method=m)
            r[m] = {v: {lv: {k: e[v].get(f"robustz_{lv}", {}).get(k)
                             for k in ("recall", "fpr", "attack_windows")}
                        for lv in ("global", "device", "service")}
                    for v in ("clean", "unlabelled") if isinstance(e.get(v), dict)}  # fmt: skip
        res[f.parent.name] = r
        print(f.parent.name, json.dumps(r, default=lambda x: round(x, 3)), flush=True)
    out = Path("reports/phase7/threshold_methods_iot23.json")
    out.write_text(json.dumps({"note": "exploratory; IoT-23 inspected in Phase 6", "scenarios": res},
                              indent=1, default=str), "utf-8")  # fmt: skip


if __name__ == "__main__":
    main()
