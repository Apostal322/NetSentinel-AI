"""Phase 6, IoT-23 labelled Zeek logs (never used before): H3 (device context), H4 (learned
model vs robust statistics), H5 (calibration under natural contamination).

Per scenario: calibration = flows ending in the first 50% of the time span, evaluation = the
rest. Variants: 'clean' (calibration restricted to flows the dataset labels Benign - an oracle
upper bound for vetted calibration) and 'unlabelled' (all calibration flows, true
contamination). Window 30 s, target FPR 0.01. Labels: dataset authors' per-flow labels.

Usage: uv run python scripts/phase6/eval_iot23.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import evaluate  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.offline import load_capture  # noqa: E402

OUT = Path("reports/phase6")


def is_attack(d: dict) -> float:
    lab = str(d.get("label", "")).lower()
    return 1.0 if lab.startswith("malicious") else 0.0


def main() -> None:
    t0 = time.perf_counter()
    res = {}
    for f in sorted(Path("data/raw/iot23").glob("*/conn.log.labeled")):
        name = f.parent.name
        frame, _, parse = load_capture(f, "zeek", zeek_extras={"IS_ATTACK": is_attack})
        if frame is None:
            continue
        end = frame["flow_end_milliseconds"]
        mid = int(end.min() + (end.max() - end.min()) // 2)
        cal = frame.filter(pl.col("flow_end_milliseconds") < mid)
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        r = evaluate(cal, ev)
        r["parse"] = parse
        res[name] = r
        brief = {v: {k: (m.get("recall"), m.get("fpr"), m.get("roc_auc"))
                     for k, m in r[v].items() if isinstance(m, dict)}
                 for v in ("clean", "unlabelled") if isinstance(r.get(v), dict)}  # fmt: skip
        print(name, f"cal_attack={r['cal_attack_share']:.3f} ev_attack={r['eval_attack_share']:.3f}",
              json.dumps(brief, default=lambda x: round(x, 3) if isinstance(x, float) else x),
              flush=True)  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    meta = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}
    (OUT / "iot23.json").write_text(json.dumps({"scenarios": res, "meta": meta}, indent=1,
                                               default=str), "utf-8")  # fmt: skip
    print(meta)


if __name__ == "__main__":
    main()
