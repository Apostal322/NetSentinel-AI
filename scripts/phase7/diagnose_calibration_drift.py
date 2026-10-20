"""Phase 7 P2: why did calibrated FPRs exceed their target in Phase 6 (H1)? EXPLORATORY.

Data: the same benign CTU captures as Phase 6 H1 (already inspected - this is diagnosis, not
confirmatory evaluation). Per capture, global level, window 30 s, target 0.01:
* held-out size n and the threshold's sampling bound (threshold_diagnostics);
* realised evaluation FPR (second half of the capture);
* score drift between calibration held-out scores and evaluation scores (KS);
* the drift monitor's verdict on the evaluation period;
for split thresholds (Phase 6) and time-blocked cross-fitted thresholds (Phase 7 default).

Usage: uv run python scripts/phase7/diagnose_calibration_drift.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.behavior.calibrate import calibrate_flows
from netsentinel.behavior.monitor import _ks, baseline_state, score_flows
from netsentinel.streaming.offline import load_capture

TARGET = 0.01


def captures() -> list[Path]:
    return [Path("data/raw/ctu_normal_26/bro/conn.log"),
            *sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log"))]  # fmt: skip


def main() -> None:
    rows = []
    for cap in captures():
        name = cap.parent.name if cap.parent.name != "bro" else "CTU-Normal-26"
        frame, _, _ = load_capture(cap, "zeek")
        end = frame["flow_end_milliseconds"]
        mid = int(end.min() + (end.max() - end.min()) // 2)
        cal = frame.filter(pl.col("flow_end_milliseconds") < mid)
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        rec = {"capture": name}
        for method in ("split", "crossfit"):
            prof = calibrate_flows(cal, window_s=30, target_fpr=TARGET, threshold_method=method)
            rec[f"{method}_status"] = prof.status
            if "global" not in prof.levels:
                continue
            g = prof.levels["global"]
            s = score_flows(prof, ev).filter(pl.col("level") == "global")
            st = baseline_state(prof, s)
            rec[method] = {
                "holdout_n": g.n_holdout_windows,
                "fpr_upper95_sampling": g.threshold_diag.get("fpr_upper95"),
                "eval_fpr": float(s["anomalous"].mean()),
                "eval_windows": s.height,
                "score_ks_cal_vs_eval": _ks(g.holdout_scores, s["score"].to_numpy()),
                "drift_state": st["state"],
            }  # fmt: skip
        rows.append(rec)
        print(name, json.dumps({k: v for k, v in rec.items() if k != "capture"},
                               default=lambda x: round(x, 4)), flush=True)  # fmt: skip
    summ = {}
    for method in ("split", "crossfit"):
        r = [x[method] for x in rows if method in x]
        f = np.array([x["eval_fpr"] for x in r])
        ub = np.array([x["fpr_upper95_sampling"] for x in r])
        ks = np.array([x["score_ks_cal_vs_eval"] for x in r])
        summ[method] = {
            "captures": len(r), "median_eval_fpr": float(np.median(f)),
            "share_fpr_le_3x": float((f <= 3 * TARGET).mean()),
            "share_fpr_within_sampling_bound": float((f <= ub).mean()),
            "median_holdout_n": float(np.median([x["holdout_n"] for x in r])),
            "corr_fpr_vs_ks": float(np.corrcoef(f, ks)[0, 1]) if len(f) > 2 else None,
            "drift_flagged_when_fpr_gt_3x": [x["drift_state"] for x in r
                                             if x["eval_fpr"] > 3 * TARGET],
        }  # fmt: skip
    out = Path("reports/phase7/calibration_drift.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"note": "exploratory (CTU captures already inspected in Phase 6)",
                               "captures": rows, "summary": summ}, indent=1, default=str),
                   "utf-8")  # fmt: skip
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
