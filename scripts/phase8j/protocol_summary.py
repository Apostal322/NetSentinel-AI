"""Phase 8j [E]: the calibration protocols side by side, seeds 0-2, at the T0 threshold.

P0 / P1 / P1u / P2 / P3 come from leakage_audit.py (+ leakage_p1u.py) for each seed; P1x from
the dev_scores.py files (T0 on the P1x hold-out). Per domain: the mean over seeds of the
realised FPR on verified-benign windows, window recall and ROC-AUC (attack vs verified benign).
Answers the question the independent review left open: does purging known calibration attackers
from the destination memory (P1x) recover the recall that P1u lost?

Output: reports/phase8j/protocol_summary.json
Usage: uv run python scripts/phase8j/protocol_summary.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leakage_audit as LA  # noqa: E402, N812
import threshold_stats as TS  # noqa: E402, N812

SEEDS = (0, 1, 2)
DEV = Path("data/derived/phase8j/dev")
PROTOCOLS = ("P0_oracle", "P1_past", "P1u_past_unlabelled", "P1x", "P2_none", "P3_screen")


def p1x(name: str, seed: int) -> dict:
    from sklearn.metrics import roc_auc_score

    z = np.load(DEV / f"{name.replace('/', '__')}__seed{seed}.npz")
    hold = np.sort(z["cal_s"][z["cal_hold"]])
    thr = hold[TS.k_of(len(hold)) - 1]
    a, y, ben = z["ev_s"] > thr, z["ev_y"], z["ev_benign"]
    lab = np.r_[np.ones(y.sum()), np.zeros(ben.sum())]
    return {"fpr": float(a[ben].mean()), "window_recall": float(a[y].mean()),
            "roc_auc": float(roc_auc_score(lab, np.r_[z["ev_s"][y], z["ev_s"][ben]]))}  # fmt: skip


def main() -> None:
    runs = {k: json.loads(LA.out_path(k).read_text("utf-8"))["domains"] for k in SEEDS}
    out = {}
    for name in runs[0]:
        row = {}
        for p in PROTOCOLS:
            vals = [p1x(name, k) if p == "P1x" else runs[k][name]["protocols"][p] for k in SEEDS]
            row[p] = {
                m: float(np.mean([v[m] for v in vals])) for m in ("fpr", "window_recall", "roc_auc")
            }
            row[p]["fpr_seeds"] = [round(v["fpr"], 4) for v in vals]
        out[name] = row
        print(name, {p: (round(v["fpr"], 4), round(v["window_recall"], 3)) for p, v in row.items()})
    Path("reports/phase8j/protocol_summary.json").write_text(json.dumps(out, indent=1), "utf-8")


if __name__ == "__main__":
    main()
