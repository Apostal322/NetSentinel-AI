"""Phase 8q Experiment B: where does the calibration-label dependency come from? Saved scores only
(Phase 8o F0 = Phase 8p S0; 6 fits; K = 5); no model fitted.

**P1x uses calibration-period attacker identities in two places:**
1. **Threshold population:** attacker windows are removed from the T0 hold-out.
2. **Shared feature state:** the destination memory behind `new_dst_frac` excludes the attackers'
   destinations. It is used by the hold-out windows AND, frozen at the midpoint, by every
   evaluation window.

The saved scores hold each window under both memories:
- P1x: `s_hold`, `s_ev`;
- unlabelled, attackers kept: `s_hold_u`, `s_ev_u`.

That allows single-factor steps:

| cell | threshold from | evaluation scores |
|---|---|---|
| U (C1) | unlabelled hold-out, attackers included | unlabelled memory |
| T (C4: threshold-only exclusion) | unlabelled hold-out without attacker windows | unlabelled memory |
| TE | unlabelled hold-out without attacker windows | P1x memory |
| P (C0) | P1x hold-out (attackers excluded; P1x memory) | P1x memory |
| UE (C3-like: state-only exclusion at evaluation) | unlabelled hold-out, attackers included | P1x memory |

**Path 1:** U → T (threshold contamination removed) → TE (evaluation memory cleaned) → P
(hold-out memory cleaned).

**Path 2:** U → UE (evaluation memory cleaned) → TE (threshold contamination removed) → P.

TE and UE mix a threshold from unlabelled-memory hold-out scores with P1x-memory evaluation
scores. That mixing is the counterfactual itself, and it is stated.

The attacker identities used to build T and TE are the oracle calibration labels: used only to
construct the counterfactual, never in a candidate.

Output: reports/phase8q/calibration_decomposition.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8q/calibration_decomposition.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8q_bm", ROOT / "scripts/phase8q/benchmark_metrics.py"
)
BM = importlib.util.module_from_spec(_spec)
sys.modules["phase8q_bm"] = BM
_spec.loader.exec_module(BM)

I8 = ROOT / "data" / "derived" / "phase8i"
P1X = ROOT / "data" / "derived" / "phase8j" / "p1x"
OUT = ROOT / "reports" / "phase8q" / "calibration_decomposition.json"
FITS = [(g, r) for g in ("base", "stress") for r in (6, 7, 8)]
V2 = BM.LA.VIEWS["V2_documented_attackers"]
HOUR_MS = 3_600_000


def hold_frame(path: Path) -> pl.DataFrame:
    """Hold-out rows (last 30 % of calibration slots) in the scoring order (sorted by win, key)."""
    cal = pl.read_parquet(path, columns=["key", "win", "window_end_ms"]).sort("win", "key")
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    return cal.filter(pl.col("win") >= lo + int(math.floor((hi - lo + 1) * 0.7)))


def calibration_attackers(name: str) -> set[str]:
    net, dom = name.split("/")
    p = I8 / net / dom / "cal_truth.parquet"
    return set(pl.read_parquet(p).filter(pl.col("y"))["key"].to_list()) if p.exists() else set()


def cell(
    alert: np.ndarray, pos: np.ndarray, neg: np.ndarray, key: np.ndarray, hours: float
) -> dict:
    return BM.view_metrics(alert, key, pos, neg, hours)


def main() -> None:
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    cells = ("U", "T", "TE", "P", "UE")
    per_cell = {c: {} for c in cells}
    diag = {}
    for name in names:
        net, dom = name.split("/")
        a = pl.read_parquet(BM.AUDIT / f"{name.replace('/', '__')}.parquet")
        cat, key = a["category"].to_numpy().astype(str), a["key"].to_numpy().astype(str)
        pos, neg = np.isin(cat, V2), np.isin(cat, BM.BENIGN)
        hours = float(np.load(BM.B0 / f"{name.replace('/', '__')}__seed0.npz")["hours"])
        hu = hold_frame(I8 / net / dom / "cal_unlabelled.parquet")
        hp = hold_frame(P1X / net / dom / "cal_p1x.parquet")
        att = calibration_attackers(name)
        is_att = np.isin(hu["key"].to_numpy().astype(str), np.array(sorted(att), dtype=str))
        # the P1x hold-out must be exactly the non-attacker rows of the unlabelled hold-out
        if not hu.filter(pl.Series(~is_att)).select("key", "win").equals(hp.select("key", "win")):
            raise RuntimeError(f"{name}: P1x hold-out is not the non-attacker unlabelled hold-out")
        d = {"calibration_attackers": len(att), "hold_u_windows": hu.height, "hold_p1x_windows": hp.height,
             "attacker_hold_windows": int(is_att.sum()), "attacker_hold_share": round(float(is_att.mean()), 4),
             "fits": {}}  # fmt: skip
        for regime, r in FITS:
            z = np.load(BM.O8 / regime / f"{name.replace('/', '__')}__r{r}.npz")
            s_hold, s_ev = z["s_hold"].mean(0), z["s_ev"].mean(0)
            s_hold_u, s_ev_u = z["s_hold_u"].mean(0), z["s_ev_u"].mean(0)
            if s_hold_u.size != hu.height or s_hold.size != hp.height:
                raise RuntimeError(f"{name}: hold-out rows and scores differ")
            t_u, t_p = BM.t0_of(s_hold_u), BM.t0_of(s_hold)
            t_t = BM.t0_of(s_hold_u[~is_att]) if (~is_att).any() else math.inf
            thr = {
                "U": (t_u, s_ev_u),
                "T": (t_t, s_ev_u),
                "TE": (t_t, s_ev),
                "P": (t_p, s_ev),
                "UE": (t_u, s_ev),
            }
            for c, (t, sev) in thr.items():
                per_cell[c].setdefault((regime, r), {})[name] = cell(sev > t, pos, neg, key, hours)
            q99_att = float(np.quantile(s_hold_u[is_att], 0.99)) if is_att.any() else None
            d["fits"][f"{regime}_r{r}"] = {"t0": {"U": t_u, "T": t_t, "P": t_p},
                                           "attacker_hold_above_P_t0": int((s_hold_u[is_att] > t_p).sum()),
                                           "attacker_hold_q99": q99_att,
                                           "doc_attack_score_median_unlabelled_vs_p1x":
                                           [float(np.median(s_ev_u[pos])) if pos.any() else None,
                                            float(np.median(s_ev[pos])) if pos.any() else None]}  # fmt: skip
        diag[name] = d
    summ = {c: BM.summarise(f) for c, f in per_cell.items()}
    res: dict = {"status": "Experiment B decomposition (saved scores; oracle labels used only to build counterfactual cells)",
                 "view": "V2_documented_attackers vs historical benign", "cells": {}, "diagnostics": diag}  # fmt: skip
    for c, s in summ.items():
        res["cells"][c] = {"macro_recall": s["macro_recall"], "R20": s["R"]["20"] if "20" in s["R"] else s["R"][20],
                           "networks": {n: {k: s["networks"][n][k] for k in ("recall", "fpr", "false_alerts")} for n in BM.NETWORKS}}  # fmt: skip
    m = {c: res["cells"][c]["macro_recall"] for c in cells}
    res["path1"] = {"threshold_contamination": m["T"] - m["U"], "evaluation_memory": m["TE"] - m["T"],
                    "holdout_memory": m["P"] - m["TE"], "total": m["P"] - m["U"]}  # fmt: skip
    res["path2"] = {"evaluation_memory": m["UE"] - m["U"], "threshold_contamination": m["TE"] - m["UE"],
                    "holdout_memory": m["P"] - m["TE"], "total": m["P"] - m["U"]}  # fmt: skip
    per_net = {}
    for n in BM.NETWORKS:
        g = {c: res["cells"][c]["networks"][n]["recall"] for c in cells}
        if None in g.values():
            continue
        per_net[n] = {"path1": {"threshold": g["T"] - g["U"], "eval_memory": g["TE"] - g["T"], "hold_memory": g["P"] - g["TE"]},
                      "path2": {"eval_memory": g["UE"] - g["U"], "threshold": g["TE"] - g["UE"], "hold_memory": g["P"] - g["TE"]},
                      "total": g["P"] - g["U"]}  # fmt: skip
    res["per_network"] = per_net
    per_dom = {}
    for name in names:
        rec = {c: float(np.mean([per_cell[c][k][name]["recall"] for k in per_cell[c]
                                 if per_cell[c][k][name]["recall"] is not None] or [np.nan])) for c in cells}  # fmt: skip
        per_dom[name] = {c: round(v, 4) for c, v in rec.items()}
    res["per_domain_recall"] = per_dom
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    for c in cells:
        print(
            c,
            round(m[c], 3),
            {
                n: (round(v["recall"] or 0, 3), round(v["fpr"] or 0, 4))
                for n, v in res["cells"][c]["networks"].items()
            },
        )
    print("path1", {k: round(v, 3) for k, v in res["path1"].items()})
    print("path2", {k: round(v, 3) for k, v in res["path2"].items()})


if __name__ == "__main__":
    main()
