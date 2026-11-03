"""Phase 8n Experiment A analysis (docs/phase8n/PREREGISTRATION.md, Experiment A). No model is
fitted here; everything comes from the saved scores of scripts/phase8n/fragility.py and the
window labels of the Phase 8j B0 files.

Per perturbation, domain and replicate: T0 (conformal rank, alpha = 1 %, P1x hold-out), window
recall, verified-benign FPR and false alerts, ROC AUC (attack vs verified benign), ranking recall
at the benign 99th percentile (an oracle quantity, reported only to separate ranking from
threshold effects), entity recall and undetected entities (entities = sources with >= 5 attack
windows), and the Spearman correlation of the evaluation scores with P_ref of the same replicate.

Registered definitions:
- catastrophic failure: on one domain and replicate, window recall falls by >= 0.5 (absolute)
  against P_ref of the same replicate, or an entity that P_ref detects in that replicate is not
  detected at all;
- mechanism of a catastrophic window-recall failure: "ranking" if the ranking recall at the
  benign 99th percentile also falls by >= 0.5, otherwise "threshold".

Output: reports/phase8n/fragility_analysis.json
Usage: python scripts/phase8n/analyze_fragility.py
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np
from scipy.stats import rankdata, spearmanr

ROOT = Path(__file__).resolve().parents[2]
FRAG = ROOT / "data" / "derived" / "phase8n" / "fragility"
B0_DIR = ROOT / "data" / "derived" / "phase8j" / "dev"
OUT = ROOT / "reports" / "phase8n" / "fragility_analysis.json"
ALPHA = 0.01
MIN_ENTITY_WINDOWS = 5
CAT_DROP = 0.5
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
FOCUS = ("nfcic/2018-02-14", "nfcic/2018-02-16", "nfcic/2018-02-21")


def k_of(n: int) -> int:
    return min(math.ceil((n + 1) * (1 - ALPHA)), n)


def auc(pos: np.ndarray, neg: np.ndarray) -> float | None:
    if not len(pos) or not len(neg):
        return None
    r = rankdata(np.concatenate([pos, neg]))
    return float((r[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


class Labels:
    def __init__(self, name: str):
        z = np.load(B0_DIR / f"{name.replace('/', '__')}__seed0.npz")
        self.key, self.end = z["ev_key"].astype(str), z["ev_end"]
        self.y, self.benign = z["ev_y"].astype(bool), z["ev_benign"].astype(bool)
        counts: dict[str, int] = {}
        for k in self.key[self.y]:
            counts[k] = counts.get(k, 0) + 1
        self.entities = sorted(k for k, c in counts.items() if c >= MIN_ENTITY_WINDOWS)
        self.masks = {e: self.y & (self.key == e) for e in self.entities}


def metrics(lab: Labels, s_hold: np.ndarray, s_ev: np.ndarray) -> dict:
    t0 = float(np.sort(s_hold)[k_of(s_hold.size) - 1])
    alert = s_ev > t0
    y, ben = lab.y, lab.benign
    q99 = float(np.quantile(s_ev[ben], 1 - ALPHA)) if ben.any() else math.inf
    detected = {e: bool((alert & m).any()) for e, m in lab.masks.items()}
    delays = [float(lab.end[alert & m].min() - lab.end[m].min()) / 1000
              for e, m in lab.masks.items() if detected[e]]  # fmt: skip
    return {"t0": t0, "fpr": float(alert[ben].mean()) if ben.any() else None,
            "false_alerts": int(alert[ben].sum()),
            "window_recall": float(alert[y].mean()) if y.any() else None,
            "ranking_recall_at_benign_q99": float((s_ev[y] > q99).mean()) if y.any() else None,
            "auc": auc(s_ev[y], s_ev[ben]), "entities": len(lab.entities),
            "entities_detected": int(sum(detected.values())), "detected": detected,
            "median_delay_s": float(np.median(delays)) if delays else None}  # fmt: skip


def main() -> None:
    perts = sorted(p.name for p in FRAG.iterdir() if p.is_dir()) if FRAG.exists() else []
    if "P_ref" not in perts:
        sys.exit("no P_ref scores yet")
    res: dict = {"status": "REGISTERED DEVELOPMENT DIAGNOSTIC (Experiment A); no candidate is "
                           "selected from it", "per": {}, "catastrophic": {}}  # fmt: skip
    labels: dict[str, Labels] = {}
    ref: dict[tuple, dict] = {}
    ref_scores: dict[tuple, np.ndarray] = {}
    for pname in ["P_ref"] + [p for p in perts if p != "P_ref"]:
        for f in sorted((FRAG / pname).glob("*.npz")):
            name, r = f.stem.rsplit("__r", 1)
            name = name.replace("__", "/")
            lab = labels.setdefault(name, Labels(name))
            z = np.load(f)
            m = metrics(lab, z["s_hold"], z["s_ev"])
            if pname == "P_ref":
                ref[(name, r)], ref_scores[(name, r)] = m, z["s_ev"]
            elif (name, r) in ref:
                m["spearman_vs_ref"] = float(spearmanr(z["s_ev"], ref_scores[(name, r)]).statistic)
                base = ref[(name, r)]
                lost = [e for e, d in base["detected"].items() if d and not m["detected"][e]]
                drop = (base["window_recall"] or 0) - (m["window_recall"] or 0)
                rank_drop = (base["ranking_recall_at_benign_q99"] or 0) - (
                    m["ranking_recall_at_benign_q99"] or 0
                )
                if drop >= CAT_DROP or lost:
                    res["catastrophic"].setdefault(pname, []).append({
                        "domain": name, "rep": int(r), "recall_drop": drop, "entities_lost": len(lost),
                        "mechanism": ("ranking" if rank_drop >= CAT_DROP else "threshold") if drop >= CAT_DROP
                        else "entity only"})  # fmt: skip
            m.pop("detected")
            res["per"].setdefault(pname, {}).setdefault(name, {})[f"r{r}"] = m
    summary = {}
    for pname, doms in res["per"].items():
        row = {}
        for net in NETWORKS:
            vals = [v for n, reps in doms.items() if n.startswith(net + "/") for v in reps.values()]
            if vals:
                row[net] = {k: float(np.mean([v[k] for v in vals if v[k] is not None]))
                            if any(v[k] is not None for v in vals) else None
                            for k in ("window_recall", "fpr", "false_alerts", "auc", "ranking_recall_at_benign_q99")}  # fmt: skip
        focus = {
            n: [doms[n][r]["window_recall"] for r in sorted(doms[n])] for n in FOCUS if n in doms
        }
        cats = res["catastrophic"].get(pname, [])
        summary[pname] = {"network_means": row, "focus_day_recall_by_rep": focus,
                          "catastrophic_cases": len(cats),
                          "catastrophic_focus_cases": sum(c["domain"] in FOCUS for c in cats),
                          "mechanisms": {k: sum(c["mechanism"] == k for c in cats)
                                         for k in ("ranking", "threshold", "entity only")}}  # fmt: skip
    res["summary"] = summary
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    for p, s in summary.items():
        print(f"{p:28s} cat={s['catastrophic_cases']:3d} focus={s['catastrophic_focus_cases']:2d} {s['mechanisms']} "
              + " ".join(f"{n}:{v['window_recall']:.3f}" for n, v in s["network_means"].items()))  # fmt: skip


if __name__ == "__main__":
    main()
