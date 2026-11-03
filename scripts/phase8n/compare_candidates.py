"""Phase 8n Experiment C: registered development comparison of M1-M3 against M0
(docs/phase8n/PREREGISTRATION.md, amendment 1). No model is fitted here.

Per model, regime, domain and replicate: the Experiment A measures (scripts/phase8n/
analyze_fragility.py `metrics`) plus false alerts per hour. Per model over its 6 fits (3 base +
3 stress): network means, pooled entity recall, and the entity stability counts R (detected in
all 6), U (some but not all) and N (never). The GO rule G1-G3 and the selection are applied
exactly as registered.

Output: reports/phase8n/candidate_comparison.json
Usage: python scripts/phase8n/compare_candidates.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8n_analyze", ROOT / "scripts/phase8n/analyze_fragility.py"
)
AF = importlib.util.module_from_spec(_spec)
sys.modules["phase8n_analyze"] = AF
_spec.loader.exec_module(AF)

CAND = ROOT / "data" / "derived" / "phase8n" / "candidates"
B0_DIR = AF.B0_DIR
OUT = ROOT / "reports" / "phase8n" / "candidate_comparison.json"
MODELS = ("M0", "M1", "M2", "M3")
SIMPLICITY = ("M3", "M2", "M1")  # tie-break order (simplest first)
REGIMES = ("base", "stress")
REPS = (0, 1, 2)
NETWORKS = AF.NETWORKS
RECALL_LOSS, ENTITY_LOSS, FA_RATIO, U_GAIN = 0.05, 0.02, 1.25, 3
# attack families per domain (dataset labels; reports/phase8i/windows_<network>.json)
FAMILY = {"nfcic/2018-02-14": "ssh_bruteforce", "nfcic/2018-02-16": "dos_hulk",
          "nfcic/2018-02-20": "ddos_loic_http", "nfcic/2018-02-21": "ddos_hoic",
          "nfcic/2018-02-22": "web_bruteforce/xss/sql_injection", "nfcic/2018-03-02": "bot",
          "nfunsw/all": "9 families (exploits, fuzzers, generic, ...)",
          "nfton/all": "password, xss, backdoor, ransomware, mitm", "nfbot/all": "dos, ddos, theft"}  # fmt: skip


def domains() -> list[str]:
    return sorted(
        p.name.split("__seed0")[0].replace("__", "/") for p in B0_DIR.glob("*__seed0.npz")
    )


def fits(model: str, labels: dict) -> dict | None:
    """(regime, rep) -> domain -> metrics (with the detection map); None if any fit is missing."""
    out = {}
    for regime in REGIMES:
        for r in REPS:
            per = {}
            for name in labels:
                f = CAND / model / regime / f"{name.replace('/', '__')}__r{r}.npz"
                if not f.exists():
                    return None
                z = np.load(f)
                m = AF.metrics(labels[name], z["s_hold"], z["s_ev"])
                hours = float(np.load(B0_DIR / f"{name.replace('/', '__')}__seed0.npz")["hours"])
                m["false_alerts_per_h"] = m["false_alerts"] / hours if hours else None
                per[name] = m
            out[(regime, r)] = per
    return out


def summarise(f: dict, labels: dict) -> dict:
    keys = ("window_recall", "fpr", "false_alerts", "false_alerts_per_h", "auc",
            "ranking_recall_at_benign_q99", "t0", "median_delay_s")  # fmt: skip
    nets = {}
    for net in NETWORKS:
        rows = [m for per in f.values() for n, m in per.items() if n.startswith(net + "/")]
        nets[net] = {k: (float(np.mean([m[k] for m in rows if m[k] is not None]))
                         if any(m[k] is not None for m in rows) else None) for k in keys}  # fmt: skip
        for regime in REGIMES:
            rr = [m["window_recall"] for (g, _), per in f.items() if g == regime
                  for n, m in per.items() if n.startswith(net + "/") and m["window_recall"] is not None]  # fmt: skip
            nets[net][f"window_recall_{regime}"] = float(np.mean(rr)) if rr else None
    robust = unstable = never = 0
    by_net = {n: [0, 0, 0] for n in NETWORKS}
    det_share = []
    for name, lab in labels.items():
        for e in lab.entities:
            v = [per[name]["detected"][e] for per in f.values()]
            det_share.append(np.mean(v))
            k = 0 if all(v) else (1 if any(v) else 2)
            robust, unstable, never = robust + (k == 0), unstable + (k == 1), never + (k == 2)
            by_net[name.split("/")[0]][k] += 1
    focus = {n: {f"{g}_r{r}": f[(g, r)][n]["window_recall"] for (g, r) in f} for n in AF.FOCUS}
    per_domain = {}
    for name in labels:
        rec = [per[name]["window_recall"] for per in f.values()]
        per_domain[name] = {"family": FAMILY.get(name), "recall_mean": float(np.mean(rec)),
                            "recall_min": float(np.min(rec)), "recall_max": float(np.max(rec)),
                            "false_alerts_mean": float(np.mean([per[name]["false_alerts"] for per in f.values()])),
                            "entities": len(labels[name].entities)}  # fmt: skip
    return {"network_means": nets, "entity_recall_pooled": float(np.mean(det_share)),
            "R": robust, "U": unstable, "N": never, "RUN_by_network": by_net,
            "focus_day_recall": focus, "per_domain": per_domain}  # fmt: skip


def go(c: dict, m0: dict) -> dict:
    g1_net = {n: c["network_means"][n]["window_recall"] >= m0["network_means"][n]["window_recall"] - RECALL_LOSS
              for n in NETWORKS}  # fmt: skip
    g1_ent = c["entity_recall_pooled"] >= m0["entity_recall_pooled"] - ENTITY_LOSS
    g2 = {n: c["network_means"][n]["false_alerts"] <= FA_RATIO * m0["network_means"][n]["false_alerts"]
          for n in NETWORKS}  # fmt: skip
    g3 = c["U"] <= m0["U"] - U_GAIN and c["R"] >= m0["R"]
    return {"G1_recall_by_network": g1_net, "G1_entity": g1_ent, "G2_workload_by_network": g2,
            "G3_robustness": g3, "pass": bool(all(g1_net.values()) and g1_ent and all(g2.values()) and g3)}  # fmt: skip


def main() -> None:
    labels = {n: AF.Labels(n) for n in domains()}
    res = {"status": "REGISTERED DEVELOPMENT (Experiment C); consumed development networks; a GO is "
                     "a candidate for independent testing, not deployment", "models": {}}  # fmt: skip
    for model in MODELS:
        f = fits(model, labels)
        if f is None:
            print(model, "incomplete")
            continue
        res["models"][model] = summarise(f, labels)
    if "M0" not in res["models"]:
        sys.exit("M0 missing")
    m0 = res["models"]["M0"]
    res["go"] = {m: go(res["models"][m], m0) for m in res["models"] if m != "M0"}
    passed = [m for m, g in res["go"].items() if g["pass"]]
    if passed:
        best = max(passed, key=lambda m: (res["models"][m]["R"], -SIMPLICITY.index(m)))
        res["selection"] = {
            "candidate": best,
            "rule": "largest R among passing; ties to the simpler",
        }
    else:
        res["selection"] = {
            "candidate": None,
            "rule": "no candidate passes G1-G3: development NO-GO, B0 stays",
        }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    for m, s in res["models"].items():
        print(m, "R/U/N", s["R"], s["U"], s["N"], "entity", round(s["entity_recall_pooled"], 3),
              {n: (round(v["window_recall"], 3), round(v["false_alerts"])) for n, v in s["network_means"].items()},
              res["go"].get(m, {}).get("pass"))  # fmt: skip
    print(res["selection"])


if __name__ == "__main__":
    main()
