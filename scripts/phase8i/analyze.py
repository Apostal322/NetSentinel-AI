"""Phase 8i development analysis: per-unit tables and the pre-registered selection rules
(docs/phase8i/PREREGISTRATION.md sections 4-6). Development results are exploratory [E].

Network-level units: N1 = mean over the primary NF-CIC days (02-22 is secondary, reported
separately), N2 = NF-UNSW, N3 = NF-ToN-IoT.
Output: reports/phase8i/analysis.json (and a markdown summary on stdout).
Usage: uv run python scripts/phase8i/analyze.py [--root reports/phase8i]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

PRIMARY_N1 = ["2018-02-14", "2018-02-16", "2018-02-20", "2018-02-21", "2018-03-02"]
METHODS = ("A3", "A4", "A5")
SIMPLICITY = {"A3": 0, "A5": 1, "A4": 2}
KEYS = ("window_recall", "fpr", "roc_auc", "pr_auc", "oracle_recall_at_fpr1", "entity_recall",
        "false_alerts_per_h", "median_delay_s")  # fmt: skip


def network_of(unit: str) -> str | None:
    net, dom = unit.split("/")
    if net == "nfcic":
        return "N1" if dom in PRIMARY_N1 else None
    return {"nfunsw": "N2", "nfton": "N3"}.get(net)


def med(vals) -> float | None:
    v = [x for x in vals if x is not None]
    return float(np.median(v)) if v else None


def mean(vals) -> float | None:
    v = [x for x in vals if x is not None]
    return float(np.mean(v)) if v else None


# ----------------------------------------------------------------------------- Experiment A
def unit_a(r: dict) -> dict:
    """Per unit: A0/A1 (mean over seeds) and, per budget and method, medians over draws x seeds."""
    seeds = list(r["seeds"].values())
    out = {k: {m: mean(s[k].get(m) for s in seeds) for m in KEYS} for k in ("A0", "A1")}
    out["n_hold"] = r["n_hold"]
    out["T0_reliable"] = all(s["T0_reliable"] for s in seeds)
    out["pool_windows"], out["pool_entities"] = r["pool_windows"], r["pool_entities"]
    out["attackers"] = len(r["attackers"])
    for b in seeds[0]["budgets"]:
        out[b] = {}
        for m in METHODS:
            per = [p for s in seeds for p in s["budgets"][b][m]["per_draw"]]
            rec = np.array([p["window_recall"] for p in per if p.get("window_recall") is not None])
            out[b][m] = {k: med(p.get(k) for p in per) for k in KEYS}
            out[b][m]["recall_p025"] = float(np.quantile(rec, 0.025)) if len(rec) else None
            out[b][m]["n"] = len(per)
        info = seeds[0]["budgets"][b]["draw_info"]
        out[b]["entities_per_draw_median"] = med(i["entities"] for i in info)
        out[b]["pool_short"] = seeds[0]["budgets"][b]["pool_short"]
    return out


def analyze_a(root: Path) -> dict:
    units = {}
    for f in sorted((root / "exp_a").glob("*.json")):
        r = json.loads(f.read_text("utf-8"))
        units[r["target"]] = unit_a(r)
    nets: dict[str, dict] = {}
    for net in ("N1", "N2", "N3"):
        us = [u for k, u in units.items() if network_of(k) == net]
        if not us:
            continue
        nets[net] = {"units": len(us),
                     "A1": {k: mean(u["A1"][k] for u in us) for k in KEYS},
                     "A0": {k: mean(u["A0"][k] for u in us) for k in KEYS}}  # fmt: skip
        for b in [b for b in us[0] if b.startswith("Ka")]:
            nets[net][b] = {m: {k: mean(u[b][m][k] for u in us if b in u) for k in KEYS}
                            for m in METHODS}  # fmt: skip
    # selection rule (section 4)
    elig = {}
    for m in METHODS:
        rec = [nets[n]["Ka25"][m]["window_recall"] for n in nets if "Ka25" in nets[n]]
        fpr = [nets[n]["Ka25"][m]["fpr"] for n in nets if "Ka25" in nets[n]]
        elig[m] = {"median_recall": med(rec), "median_fpr": med(fpr),
                   "fpr_ok": (med(fpr) is not None and med(fpr) <= 0.02)}  # fmt: skip
    ok = [m for m in METHODS if elig[m]["fpr_ok"] and elig[m]["median_recall"] is not None]
    chosen = (max(ok, key=lambda m: (elig[m]["median_recall"], -SIMPLICITY[m])) if ok else "A3")
    return {"units": units, "networks": nets, "selection": {"candidates": elig, "chosen": chosen,
            "rule_met": bool(ok)}}  # fmt: skip


# ----------------------------------------------------------------------------- Experiment C
def analyze_c(root: Path) -> dict:
    p = root / "exp_c" / "cross.json"
    if not p.exists():
        return {}
    cross = json.loads(p.read_text("utf-8"))["result"]
    units = {}
    for name, r in cross.items():
        variants = sorted({v for s in r["seeds"].values() for v in s})
        units[name] = {v: {k: mean(s[v].get(k) for s in r["seeds"].values() if v in s)
                           for k in KEYS} for v in variants}  # fmt: skip
        units[name]["B-rz"] = {k: r["B-rz"].get(k) for k in KEYS}
        units[name]["ranking"] = r["ranking"]
    nets = {}
    for net in ("N1", "N2", "N3"):
        us = [u for k, u in units.items() if network_of(k) == net]
        if us:
            vs = [v for v in us[0] if v != "ranking"]
            nets[net] = {v: {k: mean(u[v][k] for u in us) for k in KEYS} for v in vs}
    within = {}
    wp = root / "exp_c" / "within.json"
    if wp.exists():
        w = json.loads(wp.read_text("utf-8"))["result"]
        for name, seeds in w["units"].items():
            within[name] = {v: mean(s[v].get("window_recall") for s in seeds.values())
                            for v in next(iter(seeds.values()))}  # fmt: skip
    loss = {v: mean(within[u][v] - within[u]["raw"] for u in within
                    if within[u].get(v) is not None and within[u].get("raw") is not None)
            for v in ("C1_k2", "C2")}  # fmt: skip
    gain = {v: mean(nets[n][v]["window_recall"] - nets[n]["raw"]["window_recall"] for n in nets
                    if v in nets[n] and nets[n][v]["window_recall"] is not None)
            for v in ("C1_k2", "C2", "C1_k1", "C1_k3", "no_volume")}  # fmt: skip
    ok = [v for v in ("C1_k2", "C2") if gain.get(v) is not None and loss.get(v) is not None
          and loss[v] >= -0.05]  # fmt: skip
    chosen = max(ok, key=lambda v: gain[v]) if ok else "C2"
    control = {}
    cp = root / "exp_c" / "control.json"
    if cp.exists():
        control = json.loads(cp.read_text("utf-8"))["result"]
    return {"units": units, "networks": nets, "within": within,
            "selection": {"gain_vs_raw": gain, "within_loss": loss, "chosen": chosen,
                          "rule_met": bool(ok)}, "control": control}  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="reports/phase8i")
    a = ap.parse_args()
    root = Path(a.root)
    out = {"label": "[E] development data", "A": analyze_a(root), "C": analyze_c(root)}
    bp = root / "exp_b" / "summary.json"
    if bp.exists():
        out["B"] = json.loads(bp.read_text("utf-8"))
    (root / "analysis.json").write_text(json.dumps(out, indent=1, default=float), "utf-8")
    sel = {k: out[k]["selection"] for k in ("A", "C") if out[k]}
    print(json.dumps(sel, indent=1, default=float))
    if "B" in out:
        print("tau", out["B"].get("tau_S_score_60pct"))


if __name__ == "__main__":
    main()
