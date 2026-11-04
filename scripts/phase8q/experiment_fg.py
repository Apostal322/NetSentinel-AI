"""Phase 8q Experiments F (label-free threshold calibration) and G (controlled contamination of a
clean hold-out). docs/phase8q/PREREGISTRATION.md sections 3-5. Saved scores only (Phase 8o F0,
6 fits, K = 5); no model fitted.

F: every candidate sees only the unlabelled hold-out scores, hosts and end times, and is applied
   to the unlabelled evaluation scores. The labels enter only the metrics (V2 documented
   attackers vs the historical benign set).
G: the clean P1x hold-out with the domain's own calibration-attacker windows injected (persistent
   single host / spread), plus sparse calibration (25 % / 10 % of hosts). Evaluation on the P1x
   scores, so only the threshold changes.

Output: reports/phase8q/experiment_f.json, reports/phase8q/experiment_g.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8q/experiment_fg.py [--only F|G]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


CM = _load("phase8q_methods", "scripts/phase8q/calibration_methods.py")
CD = _load("phase8q_decomp", "scripts/phase8q/calibration_decomposition.py")
BM = CD.BM

OUT_F = ROOT / "reports" / "phase8q" / "experiment_f.json"
OUT_G = ROOT / "reports" / "phase8q" / "experiment_g.json"
FITS = CD.FITS
CANDIDATES = ("L1", "L2", "L4", "L5")
FRACTIONS = (0.005, 0.01, 0.02, 0.05, 0.10)
SPARSE = (0.25, 0.10)


def domain_data(name: str) -> dict:
    net, dom = name.split("/")
    a = pl.read_parquet(BM.AUDIT / f"{name.replace('/', '__')}.parquet")
    cat, key = a["category"].to_numpy().astype(str), a["key"].to_numpy().astype(str)
    hu = CD.hold_frame(CD.I8 / net / dom / "cal_unlabelled.parquet")
    hp = CD.hold_frame(CD.P1X / net / dom / "cal_p1x.parquet")
    att = CD.calibration_attackers(name)
    return {"pos": np.isin(cat, CD.V2), "neg": np.isin(cat, BM.BENIGN), "key": key,
            "hours": float(np.load(BM.B0 / f"{name.replace('/', '__')}__seed0.npz")["hours"]),
            "hu_key": hu["key"].to_numpy().astype(str), "hu_end": hu["window_end_ms"].to_numpy(),
            "hp_key": hp["key"].to_numpy().astype(str), "hp_end": hp["window_end_ms"].to_numpy(),
            "is_att": np.isin(hu["key"].to_numpy().astype(str), np.array(sorted(att), dtype=str))}  # fmt: skip


def scores(name: str, regime: str, r: int) -> dict:
    z = np.load(BM.O8 / regime / f"{name.replace('/', '__')}__r{r}.npz")
    return {k: z[k].mean(0) for k in ("s_hold", "s_ev", "s_hold_u", "s_ev_u")}


def thresholds(s: np.ndarray, hosts: np.ndarray, end: np.ndarray) -> dict[str, float]:
    return {m: f(s, hosts, end) for m, f in CM.METHODS.items()}


def experiment_f(names: list[str], data: dict) -> dict:
    per = {m: {} for m in ("U", "T", "P", *CANDIDATES)}
    abstained = {}
    for regime, r in FITS:
        for name in names:
            d, z = data[name], scores(name, regime, r)
            th = thresholds(z["s_hold_u"], d["hu_key"], d["hu_end"])
            th["T"] = CM.t0(z["s_hold_u"][~d["is_att"]]) if (~d["is_att"]).any() else np.inf
            th["P"] = CM.t0(z["s_hold"])
            abstain = CM.insufficient_evidence(d["hu_key"], d["hu_end"])
            abstained[name] = abstain
            for m in ("U", "T", "P", "L1", "L2", "L4", "L5"):
                if m == "L5":
                    alert = (z["s_ev_u"] > th["L4"]) & (not abstain)
                else:
                    alert = (z["s_ev"] if m == "P" else z["s_ev_u"]) > th[m]
                per[m].setdefault((regime, r), {})[name] = BM.view_metrics(
                    alert, d["key"], d["pos"], d["neg"], d["hours"]
                )
    summ = {m: BM.summarise(f) for m, f in per.items()}
    out = {"status": "REGISTERED DEVELOPMENT (Experiment F); saved scores; label-free candidates",
           "abstained_domains_L5": abstained, "methods": {}}  # fmt: skip
    for m, s in summ.items():
        out["methods"][m] = {"macro_recall": s["macro_recall"], "R20": s["R"][20], "U20": s["U"][20], "N20": s["N"][20],
                             "networks": s["networks"]}  # fmt: skip
    u, p = summ["U"], summ["P"]
    gap = summ["T"]["macro_recall"] - u["macro_recall"]
    dec = {}
    for m in CANDIDATES:
        x = summ[m]
        ok1 = x["macro_recall"] - u["macro_recall"] >= 0.10
        ok2 = {
            n: x["networks"][n]["recall"] >= u["networks"][n]["recall"] - 0.05 for n in BM.NETWORKS
        }
        ok3 = {n: x["networks"][n]["fpr"] <= p["networks"][n]["fpr"] + 0.01 for n in BM.NETWORKS}
        cov = {}
        if m == "L5":
            for n in BM.NETWORKS:
                doms = [d for d in names if d.startswith(n + "/")]
                cov[n] = float(np.mean([0.0 if abstained[d] else 1.0 for d in doms]))
        ok4 = all(v >= 0.5 for v in cov.values()) if cov else True
        dec[m] = {"macro_gain_vs_U": x["macro_recall"] - u["macro_recall"],
                  "gap_recovered": (x["macro_recall"] - u["macro_recall"]) / gap if gap else None,
                  "i_macro": ok1, "ii_recall_by_network": ok2, "iii_fpr_by_network": ok3, "iv_coverage": cov or None,
                  "verdict": "SUPPORTED" if ok1 and all(ok2.values()) and all(ok3.values()) and ok4 else "NOT SUPPORTED"}  # fmt: skip
    out["decisions"] = dec
    out["calibration_research"] = (
        "SUPPORTED" if any(v["verdict"] == "SUPPORTED" for v in dec.values()) else "NOT SUPPORTED"
    )
    out["paired_macro_diff_vs_U"] = {m: [BM.summarise({k: v})["macro_recall"] - BM.summarise({k: per["U"][k]})["macro_recall"]
                                         for k, v in per[m].items()] for m in CANDIDATES}  # fmt: skip
    return out


def experiment_g(names: list[str], data: dict) -> dict:
    rng = np.random.default_rng(8)
    res: dict = {"status": "REGISTERED DESCRIPTIVE (Experiment G); threshold-only contamination of the P1x hold-out",
                 "injection": {}, "sparse": {}}  # fmt: skip
    for name in names:
        d = data[name]
        if not d["is_att"].any():
            continue
        att_keys, att_cnt = np.unique(d["hu_key"][d["is_att"]], return_counts=True)
        top = att_keys[np.argmax(att_cnt)]
        rows = {}
        for regime, r in FITS:
            z = scores(name, regime, r)
            base_s, base_k, base_e = z["s_hold"], d["hp_key"], d["hp_end"]
            idx_all = np.flatnonzero(d["is_att"])
            idx_top = np.flatnonzero(d["is_att"] & (d["hu_key"] == top))
            for mode, pool in (("persistent", idx_top), ("spread", idx_all)):
                for f in (0.0, *FRACTIONS):
                    k = min(int(round(f * base_s.size)), pool.size)
                    pick = pool[:k] if mode == "persistent" else rng.choice(pool, k, replace=False)
                    s = np.r_[base_s, z["s_hold_u"][pick]]
                    h = np.r_[base_k, d["hu_key"][pick]]
                    e = np.r_[base_e, d["hu_end"][pick]]
                    for m, t in thresholds(s, h, e).items():
                        alert = z["s_ev"] > t
                        mt = BM.view_metrics(alert, d["key"], d["pos"], d["neg"], d["hours"])
                        rows.setdefault(f"{mode}|{f}|{m}", []).append(
                            {"t": t, "recall": mt["recall"], "fpr": mt["fpr"], "injected": k}
                        )
        res["injection"][name] = {kk: {"t_mean": float(np.mean([x["t"] for x in v])),
                                       "recall_mean": float(np.mean([x["recall"] for x in v if x["recall"] is not None]))
                                       if any(x["recall"] is not None for x in v) else None,
                                       "fpr_mean": float(np.mean([x["fpr"] for x in v])),
                                       "injected": int(v[0]["injected"])} for kk, v in rows.items()}  # fmt: skip
    for name in names:
        d = data[name]
        hosts = np.unique(d["hp_key"])
        out = {}
        for regime, r in FITS[:1]:  # base r6: variability of the estimators under host sparsity
            z = scores(name, regime, r)
            for frac in SPARSE:
                ts = {m: [] for m in CM.METHODS}
                for _ in range(20):
                    keep = np.isin(
                        d["hp_key"],
                        rng.choice(hosts, max(1, int(round(frac * hosts.size))), replace=False),
                    )
                    if keep.sum() < 2:
                        continue
                    for m, t in thresholds(
                        z["s_hold"][keep], d["hp_key"][keep], d["hp_end"][keep]
                    ).items():
                        ts[m].append(t)
                full = thresholds(z["s_hold"], d["hp_key"], d["hp_end"])
                out[str(frac)] = {m: {"full": full[m], "mean": float(np.mean(v)), "sd": float(np.std(v)),
                                      "p10": float(np.quantile(v, 0.1)), "p90": float(np.quantile(v, 0.9))}
                                  for m, v in ts.items() if v}  # fmt: skip
        res["sparse"][name] = out
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=("F", "G"))
    a = ap.parse_args()
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    data = {n: domain_data(n) for n in names}
    if a.only in (None, "F"):
        f = experiment_f(names, data)
        OUT_F.write_bytes(json.dumps(f, indent=1, default=str).encode())
        for m, v in f["methods"].items():
            print(m, round(v["macro_recall"], 3), "R20", v["R20"], {n: (round(x["recall"] or 0, 3), round(x["fpr"] or 0, 4))
                                                                     for n, x in v["networks"].items()})  # fmt: skip
        print({m: d["verdict"] for m, d in f["decisions"].items()}, f["calibration_research"])
    if a.only in (None, "G"):
        g = experiment_g(names, data)
        OUT_G.write_bytes(json.dumps(g, indent=1).encode())
        print("G domains", list(g["injection"]))


if __name__ == "__main__":
    main()
