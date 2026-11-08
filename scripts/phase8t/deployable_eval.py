"""Phase 8t registered deployable comparison (docs/phase8t/PREREGISTRATION.md § 8, A-1).
Saved scores only (S_U = unlabelled-memory scores); no model fitted.

Calibration uses hold-out windows only:
- CAL_T: benign hold-out windows (calibration labels; best case of trusted review);
- CAL_U: the whole unlabelled hold-out.
Evaluation labels enter only the metrics and the single retrospective matched-budget offset,
which is applied identically to every method.

Output (atomic): reports/phase8t/deployable.json (+ .sha256)
Usage: python scripts/run_capped.py -- <python> scripts/phase8t/deployable_eval.py [--tag _x]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import subprocess
import sys
import time
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


OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")
CC = _load("phase8t_cc", "scripts/phase8t/conditional_calibration.py")
FG, TO, BM, CD = OF.FG, OF.TO, OF.BM, OF.CD
OUT = ROOT / "reports" / "phase8t"
ALPHA = 0.01
REGISTERED = {"kappa": 500.0}
SENSITIVITY_KAPPA = (100.0, 2000.0)


def load(name: str) -> dict:
    d = OF.load(name)
    net, dom = name.split("/")
    fgd = FG.domain_data(name)
    cal = pl.read_parquet(CD.I8 / net / dom / "cal_unlabelled.parquet",
                          columns=["key", "win", "window_end_ms", "udp_share", "dst_ports"]).sort("win", "key")  # fmt: skip
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    cal = cal.filter(pl.col("win") >= lo + int(math.floor((hi - lo + 1) * 0.7)))
    if not np.array_equal(cal["key"].to_numpy().astype(str), fgd["hu_key"]):
        raise RuntimeError(f"{name}: hold-out order differs")
    d["cal_key"] = fgd["hu_key"]
    d["cal_att"] = fgd["is_att"]
    d["cal_grp"] = CC.service_group(cal["udp_share"].to_numpy(), cal["dst_ports"].to_numpy())
    d["cal_end"] = cal["window_end_ms"].to_numpy()
    return d


def evaluate(d: dict, s_cal: np.ndarray, s_ev: np.ndarray, cal_mask: np.ndarray, method: str,
             kappa: float, sub: np.ndarray | None = None, matched: bool = True) -> dict:  # fmt: skip
    c = CC.Calibrator(
        method, s_cal[cal_mask], d["cal_grp"][cal_mask], d["cal_key"][cal_mask], kappa=kappa
    )
    t = c.threshold_for(d["svc"], d["key"])
    alert = s_ev > t
    out = {"as_calibrated": OF.metrics(d, s_ev, alert, sub)}
    if matched:
        m = np.ones(s_ev.size, bool) if sub is None else sub
        v = c.cdf_for(s_ev, d["svc"], d["key"])
        neg = d["neg"] & m
        budget = int(math.floor(ALPHA * neg.sum()))
        alert_mb = np.zeros(s_ev.size, bool)
        alert_mb[m] = CC.matched_budget_alert(v[m], s_ev[m], neg[m], budget)  # A-2
        out["matched_budget"] = OF.metrics(d, s_ev, alert_mb, sub)
    # group transfer error (H2): calibration vs evaluation exceedance per service group
    te, w = [], []
    cal_g, cal_s = d["cal_grp"][cal_mask], s_cal[cal_mask]
    tcal = c.threshold_for(cal_g, d["cal_key"][cal_mask])
    for g in np.unique(d["svc"]):
        eg = d["neg"] & (d["svc"] == g) & (np.ones(s_ev.size, bool) if sub is None else sub)
        cg = cal_g == g
        if eg.sum() == 0 or cg.sum() == 0:
            continue
        te.append(abs(float((s_ev[eg] > t[eg]).mean()) - float((cal_s[cg] > tcal[cg]).mean())))
        w.append(int(eg.sum()))
    out["group_transfer_error"] = float(np.average(te, weights=w)) if w else None
    out["support"] = {str(k): v for k, v in c.support.items()} if method != "D_host" else c.support
    return out


def run(names: list[str], data: dict) -> dict:
    res: dict = {}
    for name in names:
        d = data[name]
        half = d["win"] >= np.median(np.unique(d["win"]))
        res[name] = {}
        for regime, r in FG.FITS:
            fk = f"{regime}_r{r}"
            z = FG.scores(name, regime, r)
            s_cal, s_ev = z["s_hold_u"], z["s_ev_u"]
            row: dict = {}
            sources = {"CAL_T": ~d["cal_att"], "CAL_U": np.ones(s_cal.size, bool)}
            for src, cm in sources.items():
                for meth in CC.METHODS:
                    row[f"{src}|{meth}"] = evaluate(d, s_cal, s_ev, cm, meth, REGISTERED["kappa"])
                    row[f"{src}|{meth}|second_half"] = evaluate(d, s_cal, s_ev, cm, meth, REGISTERED["kappa"], sub=half,
                                                                matched=False)  # fmt: skip
            for kap in SENSITIVITY_KAPPA:
                row[f"CAL_T|D2|kappa{int(kap)}"] = evaluate(
                    d, s_cal, s_ev, sources["CAL_T"], "D2", kap
                )
            # stress (EXPLORATORY): drop the benign host with most windows above the global calibration threshold
            ben = sources["CAL_T"]
            tg = CC.Calibrator("D0", s_cal[ben], d["cal_grp"][ben], d["cal_key"][ben]).t_glob
            hk, cnt = np.unique(d["cal_key"][ben & (s_cal > tg)], return_counts=True)
            if hk.size:
                drop = ben & (d["cal_key"] != hk[np.argmax(cnt)])
                for meth in ("D0", "D2"):
                    row[f"CAL_T_minus_noisiest|{meth}"] = evaluate(
                        d, s_cal, s_ev, drop, meth, REGISTERED["kappa"]
                    )
            # calibration age (EXPLORATORY): only the older half of the hold-out
            old = ben & (d["cal_end"] < np.median(d["cal_end"]))
            if old.sum() >= 100:
                for meth in ("D0", "D2"):
                    row[f"CAL_T_older_half|{meth}"] = evaluate(
                        d, s_cal, s_ev, old, meth, REGISTERED["kappa"]
                    )
            res[name][fk] = row
        print(name, "done", flush=True)
    return res


def summarise(res: dict, key: str, view: str) -> dict | None:
    names = list(res)
    fits = list(res[names[0]])
    if not all(key in res[n][fk] for n in names for fk in fits):
        return None
    nets = {}
    for net in BM.NETWORKS:
        doms = [n for n in names if n.startswith(net + "/")]
        vals = {f: [] for f in ("recall", "fpr", "fa_per_h", "top_host_fa_share")}
        for fk in fits:
            for f in vals:
                xs = [
                    res[n][fk][key][view][f] for n in doms if res[n][fk][key][view][f] is not None
                ]
                xs = [x for x in xs if not (isinstance(x, float) and math.isnan(x))]
                vals[f].append(float(np.mean(xs)) if xs else float("nan"))
        nets[net] = {f: float(np.nanmean(v)) for f, v in vals.items()}
        te = [
            res[n][fk][key]["group_transfer_error"]
            for n in doms
            for fk in fits
            if res[n][fk][key]["group_transfer_error"] is not None
        ]
        nets[net]["group_transfer_error"] = float(np.mean(te)) if te else None
    r20 = np.mean([sum(res[n][fk][key][view]["r20"] for n in names) for fk in fits])
    missed = np.mean([sum(res[n][fk][key][view]["missed"] for n in names) for fk in fits])
    rec = [v["recall"] for v in nets.values() if not math.isnan(v["recall"])]
    return {
        "networks": nets,
        "macro_recall": float(np.mean(rec)),
        "R20": float(r20),
        "missed": float(missed),
    }


def decide(S: dict) -> dict:
    t0m, t2m = S["CAL_T|D0"]["matched_budget"], S["CAL_T|D2"]["matched_budget"]
    h1 = {
        "macro_gain": t2m["macro_recall"] - t0m["macro_recall"],
        "R20_gain": t2m["R20"] - t0m["R20"],
    }
    h1["verdict"] = (
        "SUPPORTED" if h1["macro_gain"] >= 0.05 and h1["R20_gain"] >= 3 else "NOT SUPPORTED"
    )
    d1, d2 = S["CAL_T|D1"]["as_calibrated"]["networks"], S["CAL_T|D2"]["as_calibrated"]["networks"]
    h2n = {n: (d2[n]["group_transfer_error"] < d1[n]["group_transfer_error"]) for n in d1
           if d1[n]["group_transfer_error"] is not None and d2[n]["group_transfer_error"] is not None}  # fmt: skip
    h2 = {"D2_lower": h2n, "verdict": "SUPPORTED" if sum(h2n.values()) >= 3 else "NOT SUPPORTED"}
    a0, a2 = S["CAL_T|D0"]["as_calibrated"], S["CAL_T|D2"]["as_calibrated"]
    h3n = {n: a2["networks"][n]["top_host_fa_share"] <= a0["networks"][n]["top_host_fa_share"] + 1e-12
           and a2["networks"][n]["recall"] >= a0["networks"][n]["recall"] - 0.02 for n in a0["networks"]}  # fmt: skip
    h3 = {"per_network": h3n, "verdict": "SUPPORTED" if sum(h3n.values()) >= 3 else "NOT SUPPORTED"}
    s0, s2 = S["CAL_T|D0|second_half"]["as_calibrated"], S["CAL_T|D2|second_half"]["as_calibrated"]
    h4g = s2["macro_recall"] - s0["macro_recall"]
    h4f = {n: s2["networks"][n]["fpr"] <= s0["networks"][n]["fpr"] + 0.01 for n in s0["networks"]}
    h4 = {
        "macro_gain": h4g,
        "fpr_ok": h4f,
        "verdict": "SUPPORTED" if h4g >= 0.03 and all(h4f.values()) else "NOT SUPPORTED",
    }
    g_macro = a2["macro_recall"] - a0["macro_recall"]
    g_fpr = {n: a2["networks"][n]["fpr"] <= a0["networks"][n]["fpr"] + 0.01 for n in a0["networks"]}
    g_loss = {
        n: a2["networks"][n]["recall"] >= a0["networks"][n]["recall"] - 0.05 for n in a0["networks"]
    }
    g_r20 = a2["R20"] - a0["R20"]
    crit = {"H1": h1["verdict"] == "SUPPORTED", "macro_gain_ge_0.05": g_macro >= 0.05, "fpr_not_worse_1pp": all(g_fpr.values()),
            "no_network_loss_gt_0.05": all(g_loss.values()), "R20_gain_ge_3": g_r20 >= 3}  # fmt: skip
    gate = {"macro_gain": g_macro, "R20_gain": g_r20, "fpr_ok": g_fpr, "loss_ok": g_loss, "criteria": crit,
            "verdict": "DEVELOPMENT GO" if all(crit.values()) else "DEVELOPMENT NO-GO"}  # fmt: skip
    return {"H1": h1, "H2": h2, "H3": h3, "H4": h4, "operational_gate": gate}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="")
    ap.add_argument("--domains")
    args = ap.parse_args()
    from netsentinel.resources import peak_rss_mb  # noqa: PLC0415

    t0 = time.perf_counter()
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    if args.domains:
        names = [n for n in names if n in args.domains.split(",")]
    reg = json.loads((ROOT / "reports/phase8o/experiment_d_scores_sha256.json").read_text("utf-8"))
    for n in names:
        for regime, r in FG.FITS:
            rel = f"data/derived/phase8o/experiment_d/F0/{regime}/{n.replace('/', '__')}__r{r}.npz"
            if reg.get(rel) != hashlib.sha256((ROOT / rel).read_bytes()).hexdigest():
                raise RuntimeError(f"{rel}: frozen score hash missing or different")
    data = {n: load(n) for n in names}
    res = run(names, data)
    keys = sorted({k for n in res for fk in res[n] for k in res[n][fk]})
    S = {}
    for k in keys:
        views = (
            ("as_calibrated", "matched_budget") if "second_half" not in k else ("as_calibrated",)
        )
        S[k] = {v: summarise(res, k, v) for v in views if summarise(res, k, v) is not None}
    full = len(names) == 9
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()
    )
    out = {"status": "Phase 8t registered deployable comparison (S_U scores; CAL_T = calibration labels, best-case trusted review)",
           "provenance": {"git_sha": sha, "dirty_tree": dirty, "kappa": REGISTERED["kappa"], "alpha": ALPHA},
           "summary": S, "decisions": decide(S) if full else None, "domains": res,
           "runtime_s": time.perf_counter() - t0, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    body = json.dumps(out, indent=1, default=float).encode()
    OF.atomic_write(OUT / f"deployable{args.tag}.json", body)
    OF.atomic_write(OUT / f"deployable{args.tag}.sha256", hashlib.sha256(body).hexdigest().encode())
    print("done", round(out["runtime_s"], 1), "s; peak", out["peak_rss_mb"], flush=True)


if __name__ == "__main__":
    main()
