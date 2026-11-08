"""Phase 8t Stage 3: oracle-feasibility analysis and model-limit diagnostics
(docs/phase8t/PREREGISTRATION.md §§ 4-6). Saved scores only; no model fitted.

Every oracle threshold is chosen WITH the evaluation labels it is scored on (retrospective,
development data, NOT deployable).

Output (atomic; never overwritten): reports/phase8t/oracle_feasibility.json (+ .sha256)
Usage: python scripts/run_capped.py -- <python> scripts/phase8t/oracle_feasibility.py [--tag _x]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
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


FG = _load("phase8q_fg", "scripts/phase8q/experiment_fg.py")
TO = _load("phase8t_to", "scripts/phase8t/threshold_oracles.py")
BM, CD = FG.BM, FG.CD
OUT = ROOT / "reports" / "phase8t"
ALPHA = 0.01
GUARD = 100
ACT_CUTS = (1, 10, 100)  # calibration windows: new (0) / low (1-9) / mid (10-99) / high (>=100)
V2 = BM.LA.VIEWS["V2_documented_attackers"]
WIN_MIN = 0.5  # minutes per window


def load(name: str) -> dict:
    net, dom = name.split("/")
    a = pl.read_parquet(
        BM.AUDIT / f"{name.replace('/', '__')}.parquet", columns=["key", "win", "category"]
    )
    ev = pl.read_parquet(
        CD.I8 / net / dom / "eval_unlabelled.parquet",
        columns=["key", "win", "udp_share", "dst_ports"],
    )
    j = a.join(ev, on=["key", "win"], how="left", maintain_order="left")
    if j["udp_share"].null_count():
        raise RuntimeError(f"{name}: evaluation windows without features")
    cal = (
        pl.read_parquet(CD.I8 / net / dom / "cal_unlabelled.parquet", columns=["key"])
        .group_by("key")
        .len()
    )
    j = j.join(
        cal.rename({"len": "cal_n"}), on="key", how="left", maintain_order="left"
    ).with_columns(pl.col("cal_n").fill_null(0))
    cat = j["category"].to_numpy().astype(str)
    key = j["key"].to_numpy().astype(str)
    pos, neg = np.isin(cat, V2), np.isin(cat, BM.BENIGN)
    # the structural fact of PREREGISTRATION § 3, enforced
    both = np.intersect1d(np.unique(key[pos]), np.unique(key[neg]))
    if both.size:
        raise RuntimeError(f"{name}: hosts with both attack and benign windows: {both[:5]}")
    cal_n = j["cal_n"].to_numpy()
    udp, ports = j["udp_share"].to_numpy().astype(float), j["dst_ports"].to_numpy().astype(float)
    win = j["win"].to_numpy()
    ents = BM.entities(key, pos)
    return {"key": key, "pos": pos, "neg": neg, "win": win, "cal_n": cal_n,
            "act": np.digitize(cal_n, ACT_CUTS), "svc": (udp > 0.5).astype(int) * 3 + np.digitize(ports, [1.5, 5.5]),
            "ents": [(e, np.flatnonzero(pos & (key == e))) for e in ents],
            "hours": float(np.load(BM.B0 / f"{name.replace('/', '__')}__seed0.npz")["hours"])}  # fmt: skip


def metrics(d: dict, s: np.ndarray, alert: np.ndarray, sub: np.ndarray | None = None) -> dict:
    m = np.ones(s.size, bool) if sub is None else sub
    pos, neg = d["pos"] & m, d["neg"] & m
    fa = alert & neg
    n_fa = int(fa.sum())
    top = 0.0
    if n_fa:
        _, c = np.unique(d["key"][fa], return_counts=True)
        top = float(c.max() / n_fa)
    r20 = r50 = missed = 0
    delays, det20 = [], []
    for _, idx in d["ents"]:
        idx = idx[m[idx]]
        if idx.size < 5:
            continue
        a = alert[idx]
        det20.append(bool(a.mean() >= 0.2 - 1e-12))
        r20 += a.mean() >= 0.2 - 1e-12
        r50 += a.mean() >= 0.5 - 1e-12
        missed += not a.any()
        if a.any():
            w = d["win"][idx]
            delays.append((w[a].min() - w.min()) * WIN_MIN)
    frac_hours = d["hours"] * (m.mean() if sub is not None else 1.0)
    return {"recall": float(alert[pos].mean()) if pos.any() else float("nan"), "fa": n_fa,
            "fpr": n_fa / max(int(neg.sum()), 1), "fa_per_h": n_fa / frac_hours if frac_hours else None,
            "r20": int(r20), "r50": int(r50), "missed": int(missed),
            "entities": int(sum(1 for _, i in d["ents"] if m[i].sum() >= 5)),
            "delay_median_min": float(np.median(delays)) if delays else None, "top_host_fa_share": top,
            "entity_det20": det20}  # fmt: skip


def oracles(d: dict, s: np.ndarray, sub: np.ndarray | None = None) -> dict:
    """All registered oracles at budget B on the window subset `sub`."""
    m = np.ones(s.size, bool) if sub is None else sub
    neg, pos = d["neg"] & m, d["pos"] & m
    budget = int(math.floor(ALPHA * neg.sum()))
    t0 = TO.global_threshold(s[neg], budget)
    out = {"budget": budget, "O0": {"alert": (s > t0) & m, "t": t0, "free": 1}}
    for name, grp in (("O2", d["act"]), ("O3", d["svc"])):
        for tag, guard in ((name, None), (name + "g", GUARD)):
            o = TO.group_oracle(s[m], grp[m], neg[m], pos[m], budget, guard_min_benign=guard)
            alert = TO.apply_group_thresholds(s, grp, o["groups"], o["thresholds"], t0) & m
            out[tag] = {"alert": alert, "thresholds": dict(zip(map(int, o["groups"]), o["thresholds"], strict=True)),
                        "free": o["free_parameters"], "t_global": t0}  # fmt: skip
    elig = d["cal_n"] >= 100
    rest = neg & ~elig
    t4 = TO.global_threshold(s[rest], budget) if rest.any() else -np.inf
    a4 = ((pos & elig) | ((s > t4) & ~elig)) & m
    out["O4"] = {"alert": a4, "free": int(np.unique(d["key"][elig & m]).size) + 1, "t": t4}
    return out


def run_domain(name: str, d: dict) -> dict:
    res: dict = {"fits": {}}
    half = d["win"] < np.median(np.unique(d["win"]))
    for regime, r in FG.FITS:
        fk = f"{regime}_r{r}"
        z = FG.scores(name, regime, r)
        per_state = {}
        for state, s in (("S_U", z["s_ev_u"]), ("S_P", z["s_ev"])):
            o = oracles(d, s)
            row = {
                k: {**metrics(d, s, v["alert"]), "free_parameters": v["free"]}
                for k, v in o.items()
                if k != "budget"
            }
            row["budget"] = o["budget"]
            row["group_thresholds"] = {k: o[k]["thresholds"] for k in ("O2", "O2g", "O3", "O3g")}
            row["t_global"] = o["O0"]["t"]
            row["pauc_1pct"] = (
                TO.partial_auc(s[d["pos"]], s[d["neg"]]) if d["pos"].any() else float("nan")
            )
            maxes = [s[idx].max() for _, idx in d["ents"]]
            row["entity_separable_share"] = (
                float(np.mean([mx > o["O0"]["t"] for mx in maxes])) if maxes else None
            )
            # temporal fragility: select on the first half, apply to the second half
            first, second = half, ~half
            tf = {}
            if d["neg"][first].sum() >= 100 and d["neg"][second].sum() >= 100:
                o1 = oracles(d, s, first)
                o2 = oracles(d, s, second)
                for k in ("O0", "O2g", "O3g", "O2", "O3"):
                    if k == "O0":
                        a = (s > o1["O0"]["t"]) & second
                    else:
                        grp = d["act"] if k.startswith("O2") else d["svc"]
                        th = o1[k]["thresholds"]
                        a = (
                            TO.apply_group_thresholds(
                                s, grp, np.array(list(th)), list(th.values()), o1["O0"]["t"]
                            )
                            & second
                        )
                    tf[k] = {
                        "first_selected": metrics(d, s, a, second),
                        "second_in_sample": metrics(d, s, o2[k]["alert"], second),
                    }
            row["temporal"] = tf
            per_state[state] = row
        res["fits"][fk] = per_state
    res["structure"] = {"windows": int(d["key"].size), "benign": int(d["neg"].sum()), "positives": int(d["pos"].sum()),
                        "entities": len(d["ents"]), "hosts_cal_ge_100": int(np.unique(d["key"][d["cal_n"] >= 100]).size),
                        "benign_by_activity_group": {int(g): int((d["neg"] & (d["act"] == g)).sum()) for g in range(4)},
                        "pos_by_activity_group": {int(g): int((d["pos"] & (d["act"] == g)).sum()) for g in range(4)},
                        "benign_by_service_group": {int(g): int((d["neg"] & (d["svc"] == g)).sum()) for g in range(6)},
                        "pos_by_service_group": {int(g): int((d["pos"] & (d["svc"] == g)).sum()) for g in range(6)}}  # fmt: skip
    return res


def aggregate(per_dom: dict, state: str, method: str, field: str = "recall") -> dict:
    nets: dict = {}
    for n in BM.NETWORKS:
        doms = [x for x in per_dom if x.startswith(n + "/")]
        vals = [
            np.nanmean([per_dom[x]["fits"][fk][state][method][field] for x in doms])
            for fk in per_dom[doms[0]]["fits"]
        ]
        nets[n] = {
            "mean": float(np.mean(vals)),
            "min": float(np.min(vals)),
            "max": float(np.max(vals)),
        }
    return nets


def summary(per_dom: dict) -> dict:
    fits = list(next(iter(per_dom.values()))["fits"])
    out: dict = {}
    for state in ("S_U", "S_P"):
        out[state] = {}
        for meth in ("O0", "O2", "O2g", "O3", "O3g", "O4"):
            rec = aggregate(per_dom, state, meth)
            fpr = aggregate(per_dom, state, meth, "fpr")
            r20 = [sum(per_dom[x]["fits"][fk][state][meth]["r20"] for x in per_dom) for fk in fits]
            missed = [
                sum(per_dom[x]["fits"][fk][state][meth]["missed"] for x in per_dom) for fk in fits
            ]
            out[state][meth] = {"networks": {n: {"recall": rec[n]["mean"], "recall_fit_range": [rec[n]["min"], rec[n]["max"]],
                                                 "fpr": fpr[n]["mean"]} for n in BM.NETWORKS},
                                "macro_recall": float(np.mean([rec[n]["mean"] for n in BM.NETWORKS])),
                                "R20": float(np.mean(r20)), "missed_entities": float(np.mean(missed))}  # fmt: skip
        out[state]["pauc_1pct"] = {
            n: v["mean"] for n, v in aggregate(per_dom, state, "O0", "recall").items()
        }
        out[state]["pauc_1pct"] = {n: float(np.mean([np.nanmean([per_dom[x]["fits"][fk][state]["pauc_1pct"] for x in per_dom if x.startswith(n + "/")])
                                                     for fk in fits])) for n in BM.NETWORKS}  # fmt: skip
        out[state]["entity_separable_share"] = {n: float(np.mean([np.nanmean([per_dom[x]["fits"][fk][state]["entity_separable_share"]
                                                                              for x in per_dom if x.startswith(n + "/") and per_dom[x]["fits"][fk][state]["entity_separable_share"] is not None])
                                                                  for fk in fits])) for n in BM.NETWORKS}  # fmt: skip
    return out


def temporal_summary(per_dom: dict, state: str = "S_U") -> dict:
    fits = list(next(iter(per_dom.values()))["fits"])
    out = {}
    for n in BM.NETWORKS:
        doms = [x for x in per_dom if x.startswith(n + "/")]
        row = {}
        for k in ("O0", "O2g", "O3g", "O2", "O3"):
            for which in ("first_selected", "second_in_sample"):
                v = [np.nanmean([per_dom[x]["fits"][fk][state]["temporal"][k][which]["recall"] for x in doms
                                 if per_dom[x]["fits"][fk][state]["temporal"]]) for fk in fits]  # fmt: skip
                row[f"{k}|{which}"] = float(np.nanmean(v)) if not np.all(np.isnan(v)) else None
        out[n] = row
    return out


def gate(summ: dict, temp: dict, per_dom: dict) -> dict:
    u = summ["S_U"]
    best, best_gain = None, -np.inf
    for k in ("O2g", "O3g"):
        g = u[k]["macro_recall"] - u["O0"]["macro_recall"]
        if g > best_gain:
            best, best_gain = k, g
    r20_gain = u[best]["R20"] - u["O0"]["R20"]
    retained = {}
    for n, row in temp.items():
        ins = (
            None
            if row[f"{best}|second_in_sample"] is None
            else row[f"{best}|second_in_sample"] - row["O0|second_in_sample"]
        )
        out = (
            None
            if row[f"{best}|first_selected"] is None
            else row[f"{best}|first_selected"] - row["O0|first_selected"]
        )
        retained[n] = None if ins is None or out is None or ins <= 1e-12 else out / ins
        if ins is not None and ins <= 1e-12:
            retained[n] = "no in-sample gain"
    vals = [v for v in retained.values() if isinstance(v, float)]
    c3 = bool(vals) and float(np.mean(vals)) >= 0.5
    crit = {
        "i_macro_gain_ge_0.05": best_gain >= 0.05,
        "ii_R20_gain_ge_3": r20_gain >= 3,
        "iii_temporal_retention_ge_0.5": c3,
    }
    # entity bootstrap of the R20 gain (cluster = entity; per-entity gain averaged over fits)
    diffs = []
    for x in per_dom:
        fits = per_dom[x]["fits"]
        g = np.mean([np.array(f["S_U"][best]["entity_det20"], float) - np.array(f["S_U"]["O0"]["entity_det20"], float)
                     for f in fits.values()], axis=0)  # fmt: skip
        diffs.extend(np.atleast_1d(g).tolist())
    diffs = np.array(diffs)
    rng = np.random.default_rng(8)
    boot = (
        [diffs[rng.integers(0, diffs.size, diffs.size)].sum() for _ in range(2000)]
        if diffs.size
        else [0.0]
    )
    ci = [float(np.quantile(boot, 0.025)), float(np.quantile(boot, 0.975))]
    return {"best_constrained_oracle": best, "macro_gain": best_gain, "R20_gain": r20_gain,
            "R20_gain_entity_bootstrap_95": ci, "entities": int(diffs.size),
            "temporal_retention": retained, "criteria": crit,
            "verdict": "PASS" if all(crit.values()) else "FAIL"}  # fmt: skip


def atomic_write(path: Path, data: bytes) -> None:
    if path.exists():
        raise FileExistsError(f"{path} exists; completed results are never overwritten")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".partial")
    tmp.write_bytes(data)
    os.replace(tmp, path)


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
    hashes = {}
    for n in names:
        for regime, r in FG.FITS:
            rel = f"data/derived/phase8o/experiment_d/F0/{regime}/{n.replace('/', '__')}__r{r}.npz"
            h = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
            if reg.get(rel) != h:
                raise RuntimeError(f"{rel}: frozen score hash missing or different")
            hashes[rel] = h
    per_dom = {}
    for n in names:
        per_dom[n] = run_domain(n, load(n))
        print(n, "done", round(time.perf_counter() - t0, 1), "s", flush=True)
    summ = summary(per_dom) if len(names) == 9 else None
    temp = temporal_summary(per_dom) if summ else None
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()
    )
    res = {"status": "Phase 8t oracle feasibility (RETROSPECTIVE; thresholds chosen with evaluation labels; NOT deployable)",
           "provenance": {"git_sha": sha, "dirty_tree": dirty, "frozen_scores_sha256": hashes, "alpha": ALPHA, "guard": GUARD,
                          "activity_cuts": ACT_CUTS},
           "summary": summ, "temporal": temp, "gate_G1": gate(summ, temp, per_dom) if summ else None,
           "domains": per_dom, "runtime_s": time.perf_counter() - t0, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    body = json.dumps(res, indent=1, default=float).encode()
    atomic_write(OUT / f"oracle_feasibility{args.tag}.json", body)
    atomic_write(
        OUT / f"oracle_feasibility{args.tag}.sha256", hashlib.sha256(body).hexdigest().encode()
    )
    print("done", round(res["runtime_s"], 1), "s; peak", res["peak_rss_mb"], flush=True)


if __name__ == "__main__":
    main()
