"""Phase 8r Experiments A (trusted-negative calibration) and B (bounded contamination of the
trusted set). docs/phase8r/PREREGISTRATION.md sections 4-5. Saved scores only (Phase 8o F0 =
frozen M2 construction, 6 fits, K = 5); no model fitted.

**Every threshold is computed on unlabelled-memory hold-out scores (`s_hold_u`) and applied to
unlabelled-memory evaluation scores (`s_ev_u`),** except the full oracle A1 (P1x scores). The
memory is therefore NOT cleaned by trusted evidence here (Experiment C).

**Vetting is ORACLE-SIMULATED** from the calibration labels (`cal_truth`): a T1 proxy for T3/T4.
Labels also enter the metrics (V2 documented attackers vs the historical benign set, and the
Phase 8q audit categories). They never enter a selection policy.

References per fit:
- A0: U, the unlabelled conformal T0;
- A1: P, the full oracle (P1x threshold and memory);
- A1T: the oracle threshold on unlabelled memory (benign hold-out windows; Phase 8q cell T),
  the ceiling of any threshold-only method.

Output: reports/phase8r/experiment_a.json, reports/phase8r/experiment_b.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8r/experiment_ab.py [--only A|B]
       [--draws 20] [--domains nfunsw/all,...]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
import time
import zlib
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
TM = _load("phase8r_tm", "scripts/phase8r/trusted_methods.py")
CD, BM = FG.CD, FG.BM
OUT_A = ROOT / "reports" / "phase8r" / "experiment_a.json"
OUT_B = ROOT / "reports" / "phase8r" / "experiment_b.json"
FITS = FG.FITS
BUDGETS = {"small": 3, "modest": 10, "larger": 30}
ERRORS = ((0.10, 0.0), (0.25, 0.0), (0.25, 0.05))
METHODS = ("A2", "A3", "A4", "A5")
MECHANISMS = ("random", "persistent", "coordinated", "burst", "gradual", "service_matched")
FRACTIONS = (0.01, 0.02, 0.05, 0.10)
CATEGORIES = BM.LA.CATEGORIES
PRIMARY = ("modest", "random", "e0", "A3")


def seed(*parts) -> np.random.Generator:
    return np.random.default_rng([zlib.crc32(str(p).encode()) for p in parts])


def load(name: str) -> dict:
    net, dom = name.split("/")
    d = FG.domain_data(name)
    cal = pl.read_parquet(CD.I8 / net / dom / "cal_unlabelled.parquet",
                          columns=["key", "win", "window_end_ms", "udp_share", "dst_ports"]).sort("win", "key")  # fmt: skip
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    cal = cal.filter(pl.col("win") >= lo + int(math.floor((hi - lo + 1) * 0.7)))
    if not np.array_equal(cal["key"].to_numpy().astype(str), d["hu_key"]):
        raise RuntimeError(f"{name}: hold-out order differs")
    d["udp"] = cal["udp_share"].to_numpy().astype(float)
    d["ports"] = cal["dst_ports"].to_numpy().astype(float)
    d["meta"] = TM.host_meta(d["hu_key"], d["hu_end"], d["udp"], d["ports"])
    inv = d["meta"]["inv"]
    d["mal_host"] = (
        np.bincount(inv, weights=d["is_att"].astype(float), minlength=d["meta"]["uniq"].size) > 0
    )
    a = pl.read_parquet(BM.AUDIT / f"{name.replace('/', '__')}.parquet")
    d["cat"] = a["category"].to_numpy().astype(str)
    ents = BM.entities(d["key"], d["pos"])
    d["ents"] = [(e, d["pos"] & (d["key"] == e)) for e in ents]
    return d


class Evaluator:
    """Window and entity metrics of a threshold by binary search on sorted scores."""

    def __init__(self, d: dict, s_ev: np.ndarray) -> None:
        self.pos = np.sort(s_ev[d["pos"]])
        self.neg = np.sort(s_ev[d["neg"]])
        self.ents = [np.sort(s_ev[m]) for _, m in d["ents"]]
        self.cats = {c: np.sort(s_ev[d["cat"] == c]) for c in CATEGORIES if (d["cat"] == c).any()}
        self.hours = d["hours"]

    @staticmethod
    def above(a: np.ndarray, t: float) -> int:
        return int(a.size - np.searchsorted(a, t, side="right"))

    def __call__(self, t: float, cats: bool = False) -> dict:
        fa = self.above(self.neg, t)
        out = {"recall": self.above(self.pos, t) / self.pos.size if self.pos.size else np.nan,
               "fpr": fa / self.neg.size, "fa_h": fa / self.hours,
               "r20": sum(self.above(e, t) >= 0.2 * e.size - 1e-9 for e in self.ents)}  # fmt: skip
        if cats:
            out["cats"] = {c: self.above(a, t) / a.size for c, a in self.cats.items()}
        return out


NO_ALERT = {"recall": 0.0, "fpr": 0.0, "fa_h": 0.0, "r20": 0}


def trusted_mask(d: dict, accepted: np.ndarray, interval_hour: int | None = None) -> np.ndarray:
    m = np.isin(d["meta"]["inv"], accepted)
    if interval_hour is not None:
        m &= d["meta"]["hour"] == interval_hour
    return m


def estimate(d: dict, s: np.ndarray, trusted: np.ndarray, vetted: np.ndarray, malicious: np.ndarray,
             rng: np.random.Generator, t_u: float) -> dict:  # fmt: skip
    """Thresholds of A2-A5 (None = abstain). An empty trusted set falls back to U (A2-A4)."""
    inv, hour = d["meta"]["inv"], d["meta"]["hour"]
    if not trusted.any():
        return {"A2": t_u, "A3": t_u, "A4": t_u, "A5": None, "fallback": True}
    a3 = TM.anchored_t0(s, inv, trusted, vetted, malicious)
    return {"A2": TM.trusted_t0(s, trusted), "A3": a3, "A4": TM.cluster_upper_t0(s, inv, trusted, rng),
            "A5": a3 if TM.enough_evidence(inv, hour, trusted) else None, "fallback": False}  # fmt: skip


def configs(draws: int) -> list[tuple]:
    """(budget, policy, error id, e_fb, e_fm, vetting, n draws)."""
    out = []
    for b in BUDGETS:
        for p in TM.POLICIES:
            out.append((b, p, "e0", 0.0, 0.0, True, 1 if p == "admin_persistent" else draws))
        out.append((b, "admin_persistent", "naive_T2", 0.0, 0.0, False, 1))
    out.append(("interval_1h", "interval", "e0", 0.0, 0.0, True, draws))
    for fb, fm in ERRORS:
        for p in ("random", "admin_persistent"):
            out.append(("modest", p, f"fb{fb}_fm{fm}", fb, fm, True, draws))
    return out


def run_config(
    d: dict, s: np.ndarray, cfg: tuple, draw: int, fit: str, name: str, t_u: float
) -> dict:
    budget, policy, eid, fb, fm, vetting, _ = cfg
    rng = seed(name, fit, budget, policy, eid, draw)
    meta = d["meta"]
    n_h = meta["uniq"].size
    hour = None
    if budget == "interval_1h":
        hour = int(rng.choice(np.unique(meta["hour"])))
        chosen = np.unique(meta["inv"][meta["hour"] == hour])
    else:
        chosen = TM.select(policy, meta, BUDGETS[budget], rng)
    if vetting:
        accepted, found = TM.vet(chosen, d["mal_host"], rng, fb, fm)
    else:
        accepted, found = chosen, np.array([], dtype=int)
    trusted = trusted_mask(d, accepted, hour)
    vetted = np.zeros(n_h, bool)
    vetted[chosen] = True
    malicious = np.zeros(n_h, bool)
    malicious[found] = True
    th = estimate(
        d, s, trusted, vetted, malicious, seed(name, fit, budget, policy, eid, draw, "boot"), t_u
    )
    blocks = (
        np.unique(np.stack([meta["inv"][trusted], meta["hour"][trusted]]), axis=1).shape[1]
        if trusted.any()
        else 0
    )
    effort = {"vetted_hosts": int(chosen.size), "malicious_found": int(found.size),
              "malicious_accepted": int(d["mal_host"][accepted].sum()),
              "trusted_hosts": int(np.unique(meta["inv"][trusted]).size), "trusted_windows": int(trusted.sum()),
              "trusted_host_hours": int(blocks), "reviewed_host_hours": int(meta["active_hours"][chosen].sum())
              if hour is None else int(chosen.size), "fallback": th["fallback"],
              "attack_windows_in_trusted": int((trusted & d["is_att"]).sum())}  # fmt: skip
    return {
        "th": th,
        "effort": effort,
        "trusted": trusted,
        "vetted": vetted,
        "malicious": malicious,
    }


def aggregate(rows: dict, names: list[str]) -> dict:
    """rows[(name, fit, draw)] = metrics dict -> network means and draw percentiles."""
    draws = sorted({k[2] for k in rows})
    out = {"networks": {}, "draws": len(draws)}
    per_draw_macro = []
    net_draw = {n: {"recall": [], "fpr": []} for n in BM.NETWORKS}
    for dr in draws:
        macro = []
        for n in BM.NETWORKS:
            doms = [x for x in names if x.startswith(n + "/")]
            rec, fpr = [], []
            for _fi, fit in enumerate(FITS):
                fk = f"{fit[0]}_r{fit[1]}"
                rec.append(
                    np.nanmean(
                        [rows[(x, fk, dr)]["recall"] for x in doms if (x, fk, dr) in rows]
                        or [np.nan]
                    )
                )
                fpr.append(
                    np.nanmean(
                        [rows[(x, fk, dr)]["fpr"] for x in doms if (x, fk, dr) in rows] or [np.nan]
                    )
                )
            net_draw[n]["recall"].append(float(np.nanmean(rec)))
            net_draw[n]["fpr"].append(float(np.nanmean(fpr)))
            macro.append(float(np.nanmean(rec)))
        per_draw_macro.append(float(np.nanmean(macro)))
    for n in BM.NETWORKS:
        r, f = np.array(net_draw[n]["recall"]), np.array(net_draw[n]["fpr"])
        if np.isnan(r).all():
            continue
        fah = [rows[k]["fa_h"] for k in rows if k[0].startswith(n + "/")]
        out["networks"][n] = {"recall": float(np.nanmean(r)), "recall_p10_p90": [float(np.nanquantile(r, 0.1)), float(np.nanquantile(r, 0.9))],
                              "fpr": float(np.nanmean(f)), "fpr_p10_p90": [float(np.nanquantile(f, 0.1)), float(np.nanquantile(f, 0.9))],
                              "false_alerts_per_h": float(np.mean(fah))}  # fmt: skip
    m = np.array(per_draw_macro)
    out["macro_recall"] = float(np.nanmean(m))
    out["macro_p10_p90"] = [float(np.nanquantile(m, 0.1)), float(np.nanquantile(m, 0.9))]
    r20 = {}
    for (_x, fk, dr), v in rows.items():
        r20[(fk, dr)] = r20.get((fk, dr), 0) + v["r20"]
    out["mean_R20"] = float(np.mean(list(r20.values())))
    return out


def experiment_a(names: list[str], data: dict, draws: int) -> dict:
    cfgs = configs(draws)
    rows: dict = {}
    eff: dict = {}
    cats: dict = {}
    refs: dict = {"A0": {}, "A1": {}, "A1T": {}}
    for name in names:
        d = data[name]
        t_start = time.perf_counter()
        for regime, r in FITS:
            fk = f"{regime}_r{r}"
            z = FG.scores(name, regime, r)
            ev_u, ev_p = Evaluator(d, z["s_ev_u"]), Evaluator(d, z["s_ev"])
            s = z["s_hold_u"]
            t_u = TM.t0(s)
            t_t = TM.t0(s[~d["is_att"]]) if (~d["is_att"]).any() else math.inf
            for ref, (ev, t) in {
                "A0": (ev_u, t_u),
                "A1": (ev_p, TM.t0(z["s_hold"])),
                "A1T": (ev_u, t_t),
            }.items():
                m = ev(t, cats=True)
                refs[ref][(name, fk, 0)] = m
                cats.setdefault(ref, []).append((name, m["cats"]))
            for cfg in cfgs:
                cid = "|".join(map(str, cfg[:3]))
                for dr in range(cfg[6]):
                    res = run_config(d, s, cfg, dr, fk, name, t_u)
                    eff.setdefault(cid, []).append((name, res["effort"]))
                    for meth in METHODS:
                        t = res["th"][meth]
                        primary = (cid, meth) == ("|".join(PRIMARY[:3]), PRIMARY[3])
                        m = NO_ALERT if t is None else ev_u(t, cats=primary)
                        rows.setdefault((cid, meth), {})[(name, fk, dr)] = m
                        if primary and t is not None:
                            cats.setdefault("primary", []).append((name, m["cats"]))
                        if meth == "A5":
                            rows.setdefault((cid, "A5_abstained"), {})[(name, fk, dr)] = {
                                "recall": float(t is None),
                                "fpr": 0.0,
                                "fa_h": 0.0,
                                "r20": 0,
                            }
        print(name, "done", round(time.perf_counter() - t_start, 1), "s", flush=True)
    res: dict = {"status": "Experiment A (saved scores; ORACLE-SIMULATED vetting; labels in metrics only)",
                 "references": {k: aggregate(v, names) for k, v in refs.items()}, "cells": {}, "effort": {},
                 "categories": {}}  # fmt: skip
    for (cid, meth), v in rows.items():
        res["cells"].setdefault(cid, {})[meth] = (
            aggregate(v, names)
            if meth != "A5_abstained"
            else {"abstention_rate": float(np.mean([x["recall"] for x in v.values()]))}
        )
    for cid, lst in eff.items():
        res["effort"][cid] = {n: {k: float(np.mean([e[k] for x, e in lst if x.startswith(n + "/")]))
                                  for k in lst[0][1]} for n in BM.NETWORKS}  # fmt: skip
    for k, lst in cats.items():
        res["categories"][k] = {n: {c: float(np.mean([m[c] for x, m in lst if x.startswith(n + "/") and c in m]))
                                    for c in CATEGORIES if any(c in m for x, m in lst if x.startswith(n + "/"))}
                                for n in BM.NETWORKS}  # fmt: skip
    res["decision_H_A1"] = decide_a(res)
    return res


def decide_a(res: dict) -> dict:
    cell = res["cells"]["|".join(PRIMARY[:3])][PRIMARY[3]]
    a0, a1t = res["references"]["A0"], res["references"]["A1T"]
    gain = cell["macro_recall"] - a0["macro_recall"]
    gap = a1t["macro_recall"] - a0["macro_recall"]
    fpr_ok = {
        n: cell["networks"][n]["fpr"] <= a1t["networks"][n]["fpr"] + 0.02 for n in cell["networks"]
    }
    tail_ok = {
        n: cell["networks"][n]["fpr_p10_p90"][1] <= a1t["networks"][n]["fpr"] + 0.05
        for n in cell["networks"]
    }
    crit = {"i_gain_ge_0.10": gain >= 0.10, "ii_fpr_mean": all(fpr_ok.values()),
            "iii_half_gap": gain >= 0.5 * gap, "iv_fpr_p90": all(tail_ok.values())}  # fmt: skip
    return {"gain": gain, "oracle_threshold_gap": gap, "fpr_ok": fpr_ok, "tail_ok": tail_ok,
            "criteria": crit, "verdict": "SUPPORTED" if all(crit.values()) else "NOT SUPPORTED"}  # fmt: skip


def experiment_b(names: list[str], data: dict, draws: int) -> dict:
    cfg = ("modest", "random", "e0", 0.0, 0.0, True, draws)
    rows: dict = {}
    skipped: dict = {}
    evaluable = [n for n in names if data[n]["is_att"].any()]
    for name in evaluable:
        d = data[name]
        att_idx = np.flatnonzero(d["is_att"])
        for regime, r in FITS:
            fk = f"{regime}_r{r}"
            z = FG.scores(name, regime, r)
            ev = Evaluator(d, z["s_ev_u"])
            s = z["s_hold_u"]
            t_u = TM.t0(s)
            for dr in range(draws):
                base = run_config(d, s, cfg, dr, fk, name, t_u)
                if not base["trusted"].any():
                    skipped[(name, fk, dr)] = "empty trusted set"
                    continue
                for meth in ("A2", "A3", "A4"):
                    rows.setdefault(("clean", 0.0, meth), {})[(name, fk, dr)] = ev(base["th"][meth])
                for mech in MECHANISMS:
                    for frac in FRACTIONS:
                        rng = seed(name, fk, dr, mech, frac, "inject")
                        idx = TM.contaminate(mech, frac, int(base["trusted"].sum()), att_idx, d["meta"]["inv"],
                                             d["hu_end"], d["udp"], d["ports"], base["trusted"], rng)  # fmt: skip
                        if idx is None:
                            skipped[(name, fk, dr, mech, frac)] = "no eligible attacker windows"
                            continue
                        tr = base["trusted"].copy()
                        tr[idx] = True
                        vetted = base["vetted"].copy()
                        vetted[np.unique(d["meta"]["inv"][idx])] = (
                            True  # hosts with trusted windows count as vetted
                        )
                        th = estimate(
                            d,
                            s,
                            tr,
                            vetted,
                            base["malicious"],
                            seed(name, fk, dr, mech, frac, "boot"),
                            t_u,
                        )
                        for meth in ("A2", "A3", "A4"):
                            rows.setdefault((mech, frac, meth), {})[(name, fk, dr)] = ev(th[meth])
        print(name, "B done", flush=True)
    res: dict = {"status": "Experiment B (saved scores; real calibration-attacker windows marked trusted)",
                 "evaluable_domains": evaluable, "not_evaluable": [n for n in names if n not in evaluable],
                 "skipped_counts": {}, "cells": {}}  # fmt: skip
    for k in skipped:
        key = "|".join(map(str, k[3:])) if len(k) > 3 else "empty_trusted"
        res["skipped_counts"][key] = res["skipped_counts"].get(key, 0) + 1
    clean = {m: aggregate(rows[("clean", 0.0, m)], evaluable) for m in ("A2", "A3", "A4")}
    res["clean"] = clean
    for (mech, frac, meth), v in rows.items():
        if mech == "clean":
            continue
        # paired: the clean rows restricted to the same (domain, fit, draw) keys
        cl = aggregate({k: rows[("clean", 0.0, meth)][k] for k in v}, evaluable)
        ag = aggregate(v, evaluable)
        ag["delta_macro_recall"] = ag["macro_recall"] - cl["macro_recall"]
        ag["delta_fpr"] = {
            n: ag["networks"][n]["fpr"] - cl["networks"][n]["fpr"]
            for n in ag["networks"]
            if n in cl["networks"]
        }
        ag["delta_recall"] = {
            n: ag["networks"][n]["recall"] - cl["networks"][n]["recall"]
            for n in ag["networks"]
            if n in cl["networks"]
        }
        res["cells"].setdefault(meth, {}).setdefault(mech, {})[str(frac)] = ag
    res["breakdown_fraction"] = {meth: {mech: next((f for f in FRACTIONS if str(f) in cells
                                                    and cells[str(f)]["delta_macro_recall"] <= -0.10), None)
                                        for mech, cells in v.items()} for meth, v in res["cells"].items()}  # fmt: skip
    a3 = res["cells"].get("A3", {})
    ok = {
        mech: cells["0.05"]["delta_macro_recall"] >= -0.10
        for mech, cells in a3.items()
        if "0.05" in cells
    }
    res["decision_H_B1"] = {"criterion": "A3 modest/random: macro recall loss <= 0.10 at 5 % under every evaluable mechanism",
                            "per_mechanism": ok, "verdict": ("SUPPORTED" if ok and all(ok.values()) else
                                                             "NOT SUPPORTED" if ok else "NOT EVALUABLE")}  # fmt: skip
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=("A", "B"))
    ap.add_argument("--draws", type=int, default=20)
    ap.add_argument("--domains")
    ap.add_argument("--out-suffix", default="")
    args = ap.parse_args()
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    if args.domains:
        names = [n for n in names if n in args.domains.split(",")]
    t = time.perf_counter()
    data = {n: load(n) for n in names}
    print("loaded", round(time.perf_counter() - t, 1), "s", flush=True)
    OUT_A.parent.mkdir(parents=True, exist_ok=True)
    if args.only in (None, "A"):
        res = experiment_a(names, data, args.draws)
        p = OUT_A.with_name(OUT_A.stem + args.out_suffix + ".json")
        p.write_bytes(json.dumps(res, indent=1, default=float).encode())
        print("H_A1", res["decision_H_A1"], flush=True)
    if args.only in (None, "B"):
        res = experiment_b(names, data, args.draws)
        p = OUT_B.with_name(OUT_B.stem + args.out_suffix + ".json")
        p.write_bytes(json.dumps(res, indent=1, default=float).encode())
        print("H_B1", res["decision_H_B1"], flush=True)
    print("total", round(time.perf_counter() - t, 1), "s", flush=True)


if __name__ == "__main__":
    main()
