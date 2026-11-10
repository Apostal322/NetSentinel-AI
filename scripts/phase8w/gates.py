"""Phase 8w registered decision rules (docs/phase8w/PREREGISTRATION.md § 6). Pure functions.

Input: `summary[scenario][arm][seed]`, each value an aggregate of one member's metrics
(`phase8u.experiment.aggregate`): per-network exact partial AUC at FPR ≤ 1 %, recall at the
retrospective 1 % FPR, as-calibrated recall and FPR, and the entities missed as calibrated.

Every comparison is the candidate member minus the matched null control `R0` with the same seed.
`R0` does not depend on the reference scenario.
"""

from __future__ import annotations

import numpy as np

NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
HARD = ("nfunsw", "nfton")
CANDIDATES = ("S", "A")
NULL = "R0"
SCREEN_SEEDS = (1060, 1061)
ALL_SEEDS = (1060, 1061, 1062, 1063, 1064)
DEPLOYABLE, ORACLE = "Z1", "Z3"

MIN_HARD = 0.02  # mean Δ partial AUC over NF-UNSW and NF-ToN
MIN_MACRO = 0.02  # mean Δ macro partial AUC
MAX_RECALL_LOSS = 0.10  # per network, recall at the retrospective 1 % FPR
CAL_RECALL_TOL = 0.03  # macro as-calibrated recall
CAL_FPR_TOL = {"nfcic": 0.01, "nfunsw": 0.01, "nfton": 0.01, "nfbot": 0.06}
MISSED_TOL = 2.0  # entities missed as calibrated (seed mean)
RETAIN = 0.5  # share of the oracle-reference gain the deployable reference must keep


def _seeds(cand: dict, base: dict, seeds: tuple[int, ...]) -> list[str]:
    return [str(s) for s in seeds if str(s) in cand and str(s) in base]


def _hard(a: dict) -> float:
    return float(np.mean([a["networks"][n]["pauc_1pct"] for n in HARD]))


def ranking(cand: dict, base: dict, seeds: tuple[int, ...]) -> dict:
    """Paired-seed ranking criteria. `complete` is False if a registered seed is missing."""
    ss = _seeds(cand, base, seeds)
    if not ss:
        return {"complete": False, "n_seeds": 0, "pass": False}
    hard = [_hard(cand[s]) - _hard(base[s]) for s in ss]
    macro = [cand[s]["macro_pauc_1pct"] - base[s]["macro_pauc_1pct"] for s in ss]
    per_net = {n: float(np.mean([cand[s]["networks"][n]["pauc_1pct"] - base[s]["networks"][n]["pauc_1pct"]
                                 for s in ss])) for n in NETS}  # fmt: skip
    out = {"complete": len(ss) == len(seeds), "n_seeds": len(ss),
           "delta_hard_by_seed": hard, "delta_macro_by_seed": macro,
           "mean_delta_hard": float(np.mean(hard)), "mean_delta_macro": float(np.mean(macro)),
           "mean_delta_pauc_by_network": per_net,
           "hard_positive_every_seed": bool(min(hard) > 0),
           "macro_positive_every_seed": bool(min(macro) > 0)}  # fmt: skip
    out["pass"] = bool(
        out["complete"]
        and out["mean_delta_hard"] >= MIN_HARD
        and out["mean_delta_macro"] >= MIN_MACRO
        and out["hard_positive_every_seed"]
        and out["macro_positive_every_seed"]
    )
    return out


def guardrails(cand: dict, base: dict, seeds: tuple[int, ...]) -> dict:
    """Guardrails on seed means: a candidate may not pass by alerting more, by alerting less, by
    losing a network, or by losing documented attacker entities."""
    ss = _seeds(cand, base, seeds)
    if not ss:
        return {"pass": False}

    def mean(src: dict, f) -> float:
        return float(np.mean([f(src[s]) for s in ss]))

    g = {}
    for n in NETS:
        d_rec = mean(cand, lambda a, n=n: a["networks"][n]["recall_1pct"]) - mean(base, lambda a, n=n: a["networks"][n]["recall_1pct"])  # fmt: skip
        d_fpr = mean(cand, lambda a, n=n: a["networks"][n]["calT_fpr"]) - mean(base, lambda a, n=n: a["networks"][n]["calT_fpr"])  # fmt: skip
        g[n] = {"delta_recall_1pct": d_rec, "recall_ok": bool(d_rec >= -MAX_RECALL_LOSS),
                "delta_calT_fpr": d_fpr, "fpr_ok": bool(d_fpr <= CAL_FPR_TOL[n])}  # fmt: skip
    d_cal = mean(cand, lambda a: a["macro_calT_recall"]) - mean(base, lambda a: a["macro_calT_recall"])  # fmt: skip
    d_miss = mean(cand, lambda a: a["missed_calT"]) - mean(base, lambda a: a["missed_calT"])
    d_hard = {n: mean(cand, lambda a, n=n: a["networks"][n]["pauc_1pct"]) - mean(base, lambda a, n=n: a["networks"][n]["pauc_1pct"])
              for n in HARD}  # fmt: skip
    out = {"per_network": g, "delta_macro_calT_recall": d_cal, "calT_recall_ok": bool(d_cal >= -CAL_RECALL_TOL),
           "delta_missed_calT": d_miss, "entities_ok": bool(d_miss <= MISSED_TOL),
           "delta_pauc_hard": d_hard, "hard_each_not_worse": bool(min(d_hard.values()) >= 0)}  # fmt: skip
    out["pass"] = bool(
        all(v["recall_ok"] and v["fpr_ok"] for v in g.values())
        and out["calT_recall_ok"]
        and out["entities_ok"]
        and out["hard_each_not_worse"]
    )
    return out


def screen(summary: dict) -> dict:
    """Two-seed screening of each candidate under the deployable and the oracle reference."""
    out = {}
    for arm in CANDIDATES:
        row = {}
        for sc in (DEPLOYABLE, ORACLE):
            cand, base = summary.get(sc, {}).get(arm, {}), summary.get(sc, {}).get(NULL, {})
            r = ranking(cand, base, SCREEN_SEEDS)
            g = guardrails(cand, base, SCREEN_SEEDS)
            row[sc] = {"ranking": r, "guardrails": g, "pass": bool(r["pass"] and g["pass"])}
        out[arm] = row
    return out


def select(screening: dict) -> dict:
    """At most one arm is replicated. Priority 1: it passes screening (ranking and guardrails)
    under the deployable reference. Priority 2: it meets the ranking criteria under the oracle
    reference; that replication can support G1 only. Ties: the larger hard-network gain."""
    for sc, scope, key in ((DEPLOYABLE, "G1, G3, G4", "pass"), (ORACLE, "G1 only", None)):
        ok = [a for a in CANDIDATES if a in screening and
              (screening[a][sc]["pass"] if key else screening[a][sc]["ranking"]["pass"])]  # fmt: skip
        if ok:
            best = max(ok, key=lambda a: screening[a][sc]["ranking"]["mean_delta_hard"])
            return {"arm": best, "scenario": sc, "scope": scope}
    return {"arm": None, "scenario": None, "scope": "no candidate passed screening; stop"}


def decide(summary: dict) -> dict:
    screening = screen(summary)
    choice = select(screening)
    out = {"screening": screening, "selected": choice,
           "G2": "NOT EVALUABLE: the context-conditioned arm is not fitted in this phase"}  # fmt: skip
    arm = choice["arm"]
    if arm is None:
        out.update({"G1": "NOT SUPPORTED", "G3": "NOT SUPPORTED", "G4": "NOT SUPPORTED",
                    "development": "DEVELOPMENT NO-GO", "replication": None})  # fmt: skip
        return out
    rep = {}
    for sc in (DEPLOYABLE, ORACLE):
        cand, base = summary[sc][arm], summary[sc][NULL]
        r, g = ranking(cand, base, ALL_SEEDS), guardrails(cand, base, ALL_SEEDS)
        rep[sc] = {"ranking": r, "guardrails": g}
    out["replication"] = rep
    if not rep[ORACLE]["ranking"]["complete"]:
        out.update({"G1": "NOT EVALUABLE: five-seed replication incomplete",
                    "G3": "NOT EVALUABLE: five-seed replication incomplete",
                    "G4": "NOT EVALUABLE: five-seed replication incomplete",
                    "development": "NOT EVALUABLE"})  # fmt: skip
        return out
    z1, z3 = rep[DEPLOYABLE]["ranking"], rep[ORACLE]["ranking"]
    g1 = z3["pass"] or z1["pass"]
    retained = (
        z3["mean_delta_macro"] <= 0 or z1["mean_delta_macro"] >= RETAIN * z3["mean_delta_macro"]
    )
    g3 = bool(z1["pass"] and retained)
    g4 = bool(z1["pass"] and rep[DEPLOYABLE]["guardrails"]["pass"])
    out.update({"G1": "SUPPORTED" if g1 else "NOT SUPPORTED",
                "G3": "SUPPORTED" if g3 else "NOT SUPPORTED",
                "G4": "SUPPORTED" if g4 else "NOT SUPPORTED",
                "retained_share_of_oracle_macro_gain": (z1["mean_delta_macro"] / z3["mean_delta_macro"]
                                                        if z3["mean_delta_macro"] > 0 else None),
                "development": ("DEVELOPMENT GO (single member; pending ensemble and independent confirmation)"
                                if g3 and g4 else "DEVELOPMENT NO-GO")})  # fmt: skip
    return out
