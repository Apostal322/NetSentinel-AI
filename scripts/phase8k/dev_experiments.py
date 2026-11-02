"""Phase 8k development experiments [E] (docs/phase8k/). Re-thresholds the Phase 8j P1x scores
(seeds 0-2; each development network scored by a source model that never saw it); fits nothing
on any target.

1. Calibration construction (ablation), per domain and seed, at alpha = 1%:
   T0     split-conformal on the P1x hold-out (Phase 8i A1; Phase 8j M0)
   TX     the same over ALL P1x calibration windows (the source model never saw them)
   HB     host-balanced: every hold-out host has equal total weight; weighted (1 - alpha)
          quantile, alerts strictly above
   HC5    host-capped: no hold-out host carries more than 5% of the weight (water-filling)
   PAC    max(T0, PAC rank at the dependence-adjusted n_eff) (Phase 8j M3)
   HB+PAC max(HB, PAC)
   Reported: verified-benign FPR, window recall, entity recall, median delay, false alerts /h.
2. Failure decomposition: false alerts (at T0) from verified-benign hosts seen vs unseen in the
   calibration hold-out; per-host score shift (hold-out vs evaluation 95th percentile) of seen
   hosts; calibration age; unseen-host share. Explains WHY a calibration fails.
3. Network-level reliability decisions on the full calibration (decision-time information only):
   M0 always accept (T0) | M1 Phase 8i checks 1-3 (T0) | M2 PAC feasible with >= 10 hosts
   (threshold PAC) | M3 M2 and temporal self-consistency (T0 fitted on the first 70% of the
   calibration, exceedance of the last 30% <= 2 alpha) | M4 M2 with the host-balanced threshold
   (HB+PAC). Controls: always abstain, random selection (analytic). Adequacy (evaluation-only):
   realised verified-benign FPR of the decision's own threshold <= 2 alpha.
4. Within-network stress tests (NOT independent evidence): each domain's calibration re-drawn by
   host subsampling and recency truncation (Phase 8j variants); false acceptance / false
   rejection of every rule against the episode's own adequacy.

Output: reports/phase8k/dev_experiments.json
Usage: uv run python scripts/run_capped.py -- uv run python scripts/phase8k/dev_experiments.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8j"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
import threshold_stats as TS  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

# scripts/phase8c/dev_compare.py exists too: load the Phase 8j module under its own name
_spec = importlib.util.spec_from_file_location("phase8j_dev_compare",
                                               ROOT / "scripts/phase8j/dev_compare.py")  # fmt: skip
DC = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(DC)

ALPHA = 0.01
TOL = 2 * ALPHA
SEEDS = (0, 1, 2)
DEV = Path("data/derived/phase8j/dev")
OUT = Path("reports/phase8k/dev_experiments.json")
THRESHOLDS = ("T0", "TX", "HB", "HC5", "PAC", "HB+PAC")
RULES = ("M0", "M1", "M2", "M3", "M4")


# ----------------------------------------------------------------------------- thresholds
def weighted_threshold(s: np.ndarray, w: np.ndarray, alpha: float = ALPHA) -> float:
    """Smallest observed score whose weighted share of scores STRICTLY above it is <= alpha."""
    o = np.argsort(s)
    s, w = s[o], w[o] / w.sum()
    vals, first = np.unique(s, return_index=True)
    above = 1 - np.cumsum(w)[np.r_[first[1:] - 1, len(s) - 1]]  # weight strictly above each value
    return float(vals[np.argmax(above <= alpha + 1e-12)])


def host_weights(keys: np.ndarray, cap: float | None) -> np.ndarray:
    """Per-window weights: equal total weight per host (cap None), or the window share capped at
    `cap` per host with the excess spread over the others (water-filling)."""
    _, inv, m = np.unique(keys, return_inverse=True, return_counts=True)
    if cap is None or len(m) * cap <= 1:
        share = np.full(len(m), 1 / len(m))
    else:
        share = m / m.sum()
        for _ in range(100):
            over = share > cap + 1e-12
            if not over.any():
                break
            excess = (share[over] - cap).sum()
            share[over] = cap
            free = ~over & (share < cap)
            share[free] += excess * share[free] / share[free].sum()
    return (share / m)[inv]


def thresholds(c: dict, hold_s: np.ndarray, hold_k: np.ndarray, all_s: np.ndarray) -> dict:
    t0 = c["t0"]
    hb = weighted_threshold(hold_s, host_weights(hold_k, None))
    pac = c["t_m3"]
    return {"T0": t0, "TX": float(np.sort(all_s)[TS.k_of(len(all_s)) - 1]), "HB": hb,
            "HC5": weighted_threshold(hold_s, host_weights(hold_k, 0.05)),
            "PAC": pac, "HB+PAC": None if pac is None else max(hb, pac)}  # fmt: skip


# ----------------------------------------------------------------------------- metrics
def detection(d, thr: float) -> dict:
    ev = d.ev
    a, y, ben, key = ev["s"] > thr, ev["y"], ev["benign"], ev["key"]
    det, delays, elig = 0, [], 0
    for e in d.attackers:
        m = y & (key == e)
        if m.sum() < 5:
            continue
        elig += 1
        if (a & m).any():
            det += 1
            delays.append(float((ev["end"][a & m].min() - ev["end"][m].min()) / 1000))
    hours = max(float(np.ptp(ev["end"])) / 3.6e6, 1e-9)
    return {"fpr": float(a[ben].mean()) if ben.any() else None,
            "benign_windows": int(ben.sum()), "false_alerts": int(a[ben].sum()),
            "recall": float(a[y].mean()) if y.any() else None,
            "attack_windows": int(y.sum()), "entities": elig,
            "entity_recall": det / elig if elig else None,
            "median_delay_s": float(np.median(delays)) if delays else None,
            "false_alerts_per_h": float(a[ben].sum() / hours), "alerts_per_h": float(a.sum() / hours)}  # fmt: skip


def decomposition(
    d, hold_s: np.ndarray, hold_k: np.ndarray, hold_end: np.ndarray, t0: float
) -> dict:
    """Where do the false alerts at T0 come from, and how stable are the seen hosts?"""
    ev = d.ev
    ben = ev["benign"]
    seen = np.isin(ev["key"], hold_k)
    a = ev["s"] > t0
    shifts = []
    for h in np.unique(ev["key"][ben & seen]):
        e = ev["s"][ben & (ev["key"] == h)]
        c = hold_s[hold_k == h]
        if len(e) >= 20 and len(c) >= 20:
            shifts.append(float(np.quantile(e, 0.95) - np.quantile(c, 0.95)))
    fa = a & ben
    return {"benign_from_unseen_hosts": float((ben & ~seen).sum() / max(ben.sum(), 1)),
            "false_alerts_from_unseen_hosts": float((fa & ~seen).sum() / max(fa.sum(), 1)) if fa.any() else None,
            "fpr_seen_hosts": float(a[ben & seen].mean()) if (ben & seen).any() else None,
            "fpr_unseen_hosts": float(a[ben & ~seen].mean()) if (ben & ~seen).any() else None,
            "seen_hosts_with_shift": len(shifts),
            "median_p95_shift_seen_hosts": float(np.median(shifts)) if shifts else None,
            "calibration_age_h": float((np.median(ev["end"][ben]) - hold_end.max()) / 3.6e6) if ben.any() else None,
            "largest_false_alert_host_share": float(np.max(np.unique(ev["key"][fa], return_counts=True)[1]) / fa.sum())
            if fa.any() else None}  # fmt: skip


# ----------------------------------------------------------------------------- decisions
def temporal_consistency(btrain_s: np.ndarray, hold_s: np.ndarray) -> float | None:
    """Exceedance of the hold-out (last 30% of calibration) over T0 fitted on the first 70%."""
    if len(btrain_s) < 20 or len(hold_s) < 20:
        return None
    t = np.sort(btrain_s)[TS.k_of(len(btrain_s)) - 1]
    return float(np.mean(hold_s > t))


def decide(c: dict, th: dict, tc: float | None) -> dict[str, tuple[bool, float]]:
    """(accept, threshold) per rule, from decision-time information only."""
    m2 = c["t_m3"] is not None  # >= 10 hosts and a PAC rank exists
    return {"M0": (True, th["T0"]), "M1": (DC.m1_network_pass(c), th["T0"]),
            "M2": (m2, th["PAC"] if m2 else th["T0"]),
            "M3": (m2 and tc is not None and tc <= TOL, th["PAC"] if m2 else th["T0"]),
            "M4": (m2, th["HB+PAC"] if m2 else th["T0"])}  # fmt: skip


def rule_summary(rows: list[dict]) -> dict:
    """Network-decision table over (domain) rows for one rule: counts by adequacy."""
    acc = np.array([r["accept"] for r in rows])
    ok = np.array([r["adequate"] for r in rows])
    out = {"n": len(rows), "accepted": int(acc.sum()), "adequate": int(ok.sum()),
           "true_accept": int((acc & ok).sum()), "false_accept": int((acc & ~ok).sum()),
           "true_reject": int((~acc & ~ok).sum()), "false_reject": int((~acc & ok).sum())}  # fmt: skip
    out["false_acceptance_rate"] = (
        out["false_accept"] / max((~ok).sum(), 1) if (~ok).any() else None
    )
    out["false_rejection_rate"] = out["false_reject"] / max(ok.sum(), 1) if ok.any() else None
    out["far_wilson95"] = wilson(out["false_accept"], int((~ok).sum()))
    out["frr_wilson95"] = wilson(out["false_reject"], int(ok.sum()))
    return out


def wilson(k: int, n: int) -> tuple[float, float] | None:
    if n == 0:
        return None
    z, p = 1.959964, k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, c - h), min(1.0, c + h))


# ----------------------------------------------------------------------------- main
def main() -> None:
    t_start = time.perf_counter()
    names = sorted({p.name.split("__seed")[0] for p in DEV.glob("*__seed*.npz")})
    res = {"construction": {}, "decomposition": {}, "decisions": {}, "stress": {}}
    stress_rows: dict[str, list] = {r: [] for r in RULES}
    for seed in SEEDS:
        for i, name in enumerate(names):
            d = DC.Domain(DEV / f"{name}__seed{seed}.npz")
            hold = d.cal["hold"]
            rng = np.random.default_rng(20_000 * seed + i)
            for is_full, idx in DC.variants(d, rng):
                hs, hk = d.cal["s"][idx], d.cal["key"][idx]
                c = DC.calib(hs, hk, d.cal["win"][idx], d.cal["end"][idx], rng)
                hosts = np.unique(hk)
                bt = ~hold & np.isin(d.cal["key"], hosts)
                th = thresholds(c, hs, hk, d.cal["s"][bt | np.isin(np.arange(len(hold)), idx)])
                tc = temporal_consistency(d.cal["s"][bt], hs)
                dec = decide(c, th, tc)
                adeq_t0 = None
                for rule, (acc, thr) in dec.items():
                    m = detection(d, thr)
                    if rule == "M0":
                        adeq_t0 = m["fpr"] is not None and m["fpr"] <= TOL
                    row = {"domain": name, "seed": seed, "accept": bool(acc),
                           "adequate": bool(m["fpr"] is not None and m["fpr"] <= TOL),
                           "adequate_at_t0": adeq_t0, **m}  # fmt: skip
                    if is_full:
                        res["decisions"].setdefault(rule, []).append(row)
                    stress_rows[rule].append(row)
                if is_full:
                    res["construction"].setdefault(name, {})[seed] = {
                        k: (None if v is None else {"threshold": v, **detection(d, v)})
                        for k, v in th.items()
                    }
                    res["decomposition"].setdefault(name, {})[seed] = {
                        **decomposition(d, hs, hk, d.cal["end"][idx], th["T0"]),
                        "temporal_consistency": tc,
                        **{k: c[k] for k in ("n", "hosts", "eff_hosts", "top_share", "sess_neff",
                                             "m3_neff", "pac_l", "tie", "grouped")}}  # fmt: skip
            print(f"seed {seed} {name}: {time.perf_counter() - t_start:.0f} s", flush=True)
    # network-level decision tables on the real calibrations (development units)
    res["decision_tables"] = {}
    for rule in RULES:
        rows = res["decisions"][rule]
        res["decision_tables"][rule] = {"by_domain": rule_summary(rows)}
        nets = {}
        for r in rows:
            nets.setdefault(r["domain"].split("__")[0], []).append(r)
        res["decision_tables"][rule]["by_network_majority"] = {
            n: {"accept_share": float(np.mean([r["accept"] for r in v])),
                "adequate_share": float(np.mean([r["adequate"] for r in v]))} for n, v in nets.items()}  # fmt: skip
    # controls: always abstain; random selection at each rule's acceptance rate (expected values)
    rows0 = res["decisions"]["M0"]
    ok0 = np.array([r["adequate"] for r in rows0])
    res["controls"] = {"always_abstain": {"accepted": 0, "false_acceptance_rate": 0.0, "false_rejection_rate": 1.0},
                       "always_accept": rule_summary(rows0),
                       "random_at_rate": {rule: {"accept_rate": res["decision_tables"][rule]["by_domain"]["accepted"] / len(rows0),
                                                 "expected_false_acceptance_rate": res["decision_tables"][rule]["by_domain"]["accepted"] / len(rows0),
                                                 "expected_false_rejection_rate": 1 - res["decision_tables"][rule]["by_domain"]["accepted"] / len(rows0)}
                                          for rule in RULES},
                       "adequate_domains_at_t0": int(ok0.sum()), "domains": len(rows0)}  # fmt: skip
    # within-network stress tests: per domain, then the mean over domains (equal weights)
    for rule in RULES:
        per = {}
        for r in stress_rows[rule]:
            per.setdefault(r["domain"], []).append(r)
        dom = {n: rule_summary(v) for n, v in per.items()}
        far = [
            v["false_acceptance_rate"]
            for v in dom.values()
            if v["false_acceptance_rate"] is not None
        ]
        frr = [
            v["false_rejection_rate"] for v in dom.values() if v["false_rejection_rate"] is not None
        ]
        res["stress"][rule] = {"by_domain": dom,
                               "mean_false_acceptance_rate": float(np.mean(far)) if far else None,
                               "mean_false_rejection_rate": float(np.mean(frr)) if frr else None,
                               "pooled": rule_summary(stress_rows[rule])}  # fmt: skip
    res["seconds"] = round(time.perf_counter() - t_start, 1)
    res["peak_rss_mb"] = peak_rss_mb()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=float), "utf-8")
    for rule in RULES:
        print(
            rule,
            res["decision_tables"][rule]["by_domain"],
            "| stress",
            {
                k: res["stress"][rule][k]
                for k in ("mean_false_acceptance_rate", "mean_false_rejection_rate")
            },
        )


if __name__ == "__main__":
    main()
