"""Phase 8j: can the calibration eligibility thresholds be justified statistically? [E]

Uses no network data. Three parts, written to reports/phase8j/threshold_stats.json:

A. Exact i.i.d. theory. The split-conformal T0 is the k-th smallest of n hold-out scores,
   k = ceil((n + 1)(1 - alpha)). For exchangeable scores its exceedance probability (the FPR on
   new windows, conditional on the calibration) is Beta(n + 1 - k, k). For each n: the mean,
   P(FPR > 2 alpha) and the 95th percentile; and the smallest n from which the 95th (90th)
   percentile stays <= 2 alpha.
B. Evidence needed to CLAIM a realised FPR: the smallest number of independent benign
   evaluation windows for which an observed 1% has a Clopper-Pearson 95% upper bound <= 2%.
C. Simulation of dependent calibration data (the failure mode seen on NF-UNSW-NB15-v3 and
   NF-BoT-IoT-v3). Score of host h, window t: z = u_h + sqrt(1 - rho) e_t, u_h ~ N(0, rho),
   e an AR(1) series per host (phi = 0.9, unit variance), so z ~ N(0, 1) over the host
   population and the population FPR of a threshold t is 1 - Phi(t). Host sizes are equal or
   Zipf. For every configuration (hosts H, windows n, rho, skew) and replicate, the
   eligibility statistics are computed from the calibration only, exactly as in
   scripts/phase8i/calibration_audit.py, and compared with the true population FPR. Reported:
   P(FPR > 2 alpha), each rule's pass rate, and P(FPR > 2 alpha | pass).

The model is exchangeable across hosts: it covers small and dependent calibration, not drift
between calibration and evaluation, which needs real data (leakage_audit / reliability study).

Usage: uv run python scripts/phase8j/threshold_stats.py [--reps 300]
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8i"))
from calibration_audit import eff_n, grouped_exceedance, icc  # noqa: E402

ALPHA = 0.01
OUT = Path("reports/phase8j/threshold_stats.json")
HOSTS = (2, 3, 5, 10, 20, 50)
NS = (250, 1000, 4000)
RHOS = (0.0, 0.2, 0.5, 0.9)
SKEWS = (0.0, 1.0)  # host-size exponent: 0 = equal sizes, 1 = Zipf
PHIS = (0.5, 0.9)  # within-host AR(1) coefficient


def k_of(n: int, alpha: float = ALPHA) -> int:
    return min(math.ceil((n + 1) * (1 - alpha)), n)


def iid_table(n_max: int = 5000) -> dict:
    from scipy.stats import beta

    rows, last_bad = {}, {0.95: 0, 0.90: 0}
    for n in range(50, n_max + 1):
        k = k_of(n)
        a, b = n + 1 - k, k
        q95, q90 = beta.ppf(0.95, a, b), beta.ppf(0.90, a, b)
        for q, v in ((0.95, q95), (0.90, q90)):
            if v > 2 * ALPHA:
                last_bad[q] = n
        if n in (99, 150, 198, 199, 250, 300, 500, 1000, 2000, 5000):
            rows[n] = {"k": k, "mean": a / (n + 1), "p_fpr_above_2alpha": float(beta.sf(2 * ALPHA, a, b)),
                       "q95": float(q95)}  # fmt: skip
    return {"by_n": rows, "n_from_which_q95_le_2alpha": last_bad[0.95] + 1,
            "n_from_which_q90_le_2alpha": last_bad[0.90] + 1}  # fmt: skip


def claim_table(n_max: int = 6000) -> dict:
    """Independent benign windows needed so that an observed 1% (x = ceil(0.01 n) alerts) has a
    one-sided Clopper-Pearson 95% upper bound <= target: the first n that works, and the n
    from which it always works up to n_max (the bound is not monotone in n)."""
    from scipy.stats import beta

    out = {}
    for target in (0.02, 0.015):
        ok = [beta.ppf(0.95, math.ceil(0.01 * n) + 1, n - math.ceil(0.01 * n)) <= target
              for n in range(100, n_max + 1)]  # fmt: skip
        first = 100 + ok.index(True)
        always = 100 + len(ok) - next(i for i, v in enumerate(reversed(ok)) if not v)
        out[f"upper95_le_{target}"] = {"first": first, "from_which_always": always}
    return {"independent_windows_needed_at_observed_1pct": out}


_PAC: dict[int, int] = {}


def pac_exceedances(n: int, eps: float = 2 * ALPHA, delta: float = 0.05) -> int:
    """Largest l such that the (n + 1 - l)-th order statistic of n exchangeable scores has
    P(FPR > eps) <= delta (training-conditional conformal, Vovk 2012); 0 if none."""
    from scipy.stats import beta

    if n not in _PAC:
        lo = 0
        for cnt in range(1, n + 1):
            if beta.sf(eps, cnt, n + 1 - cnt) > delta:
                break
            lo = cnt
        _PAC[n] = lo
    return _PAC[n]


def pac_threshold(z: np.ndarray, n_eff: float) -> float | None:
    """Dependence-aware PAC threshold (M3): the PAC exceedance count for n_eff independent
    observations, turned into a rank of all n scores (an order statistic, no interpolation;
    alerts are scores strictly above it, so ties at the threshold never alert), and never below
    the plain conformal T0 (at large n_eff the PAC rank alone is looser than the 1% target);
    None (abstain) if no count is safe."""
    ne = int(math.floor(n_eff)) if math.isfinite(n_eff) else 0
    lo = pac_exceedances(ne) if ne >= 1 else 0
    if lo < 1:
        return None
    s = np.sort(z)
    k = min(len(s), max(k_of(len(s)), math.ceil(len(s) * (1 - lo / (ne + 1)))))
    return float(s[k - 1])


def lag1(z: np.ndarray, hosts: np.ndarray) -> float:
    """Pooled within-host lag-1 autocorrelation (each host demeaned; rows in time order)."""
    _, inv = np.unique(hosts, return_inverse=True)
    d = z - (np.bincount(inv, z) / np.bincount(inv))[inv]
    same = hosts[1:] == hosts[:-1]
    den = float(np.sum(d**2))
    return float(np.sum(d[1:][same] * d[:-1][same]) / den) if den > 0 else 0.0


def neff_m3(z: np.ndarray, hosts: np.ndarray) -> float:
    """M3's effective n: each host's windows deflated by the AR(1) design effect
    (1 + r) / (1 - r) of the pooled within-host lag-1 autocorrelation r, then the Kish
    host-cluster correction with the ANOVA ICC (nan with < 2 hosts)."""
    r = min(max(lag1(z, hosts), 0.0), 0.99)
    m = np.unique(hosts, return_counts=True)[1] / ((1 + r) / (1 - r))
    rho = icc(z, hosts)
    return eff_n(m.astype(float), rho) if not math.isnan(rho) else float("nan")


def sizes(h: int, n: int, skew: float) -> np.ndarray:
    w = np.arange(1, h + 1, dtype=float) ** -skew
    m = np.maximum(1, np.floor(n * w / w.sum())).astype(int)
    m[0] += n - m.sum()
    return m


def ar1(rng: np.random.Generator, m: int, phi: float) -> np.ndarray:
    from scipy.signal import lfilter

    v = rng.standard_normal(m) * math.sqrt(1 - phi**2)
    v[0] = rng.standard_normal()  # x_0 ~ N(0, 1): the series is stationary from the start
    return lfilter([1.0], [1.0, -phi], v)


def replicate(rng: np.random.Generator, h: int, n: int, rho: float, skew: float,
              phi: float) -> dict:  # fmt: skip
    from scipy.stats import norm

    m = sizes(h, n, skew)
    u = rng.standard_normal(h) * math.sqrt(rho)
    z = np.concatenate([u[i] + math.sqrt(1 - rho) * ar1(rng, m[i], phi) for i in range(h)])
    hosts = np.repeat(np.arange(h), m)
    t = np.sort(z)[k_of(n) - 1]
    ge = grouped_exceedance(z, hosts)
    rho_hat = icc(z, hosts)
    n_eff = eff_n(m.astype(float), rho_hat) if not math.isnan(rho_hat) else float(n)
    tp = pac_threshold(z, neff_m3(z, hosts)) if h >= 10 else None
    return {"fpr": float(norm.sf(t)), "n_eff": n_eff,
            "pac_fpr": None if tp is None else float(norm.sf(tp)),
            "hosts": h, "eff_hosts": float(m.sum() ** 2 / np.sum(m.astype(float) ** 2)),
            "top_share": float(m.max() / m.sum()), "grouped": ge.get("exceedance", float("nan")),
            "cluster_ucb": cluster_ucb(z > t, hosts, rng),
            "loho_ucb": cluster_ucb(out_of_fold_exceedance(z, hosts), hosts, rng)}  # fmt: skip


def out_of_fold_exceedance(s: np.ndarray, hosts: np.ndarray, folds: int = 10) -> np.ndarray:
    """Per window: does it exceed the T0 fitted on the OTHER host folds? (Host folds as in
    calibration_audit.grouped_exceedance: hosts by size, dealt round-robin into <= 10 folds.)"""
    uniq, inv, cnt = np.unique(hosts, return_inverse=True, return_counts=True)
    if len(uniq) < 2:
        return np.zeros(len(s), dtype=bool)
    rank = np.empty(len(uniq), dtype=int)
    rank[np.argsort(-cnt, kind="stable")] = np.arange(len(uniq))
    f = (rank % min(folds, len(uniq)))[inv]
    out = np.zeros(len(s), dtype=bool)
    for k in np.unique(f):
        out[f == k] = s[f == k] > np.sort(s[f != k])[k_of(int((f != k).sum())) - 1]
    return out


def cluster_ucb(exceed: np.ndarray, hosts: np.ndarray, rng: np.random.Generator,
                b: int = 400, q: float = 0.95) -> float:  # fmt: skip
    """Upper q-quantile of the exceedance rate at the fitted threshold when HOSTS (with all
    their windows) are resampled with replacement: a dependence-aware upper bound that widens
    when few hosts carry the tail."""
    _, inv = np.unique(hosts, return_inverse=True)
    e, m = np.bincount(inv, exceed.astype(float)), np.bincount(inv).astype(float)
    w = rng.multinomial(len(m), np.full(len(m), 1 / len(m)), size=b).astype(float)
    return float(np.quantile((w @ e) / (w @ m), q))


RULES = {
    "n_eff_ge_199": lambda r: r["n_eff"] >= 199,
    "eff_hosts_ge_10_top_le_25pct": lambda r: r["eff_hosts"] >= 10 and r["top_share"] <= 0.25,
    "grouped_le_2alpha": lambda r: r["grouped"] <= 2 * ALPHA,
}
_PROPOSED = tuple(RULES.values())
RULES["all_three"] = lambda r: all(f(r) for f in _PROPOSED)
RULES["n_eff_ge_313_hosts_ge_10"] = lambda r: r["n_eff"] >= 313 and r["hosts"] >= 10
RULES["cluster_ucb_le_2alpha_hosts_ge_20"] = lambda r: (
    r["cluster_ucb"] <= 2 * ALPHA and r["hosts"] >= 20
)
RULES["loho_ucb_le_2alpha_hosts_ge_20"] = lambda r: r["loho_ucb"] <= 2 * ALPHA and r["hosts"] >= 20


def simulate(reps: int) -> list[dict]:
    out = []
    grid = itertools.product(HOSTS, NS, RHOS, SKEWS, PHIS)
    for i, (h, n, rho, skew, phi) in enumerate(grid):
        rng = np.random.default_rng(i)
        rs = [replicate(rng, h, n, rho, skew, phi) for _ in range(reps)]
        bad = np.array([r["fpr"] > 2 * ALPHA for r in rs])
        row = {"hosts": h, "n": n, "rho": rho, "skew": skew, "phi": phi, "reps": reps,
               "fpr_median": float(np.median([r["fpr"] for r in rs])),
               "fpr_q90": float(np.quantile([r["fpr"] for r in rs], 0.9)),
               "p_fpr_above_2alpha": float(bad.mean()), "rules": {}}  # fmt: skip
        for name, f in RULES.items():
            ok = np.array([f(r) for r in rs])
            row["rules"][name] = {"pass_rate": float(ok.mean()), "passes": int(ok.sum()),
                                  "bad_passes": int(bad[ok].sum()),
                                  "p_bad_given_pass": float(bad[ok].mean()) if ok.any() else None}  # fmt: skip
        # the PAC threshold is a different threshold, so "bad" is judged on its own FPR
        pf = np.array([r["pac_fpr"] for r in rs if r["pac_fpr"] is not None])
        row["rules"]["pac_threshold_neff_hosts_ge_10"] = {
            "pass_rate": len(pf) / reps, "passes": len(pf), "bad_passes": int((pf > 2 * ALPHA).sum()),
            "p_bad_given_pass": float((pf > 2 * ALPHA).mean()) if len(pf) else None,
            "fpr_median_given_pass": float(np.median(pf)) if len(pf) else None}  # fmt: skip
        out.append(row)
    return out


def summarize(rows: list[dict]) -> dict:
    """Per rule, over the grid. SAFETY: pooled bad passes / passes with a Clopper-Pearson 95%
    upper bound, and the worst configuration (any pass count; with its counts, since a few
    passes give a noisy rate). UTILITY: the mean pass rate over the configurations that are
    actually safe (P(FPR > 2 alpha) <= 5%). Every summary depends on the grid: it weights
    configurations equally, and the safe configurations are mostly rho = 0."""
    from scipy.stats import beta

    safe = [r for r in rows if r["p_fpr_above_2alpha"] <= 0.05]
    out = {"safe_configurations": len(safe), "configurations": len(rows),
           "p_bad_mean_over_grid": float(np.mean([r["p_fpr_above_2alpha"] for r in rows]))}  # fmt: skip
    keys = ("hosts", "n", "rho", "skew", "phi")
    for name in rows[0]["rules"]:
        live = [r for r in rows if r["rules"][name]["passes"] > 0]
        worst = max(live, key=lambda r: r["rules"][name]["p_bad_given_pass"], default=None)
        n_pass = sum(r["rules"][name]["passes"] for r in rows)
        n_bad = sum(r["rules"][name]["bad_passes"] for r in rows)
        w = worst["rules"][name] if worst else None
        out[name] = {
            "passes": n_pass, "bad_passes": n_bad,
            "pooled_p_bad_given_pass": n_bad / n_pass if n_pass else None,
            "pooled_upper95": float(beta.ppf(0.95, n_bad + 1, n_pass - n_bad)) if n_pass else None,
            "worst_p_bad_given_pass": w["p_bad_given_pass"] if w else None,
            "worst_counts": f"{w['bad_passes']} of {w['passes']}" if w else None,
            "worst_at": {k: worst[k] for k in keys} if worst else None,
            "pass_rate_in_safe_configurations": float(np.mean(
                [r["rules"][name]["pass_rate"] for r in safe])) if safe else None,
            "pass_rate_overall": float(np.mean([r["rules"][name]["pass_rate"] for r in rows]))}  # fmt: skip
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=200)
    a = ap.parse_args()
    t0 = time.perf_counter()
    sim = simulate(a.reps)
    res = {"alpha": ALPHA, "iid": iid_table(), "claim": claim_table(),
           "simulation": {"model": "z = u_h + sqrt(1-rho) AR1(phi); population FPR = 1 - Phi(T0)",
                          "reps": a.reps, "phis": PHIS, "grid": sim, "pooled": summarize(sim)},
           "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print(json.dumps({"iid": res["iid"], "claim": res["claim"],
                      "pooled": res["simulation"]["pooled"], "seconds": res["seconds"]}, indent=1))  # fmt: skip


if __name__ == "__main__":
    main()
