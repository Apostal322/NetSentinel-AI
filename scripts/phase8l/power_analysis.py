"""Phase 8l statistical power of a network-level calibration-reliability confirmation (no data).

Model of one confirmatory study with N network units:
  - each unit is truly adequate with probability `prev` (true FPR ~ U(0.5%, 1.8%)), else unsafe
    (true FPR ~ U(2.5%, 15%), the development range);
  - the rule accepts an adequate unit with probability `sens` and an unsafe one with `far`;
    with family dependence, units come in families of `fam_size` and each family shifts both
    probabilities on the logit scale by N(0, sigma^2);
  - the unit's ADEQUACY LABEL is observed with noise: realised FPR = Binomial(n_eff, true FPR) /
    n_eff over its verified-benign evidence (n_eff effective independent windows), labelled
    adequate if <= 2%. Small networks therefore give noisy labels.
Registered Phase 8k K1 discrimination criteria are applied to the OBSERVED labels: gates E2
(>= 2 adequate and >= 2 unsafe) and E3 (1/C(N, K) <= 0.05); (a) FAR <= 0.25; (b) FRR <= 0.5 with
>= 2 accepted; (d) exact hypergeometric (one-sided Fisher) p <= 0.05.
Power = P(all hold). Also reported: P(evaluable) and the label-noise rates.

Output: reports/phase8l/power_analysis.json
Usage: uv run python scripts/phase8l/power_analysis.py
"""

from __future__ import annotations

import itertools
import json
import time
from pathlib import Path

import numpy as np
from scipy.special import expit, logit
from scipy.stats import beta, hypergeom

OUT = Path("reports/phase8l/power_analysis.json")
REPS = 2000
NS = (4, 7, 10, 13, 16, 20, 25, 30, 40, 50, 60, 80, 100)
PREVS = (0.25, 0.5, 0.75)
RULES = {"good": (0.9, 0.1), "moderate": (0.8, 0.2), "weak": (0.7, 0.3)}
NEFFS = (50, 200, 1000, 5000)
LABEL_MODES = ("point", "three_state")
DEPENDENCE = {"independent": (1, 0.0), "families_of_4_sigma1": (4, 1.0)}


def label_noise(n_eff: int, rng: np.random.Generator, reps: int = 20000) -> dict:
    """P(observed label wrong) for a truly adequate and a truly unsafe unit at this n_eff."""
    p_ok = rng.uniform(0.005, 0.018, reps)
    p_bad = rng.uniform(0.025, 0.15, reps)
    return {"adequate_labelled_unsafe": float((rng.binomial(n_eff, p_ok) / n_eff > 0.02).mean()),
            "unsafe_labelled_adequate": float((rng.binomial(n_eff, p_bad) / n_eff <= 0.02).mean())}  # fmt: skip


def one_config(n: int, prev: float, sens: float, far: float, n_eff: int, fam_size: int,
               sigma: float, rng: np.random.Generator, mode: str = "point") -> dict:  # fmt: skip
    ok_true = rng.random((REPS, n)) < prev
    p_true = np.where(
        ok_true, rng.uniform(0.005, 0.018, (REPS, n)), rng.uniform(0.025, 0.15, (REPS, n))
    )
    x = rng.binomial(n_eff, p_true)
    if mode == "point":  # Phase 8k: observed FPR <= 2% (>= 200 windows); every unit determinable
        ok_obs, det = x / n_eff <= 0.02, np.ones_like(ok_true)
    else:  # three-state: decided only when the exact 95% interval excludes 2%
        up = np.where(x < n_eff, beta.ppf(0.975, x + 1, n_eff - x), 1.0)
        lo = np.where(x > 0, beta.ppf(0.025, np.maximum(x, 1), n_eff - x + 1), 0.0)
        ok_obs, det = up <= 0.02, (up <= 0.02) | (lo > 0.02)
    shift = (
        np.repeat(rng.normal(0, sigma, (REPS, -(-n // fam_size))), fam_size, axis=1)[:, :n]
        if sigma
        else 0.0
    )
    p_acc = np.where(ok_true, expit(logit(sens) + shift), expit(logit(far) + shift))
    acc = rng.random((REPS, n)) < p_acc
    ok, bad = det & ok_obs, det & ~ok_obs
    n_det, k_ok, k_bad = det.sum(1), ok.sum(1), bad.sum(1)
    fa = (acc & bad).sum(1)
    fr = (~acc & ok).sum(1)
    n_acc = (acc & det).sum(1)
    e2 = (k_ok >= 2) & (k_bad >= 2)
    e3 = np.array(
        [
            0 < k < m and 1.0 / _comb(int(m), int(k)) <= 0.05
            for k, m in zip(k_bad, n_det, strict=True)
        ]
    )
    a = np.where(k_bad > 0, fa / np.maximum(k_bad, 1) <= 0.25, False)
    b = np.where(k_ok > 0, (fr / np.maximum(k_ok, 1) <= 0.5) & (n_acc >= 2), False)
    d = hypergeom.cdf(fa, np.maximum(n_det, 1), k_bad, n_acc) <= 0.05
    ev = e2 & e3
    return {"evaluable": float(ev.mean()), "power": float((ev & a & b & d).mean()),
            "power_given_evaluable": float((ev & a & b & d).sum() / max(ev.sum(), 1)),
            "mean_determinable_units": float(n_det.mean())}  # fmt: skip


_C: dict = {}


def _comb(n: int, k: int) -> int:
    from math import comb

    if (n, k) not in _C:
        _C[(n, k)] = comb(n, k)
    return _C[(n, k)]


def main() -> None:
    t0 = time.perf_counter()
    rng = np.random.default_rng(81)
    res = {"model": __doc__.split("Output:")[0].strip(), "reps": REPS,
           "label_noise": {n: label_noise(n, rng) for n in NEFFS}, "grid": [], "minimum_n_for_80pct_power": {}}  # fmt: skip
    for mode, (dep, (fs, sg)), prev, (rname, (sens, far)), n_eff in itertools.product(
            LABEL_MODES, DEPENDENCE.items(), PREVS, RULES.items(), NEFFS):  # fmt: skip
        best = None
        for n in NS:
            r = one_config(n, prev, sens, far, n_eff, fs, sg, rng, mode)
            res["grid"].append({"labels": mode, "dependence": dep, "prev_adequate": prev, "rule": rname,
                                "n_eff": n_eff, "n_units": n, **r})  # fmt: skip
            if best is None and r["power"] >= 0.8:
                best = n
        res["minimum_n_for_80pct_power"][f"{mode}|{dep}|prev={prev}|{rname}|n_eff={n_eff}"] = best
    # the actual Phase 8k situation: 7 F1 networks, ~7 effective hosts -> small n_eff
    res["phase8k_f1_like"] = {f"prev={p}|{r}": one_config(7, p, s, f, 200, 7, 1.0, rng)
                              for p in PREVS for r, (s, f) in RULES.items()}  # fmt: skip
    res["seconds"] = round(time.perf_counter() - t0, 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print(json.dumps({"label_noise": res["label_noise"], "minimum_n": res["minimum_n_for_80pct_power"],
                      "f1_like": res["phase8k_f1_like"], "seconds": res["seconds"]}, indent=1))  # fmt: skip


if __name__ == "__main__":
    main()
