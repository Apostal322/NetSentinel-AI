"""Phase 8r Stage 1: calibration identifiability audit. Saved scores only (Phase 8o F0, 6 fits,
K = 5); no model fitted. docs/phase8r/CALIBRATION_IDENTIFIABILITY.md.

**Target.** The benign (1 − α) score quantile q_b of the deployment hold-out (α = 1 %): the
threshold at which benign windows alert at rate α.

**Observable without labels:** the mixture F = (1 − ε) F_b + ε G of benign windows (F_b) and
calibration-attacker windows (G, arbitrary), with ε unknown.

**Partial identification (Horowitz–Manski bound).** If ε ≤ ε̄ and G is unrestricted,
q_b ∈ [Q_F((1 − α)(1 − ε̄)), Q_F(1 − α(1 − ε̄))]. With ε unbounded, the identified set is the
whole score range: q_b is NOT IDENTIFIABLE.

For each domain this script reports:
1. **Hold-out composition** (oracle labels used only to describe):
   - windows, hosts, host-hour blocks;
   - calibration-attacker hosts and window share ε;
   - benign hosts, effective benign hosts (1 / Σ share²), largest benign-host share.
2. **The identified threshold interval** at ε̄ ∈ {ε_true, 1 %, 5 %, 10 %, 30 %}, and its
   consequence on the unlabelled-memory evaluation scores: the range of FPR (historical benign)
   and documented-attacker recall (V2) over the interval's end points. Quantiles use the
   empirical (inverted-CDF) definition, for which the bound holds exactly at ε̄ = ε_true.
3. **Distribution-free feasibility:**
   - a host-exchangeable conformal guarantee at α needs ≥ ⌈1/α⌉ − 1 = 99 exchangeable benign
     hosts;
   - a window-exchangeable guarantee ignores within-host dependence.

Output: reports/phase8r/identifiability.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8r/identifiability.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


FG = _load("phase8q_fg", "scripts/phase8q/experiment_fg.py")
CM, BM = FG.CM, FG.BM
OUT = ROOT / "reports" / "phase8r" / "identifiability.json"
ALPHA = 0.01
EPS_BARS = (0.01, 0.05, 0.10, 0.30)
HOUR_MS = 3_600_000


def manski_interval(s_mix: np.ndarray, eps_bar: float, alpha: float = ALPHA) -> tuple[float, float]:
    """Identified set of the benign (1 − α) quantile when at most a share eps_bar is arbitrary."""
    lo = float(np.quantile(s_mix, (1 - alpha) * (1 - eps_bar), method="inverted_cdf"))
    hi = float(np.quantile(s_mix, 1 - alpha * (1 - eps_bar), method="inverted_cdf"))
    return lo, hi


def composition(d: dict) -> dict:
    key, end, att = d["hu_key"], d["hu_end"], d["is_att"]
    blocks = np.char.add(key.astype(str), "|" + (end // HOUR_MS).astype(str))
    bk, bc = np.unique(key[~att], return_counts=True)
    p = bc / bc.sum() if bc.size else np.array([1.0])
    return {"windows": int(key.size), "hosts": int(np.unique(key).size),
            "host_hour_blocks": int(np.unique(blocks).size),
            "attacker_hosts": int(np.unique(key[att]).size), "attacker_window_share": round(float(att.mean()), 4),
            "benign_hosts": int(bk.size), "benign_windows": int((~att).sum()),
            "benign_host_hour_blocks": int(np.unique(blocks[~att]).size),
            "effective_benign_hosts": round(float(1 / (p**2).sum()), 2) if bc.size else 0.0,
            "largest_benign_host_share": round(float(p.max()), 4) if bc.size else None,
            "host_conformal_feasible": bool(bk.size >= math.ceil(1 / ALPHA) - 1)}  # fmt: skip


def main() -> None:
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    res: dict = {"status": "Stage 1 identifiability audit (saved scores; oracle labels describe only)",
                 "alpha": ALPHA, "domains": {}}  # fmt: skip
    for name in names:
        d = FG.domain_data(name)
        comp = composition(d)
        eps_true = float(d["is_att"].mean())  # unrounded
        bars = {"true": eps_true, **{f"{e:.2f}": e for e in EPS_BARS}}
        per_bar: dict = {b: {"t_lo": [], "t_hi": [], "fpr": [], "recall": [], "contains_benign_q": []}
                         for b in bars}  # fmt: skip
        ref = {"U": [], "T_benign_q": [], "P": []}
        for regime, r in FG.FITS:
            z = FG.scores(name, regime, r)
            s_mix, s_ev = z["s_hold_u"], z["s_ev_u"]
            ben = s_mix[~d["is_att"]]
            qb = CM.t0(ben) if ben.size else math.inf
            # population benign quantile (same empirical definition as the bound) for containment
            qb_pop = (
                float(np.quantile(ben, 1 - ALPHA, method="inverted_cdf")) if ben.size else math.inf
            )
            ref["U"].append(CM.t0(s_mix))
            ref["T_benign_q"].append(qb)
            ref["P"].append(CM.t0(z["s_hold"]))
            for b, e in bars.items():
                lo, hi = manski_interval(s_mix, min(e, 0.999))
                fpr = [float((s_ev[d["neg"]] > t).mean()) for t in (hi, lo)]
                rec = [
                    float((s_ev[d["pos"]] > t).mean()) if d["pos"].any() else None for t in (hi, lo)
                ]
                q = per_bar[b]
                q["t_lo"].append(lo)
                q["t_hi"].append(hi)
                q["fpr"].append(fpr)
                q["recall"].append(rec)
                q["contains_benign_q"].append(bool(lo <= qb_pop <= hi))
        out = {}
        for b, q in per_bar.items():
            rec = np.array([x for x in q["recall"] if x[0] is not None], dtype=float)
            fpr = np.array(q["fpr"])
            out[b] = {"eps_bar": bars[b], "threshold_interval": [float(np.mean(q["t_lo"])), float(np.mean(q["t_hi"]))],
                      "fpr_range": [round(float(fpr[:, 0].mean()), 4), round(float(fpr[:, 1].mean()), 4)],
                      "recall_range": ([round(float(rec[:, 0].mean()), 4), round(float(rec[:, 1].mean()), 4)]
                                       if rec.size else None),
                      "contains_benign_quantile_all_fits": all(q["contains_benign_q"])}  # fmt: skip
        res["domains"][name] = {"composition": comp,
                                "reference_thresholds": {k: float(np.mean(v)) for k, v in ref.items()},
                                "identified_sets": out}  # fmt: skip
        print(name, comp["attacker_window_share"], comp["benign_hosts"], comp["effective_benign_hosts"],
              {b: (v["fpr_range"], v["recall_range"]) for b, v in out.items()}, flush=True)  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    main()
