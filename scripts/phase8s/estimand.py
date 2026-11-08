"""Phase 8s Stage 3: the calibration estimand and how much independent evidence its 1 % tail
needs (docs/phase8s/SAMPLING_ESTIMAND.md). Saved scores only; oracle labels describe the
population, they never select anything. Mean over the 6 Phase 8o F0 fits.

Per domain, on the benign hold-out windows (the population a trusted sample should represent):
- host activity: benign hosts, windows, share of single-window hosts, the share of benign windows
  held by the top 1 % / 10 % of hosts;
- where the tail lives: the hosts holding the benign windows above q_b (the benign (1 − α)
  quantile) and the Kish count of those hosts;
- the design effect of the exceedance indicator 1{s > q_b} under host clustering, and the
  effective sample size of a full census of the benign hold-out;
- the i.i.d. sample sizes a 1 % threshold needs: 99 (marginal conformal, expected FPR ≤ α) and
  299 (the sample maximum exceeds q_b with probability 0.95).

Output: reports/phase8s/estimand.json
"""

from __future__ import annotations

import importlib.util
import json
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


AB = _load("phase8r_ab", "scripts/phase8r/experiment_ab.py")
AC = _load("phase8s_ac", "scripts/phase8s/active_calibration.py")
OUT = ROOT / "reports" / "phase8s" / "estimand.json"


def top_share(sorted_desc: np.ndarray, f: float) -> float:
    return float(
        sorted_desc[: max(1, int(np.ceil(f * sorted_desc.size)))].sum() / sorted_desc.sum()
    )


def main() -> None:
    names = sorted(p.stem.replace("__", "/") for p in AB.BM.AUDIT.glob("*.parquet"))
    res: dict = {"status": "Stage 3 estimand analysis (saved scores; labels describe only)",
                 "n_marginal_conformal": 99, "n_max_95": AC.n_for_max_guarantee(0.01, 0.05), "domains": {}}  # fmt: skip
    for name in names:
        d = AB.load(name)
        ben = ~d["is_att"]
        inv = d["meta"]["inv"][ben]
        _, g, n = np.unique(inv, return_inverse=True, return_counts=True)
        o = np.sort(n)[::-1]
        per_fit = []
        for regime, r in AB.FITS:
            s = AB.FG.scores(name, regime, r)["s_hold_u"][ben]
            q = AC.conformal_t0(s)
            ex = s > q
            tail_hosts = np.unique(g[ex])
            tail_w = np.bincount(g[ex], minlength=n.size)[tail_hosts]
            dd = AC.exceedance_deff(ex, g)
            per_fit.append({"q_b": q, "exceed_windows": int(ex.sum()), "tail_hosts": int(tail_hosts.size),
                            "tail_host_kish": AC.kish_neff(tail_w.astype(float)), **dd})  # fmt: skip
        agg = {k: float(np.mean([p[k] for p in per_fit])) for k in per_fit[0]}
        res["domains"][name] = {"benign_hosts": int(n.size), "benign_windows": int(ben.sum()),
                                "single_window_host_share": float((n == 1).mean()),
                                "window_share_top1pct_hosts": top_share(o, 0.01), "window_share_top10pct_hosts": top_share(o, 0.10),
                                **agg}  # fmt: skip
        x = res["domains"][name]
        print(name, x["benign_hosts"], x["benign_windows"], round(x["single_window_host_share"], 2),
              round(x["window_share_top1pct_hosts"], 2), "tail hosts", round(x["tail_hosts"], 1),
              "kish", round(x["tail_host_kish"], 1), "deff", round(x["deff"], 1), "n_eff", round(x["n_eff"]), flush=True)  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    main()
