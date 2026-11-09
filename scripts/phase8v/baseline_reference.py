"""Phase 8v Stage 2: frozen-baseline reference with the exact partial AUC (saved scores only).

- Frozen M2 ensemble: mean of the 5 saved Phase 8o F0 members, 6 fits (base and stress, r6-8).
- Matched single members: base r6 members 0-2 (seeds 1060-1062), the Phase 8u/8v baselines.
Deployable memory (`s_ev_u`); V2 documented attackers vs historical benign.

Output: reports/phase8v/baseline_reference.json
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


OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")
LF = _load("phase8u_lf", "scripts/phase8u/lowfpr.py")
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
F0 = ROOT / "data/derived/phase8o/experiment_d/F0"


def point(d: dict, s: np.ndarray) -> dict:
    pos, neg = d["pos"], d["neg"]
    t = OF.TO.global_threshold(s[neg], int(math.floor(0.01 * neg.sum())))
    return {
        "pauc": LF.partial_auc_exact(s[pos], s[neg]),
        "recall_1pct": float((s[pos] > t).mean()) if pos.any() else float("nan"),
    }


def net_mean(per: dict, field: str) -> dict:
    return {
        n: float(np.nanmean([v[field] for k, v in per.items() if k.startswith(n + "/")]))
        for n in NETS
    }


def main() -> None:
    names = sorted(p.stem.replace("__", "/") for p in OF.BM.AUDIT.glob("*.parquet"))
    ens: dict = {}
    mem: dict = {m: {} for m in range(3)}
    for name in names:
        d = OF.load(name)
        f = name.replace("/", "__")
        fits = []
        for regime in ("base", "stress"):
            for r in (6, 7, 8):
                z = np.load(F0 / regime / f"{f}__r{r}.npz")["s_ev_u"]
                fits.append(point(d, z.mean(0)))
                if regime == "base" and r == 6:
                    for m in range(3):
                        mem[m][name] = point(d, z[m])
        ens[name] = {k: float(np.mean([x[k] for x in fits])) for k in ("pauc", "recall_1pct")}
        print(name, flush=True)
    res = {"status": "frozen references, exact partial AUC (FPR <= 1 %), saved scores only",
           "frozen_M2_ensemble_6fits": {"pauc": net_mean(ens, "pauc"), "recall_1pct": net_mean(ens, "recall_1pct")},
           "single_members_base_r6": {str(1060 + m): {"pauc": net_mean(mem[m], "pauc"), "recall_1pct": net_mean(mem[m], "recall_1pct")}
                                      for m in range(3)}}  # fmt: skip
    for blk in (res["frozen_M2_ensemble_6fits"], *res["single_members_base_r6"].values()):
        blk["macro_pauc"] = float(np.mean(list(blk["pauc"].values())))
        blk["macro_recall_1pct"] = float(np.mean(list(blk["recall_1pct"].values())))
    (ROOT / "reports/phase8v/baseline_reference.json").write_bytes(
        json.dumps(res, indent=1).encode()
    )
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
