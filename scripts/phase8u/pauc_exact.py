"""Phase 8u amendment U-1: recompute the registered gates with the exact partial AUC
(`lowfpr.partial_auc_exact`) from the saved scores. No model is fitted. The registered evaluation
file is kept; this writes reports/phase8u/evaluation_pauc_exact.json."""

from __future__ import annotations

import copy
import hashlib
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


X = _load("phase8u_x", "scripts/phase8u/experiment.py")
OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")


def main() -> None:
    R = json.loads((ROOT / "reports/phase8u/evaluation_final.json").read_text("utf-8"))  # noqa: N806
    per = copy.deepcopy(R["per_domain"])
    for name in sorted(next(iter(per.values()))):
        d = OF.load(name)
        for run in per:
            v, s = run.split("|")
            s = int(s)
            if v == "M2member" or (v == "A0" and name.startswith("nfbot")):
                z = np.load(
                    ROOT
                    / "data/derived/phase8o/experiment_d/F0/base"
                    / f"{name.replace('/', '__')}__r6.npz"
                )
                se = z["s_ev_u"][s - X.SEED0]
            else:
                se = np.load(X.DER / "scores" / v / f"{name.replace('/', '__')}__s{s}.npz")[
                    "s_ev_u"
                ]
            per[run][name]["pauc_1pct_registered"] = per[run][name]["pauc_1pct"]
            per[run][name]["pauc_1pct"] = X.LF.partial_auc_exact(se[d["pos"]], se[d["neg"]])
        print(name, flush=True)
    summary = {k: X.aggregate(v) for k, v in per.items()}
    res = {"status": "Amendment U-1: exact partial AUC; all other metrics as registered", "summary": summary,
           "decisions": X.decide(summary), "per_domain": per}  # fmt: skip
    body = json.dumps(res, indent=1, default=float).encode()
    p = ROOT / "reports/phase8u/evaluation_pauc_exact.json"
    if p.exists():
        raise FileExistsError(p)
    p.write_bytes(body)
    (ROOT / "reports/phase8u/evaluation_pauc_exact.sha256").write_text(
        hashlib.sha256(body).hexdigest()
    )
    for k in ("A1|1060", "A2|1060", "B|1060", "C1|1060"):
        print(
            k,
            {
                kk: (round(vv, 4) if isinstance(vv, float) else vv)
                for kk, vv in res["decisions"]["screening"][k.split("|")[0]].items()
                if kk != "guardrails"
            },
        )
    print(json.dumps(res["decisions"]["replication"], indent=0))
    for k in ("M2member|1060", "B|1060", "M2member|1061", "B|1061", "M2member|1062", "B|1062"):
        print(
            k,
            round(summary[k]["macro_pauc_1pct"], 4),
            {n: round(v["pauc_1pct"], 4) for n, v in summary[k]["networks"].items()},
        )


if __name__ == "__main__":
    main()
