"""Phase 8v EXPLORATORY check prompted by the independent review: how concentrated is the NF-ToN
effect, and is it specific to the added columns? Saved scores and features only; no model fitted.

- true positives at the retrospective 1 % FPR threshold, by attacker host;
- as-calibrated (CAL_T) false alerts: host concentration and overlap between candidates;
- exact partial AUC of two single raw features on NF-ToN, against the `TIME` model's.

Output: reports/phase8v/ton_concentration.json
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = str(Path(__file__).resolve().parents[2]).replace("\\", "/")


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT + "/" + rel)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


OF = load("of", "scripts/phase8t/oracle_feasibility.py")
LF = load("lf", "scripts/phase8u/lowfpr.py")
name = "nfton/all"
d = OF.load(name)
is_att = OF.FG.domain_data(name)["is_att"]


def sc(v):
    if v == "M2member":
        z = np.load(ROOT + "/data/derived/phase8o/experiment_d/F0/base/nfton__all__r6.npz")
        return z["s_hold_u"][0], z["s_ev_u"][0]
    z = np.load(ROOT + f"/data/derived/phase8v/scores/{v}/nfton__all__s1060.npz")
    return z["s_hold_u"], z["s_ev_u"]


budget = int(math.floor(0.01 * d["neg"].sum()))
out = {}
fa = {}
for v in ("M2member", "FLOW", "TIME", "BIDIR", "INV"):
    sh, se = sc(v)
    t_or = OF.TO.global_threshold(se[d["neg"]], budget)
    tp = (se > t_or) & d["pos"]
    k, c = np.unique(d["key"][tp], return_counts=True)
    c = np.sort(c)[::-1]
    ben = ~is_att
    t_cal = float(np.sort(sh[ben])[min(ben.sum(), math.ceil((ben.sum() + 1) * 0.99)) - 1])
    f = (se > t_cal) & d["neg"]
    fa[v] = f
    hk, hc = np.unique(d["key"][f], return_counts=True)
    hc = np.sort(hc)[::-1]
    out[v] = {
        "oracle_tp": int(tp.sum()),
        "tp_top1_share": float(c[0] / c.sum()) if c.size else None,
        "tp_top3_share": float(c[:3].sum() / c.sum()) if c.size else None,
        "calT_false_alerts": int(f.sum()),
        "fa_top3_host_share": float(hc[:3].sum() / hc.sum()),
    }
for v in ("FLOW", "BIDIR", "INV"):
    out[v]["fa_shared_with_TIME"] = int((fa[v] & fa["TIME"]).sum())
out["TIME"]["fa_also_in_baseline"] = int((fa["TIME"] & fa["M2member"]).sum())
new = fa["TIME"] & ~fa["M2member"]
shared_all = new & fa["FLOW"] & fa["BIDIR"] & fa["INV"]
out["new_fa_TIME_vs_baseline"] = int(new.sum())
out["new_fa_shared_by_all_four"] = int(shared_all.sum())
a = pl.read_parquet(
    ROOT + "/data/derived/phase8q/label_audit/nfton__all.parquet", columns=["key", "win"]
)
ev = pl.read_parquet(
    ROOT + "/data/derived/phase8i/nfton/all/eval_unlabelled.parquet",
    columns=["key", "win", "log_flows"],
)
en = pl.read_parquet(
    ROOT + "/data/derived/phase8v/enriched/nfton/all.parquet",
    columns=["key", "win", "prev4_mean_log_flows"],
)
j = a.join(ev, on=["key", "win"], how="left", maintain_order="left").join(
    en, on=["key", "win"], how="left", maintain_order="left"
)
for f in ("log_flows", "prev4_mean_log_flows"):
    x = j[f].to_numpy().astype(float)
    out["univariate_pauc_" + f] = LF.partial_auc_exact(x[d["pos"]], x[d["neg"]])
_, se = sc("TIME")
out["TIME_pauc"] = LF.partial_auc_exact(se[d["pos"]], se[d["neg"]])
Path(ROOT, "reports/phase8v/ton_concentration.json").write_bytes(json.dumps(out, indent=1).encode())
print(json.dumps(out, indent=1))
