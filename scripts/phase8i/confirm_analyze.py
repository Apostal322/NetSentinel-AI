"""Phase 8i confirmatory verdicts on NF-BoT-IoT-v3 (docs/phase8i/PREREGISTRATION.md sections
4-6). Written before N4 was opened; reads the frozen choices from reports/phase8i/freeze.json.

I1 (selected method M, budget Ka = 25 / 100):
  not evaluable  pool < 25 labelled attack windows, or A1 recall >= 0.95 at FPR <= 2% (A4)
  success        median recall(Ka25) >= 0.5 and p2.5 recall(Ka25) > A1 recall and median FPR <= 2%
  failure        median recall(Ka100) < 0.3, or p2.5 recall(Ka25) <= A1 recall
  inconclusive   otherwise
I2 (B-rz, tau fixed on development):
  not evaluable  < 5 eligible blocks, or no block overruns (amendment A4)
  success        coverage >= 60% and exceedance(covered) <= 10% and < exceedance(all)
  failure        exceedance(covered) >= exceedance(all)
  inconclusive   otherwise
I3 (selected variant V vs raw, mean over seeds; not evaluable if raw recall > 0.90 at
FPR <= 2%, amendment A4):
  success        recall(V) >= recall(raw) + 0.10 and FPR(V) <= 2%
  failure        otherwise
Output: reports/phase8i/confirm/verdicts.json
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

ROOT = Path("reports/phase8i/confirm")


def i1(freeze: dict) -> dict:
    p = next(iter(sorted((ROOT / "exp_a").glob("*.json"))), None)
    if p is None:
        return {"verdict": "not run"}
    r = json.loads(p.read_text("utf-8"))
    m = freeze["A_method"]
    seeds = list(r["seeds"].values())
    a1 = float(np.mean([s["A1"]["window_recall"] for s in seeds]))
    corr = [s for s in seeds if s["budgets"]]
    out = {"method": m, "A1_recall": a1, "pool_windows": r["pool_windows"],
           "pool_entities": r["pool_entities"], "n_hold": r["n_hold"]}  # fmt: skip
    if r["pool_windows"] < 25 or not corr:
        return {**out, "verdict": "not evaluable"}

    def stats(b):
        per = [p for s in corr for p in s["budgets"][b][m]["per_draw"]]
        rec = np.array([p["window_recall"] for p in per], dtype=float)
        fpr = np.array([p["fpr"] for p in per], dtype=float)
        return {"median_recall": float(np.median(rec)), "p025_recall": float(np.quantile(rec, 0.025)),
                "median_fpr": float(np.median(fpr)), "n": len(per)}  # fmt: skip

    k25, k100 = stats("Ka25"), stats("Ka100")
    out.update(Ka25=k25, Ka100=k100)
    a1_fpr = float(np.mean([s["A1"]["fpr"] for s in seeds]))
    if a1 >= 0.95 and a1_fpr <= 0.02:  # amendment A4: no room for labels to help
        return {**out, "A1_fpr": a1_fpr, "verdict": "not evaluable (zero-label ceiling)"}
    if k25["median_recall"] >= 0.5 and k25["p025_recall"] > a1 and k25["median_fpr"] <= 0.02:
        v = "success"
    elif k100["median_recall"] < 0.3 or k25["p025_recall"] <= a1:
        v = "failure"
    else:
        v = "inconclusive"
    return {**out, "verdict": v}


def i2() -> dict:
    p = ROOT / "exp_b" / "summary.json"
    if not p.exists():
        return {"verdict": "not run"}
    s = json.loads(p.read_text("utf-8"))
    blocks = s.get("B-rz", {}).get("blocks", 0)
    c = s.get("confirm")
    if blocks < 5 or not c:
        return {"blocks": blocks, "verdict": "not evaluable", **(c or {})}
    cov, ec, ea = c["coverage"], c["exceedance_covered"], c["exceedance_all"]
    if ea == 0:  # amendment A4: nothing overran, so there is nothing for a shift score to flag
        return {"blocks": blocks, **c, "verdict": "not evaluable (no overrunning blocks)"}
    if cov >= 0.6 and ec is not None and ec <= 0.10 and ec < ea:
        v = "success"
    elif ec is None or ec >= ea:
        v = "failure"
    else:
        v = "inconclusive"
    return {"blocks": blocks, **c, "verdict": v}


def i3(freeze: dict) -> dict:
    p = ROOT / "exp_c" / "cross.json"
    if not p.exists():
        return {"verdict": "not run"}
    r = next(iter(json.loads(p.read_text("utf-8"))["result"].values()))
    v = freeze["C_variant"]

    def mean(var, k):
        vals = [s[var][k] for s in r["seeds"].values() if s.get(var, {}).get(k) is not None]
        return float(np.mean(vals)) if vals else None

    rv, rr, fv = mean(v, "window_recall"), mean("raw", "window_recall"), mean(v, "fpr")
    fr = mean("raw", "fpr")
    if rr is not None and fr is not None and rr > 0.90 and fr <= 0.02:  # amendment A4
        return {"variant": v, "recall_raw": rr, "fpr_raw": fr, "recall_variant": rv,
                "fpr_variant": fv, "verdict": "not evaluable (raw-model ceiling)"}  # fmt: skip
    ok = rv is not None and rr is not None and fv is not None and rv >= rr + 0.10 and fv <= 0.02
    return {"variant": v, "recall_variant": rv, "recall_raw": rr, "fpr_variant": fv,
            "fpr_raw": mean("raw", "fpr"), "verdict": "success" if ok else "failure"}  # fmt: skip


def main() -> None:
    import argparse

    global ROOT
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--freeze", default="reports/phase8i/freeze.json")
    a = ap.parse_args()
    ROOT = Path(a.root)
    freeze = json.loads(Path(a.freeze).read_text("utf-8"))
    out = {"label": "[C] NF-BoT-IoT-v3, single confirmatory evaluation",
           "I1": i1(freeze), "I2": i2(), "I3": i3(freeze)}  # fmt: skip
    (ROOT / "verdicts.json").write_text(json.dumps(out, indent=1), "utf-8")
    print(json.dumps({k: out[k].get("verdict") for k in ("I1", "I2", "I3")}))


if __name__ == "__main__":
    main()
