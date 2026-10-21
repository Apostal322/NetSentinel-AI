"""Phase 8b development comparison (EXPLORATORY: every capture here was already inspected).

Leave-one-capture-out over the development captures: IoT-23 x9 (inspected), NF-UNSW-v3
development part, CTU-Normal x12 (benign only). For each target capture and calibration
variant (clean / unlabelled), every scorer of scripts/phase8b/scorers.py is computed on the
same device windows; LightGBM is trained on all OTHER development captures.
Writes reports/phase8b/dev_compare.json.

Usage: uv run --extra torch python scripts/phase8b/dev_compare.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scorers as S  # noqa: E402, N812
from harness import domain_shift, operational, windows, with_truth  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("reports/phase8b")


def dev_captures() -> dict[str, object]:
    caps: dict[str, object] = {}
    for f in sorted(Path("data/raw/iot23").glob("*/conn.log.labeled")):
        caps[f.parent.name] = f
    caps["NF-UNSW-NB15-v3-dev"] = "nf_unsw"
    for f in sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log")):
        caps[f.parent.name] = f
    p = Path("data/raw/ctu_normal_26/bro/conn.log")
    if p.exists():
        caps["CTU-Normal-26"] = p
    return caps


def evaluate_target(name: str, d: dict, others: list[dict], variant: str) -> dict:
    cal, ev, tr = d[f"cal_{variant}"], d[f"eval_{variant}"], d["truth"]
    hours, fa = d["meta"]["eval_hours"], d["meta"]["first_attack_ms"]
    res: dict = {"cal_windows": cal.height, "eval_windows": ev.height}
    if cal.height < 60 or ev.height == 0:
        res["status"] = "too few windows"
        return res
    for k, (s, thr) in S.unsupervised(cal, ev, tr, hours).items():
        res[k] = operational(ev, tr, s, thr, hours, fa)
    s, thr = S.product(cal, ev)
    res["robust_z_product"] = operational(ev, tr, s, thr, hours, fa)
    for local in (False, True):
        key = "lgbm_local" if local else "lgbm_raw"
        t0 = time.perf_counter()
        model, src_thr = S.lgbm_fit(others, local)
        s, loc_thr = S.lgbm_score(model, cal, ev, local)
        res[f"{key}@source"] = operational(ev, tr, s, src_thr, hours, fa)
        res[f"{key}@local"] = operational(ev, tr, s, loc_thr, hours, fa)
        res[f"{key}@local"]["fit_seconds"] = round(time.perf_counter() - t0, 2)
    ben = with_truth(ev, tr).filter(~pl.col("y"))
    src_ben = pl.concat([o["cal"] for o in others], how="diagonal_relaxed")
    res["domain_shift_vs_sources"] = domain_shift(src_ben, ben) if ben.height else None
    return res


def summarise(results: dict) -> dict:
    out: dict = {}
    for variant in ("clean", "unlabelled"):
        rows = {n: r[variant] for n, r in results.items() if isinstance(r.get(variant), dict)}
        keys = sorted({k for r in rows.values() for k, v in r.items()
                       if isinstance(v, dict) and "fpr" in v})  # fmt: skip
        summ = {}
        for k in keys:
            ms = [r[k] for r in rows.values() if k in r]
            elig = [m for m in ms if m.get("pr_auc") is not None and m["attack_windows"] >= 5
                    and m["windows"] - m["attack_windows"] >= 30]  # fmt: skip
            fah = [m["false_alerts_per_h"] for m in ms if m.get("false_alerts_per_h") is not None
                   and m["windows"] > m["attack_windows"]]  # fmt: skip
            ents = sum(m["attacking_entities"] for m in ms)
            det = sum(m["entities_detected"] for m in ms)
            delays = [m["median_delay_s"] for m in ms if m.get("median_delay_s") is not None]
            summ[k] = {"eligible_units": len(elig),
                       "mean_pr_auc": float(np.mean([m["pr_auc"] for m in elig])) if elig else None,
                       "mean_recall": float(np.mean([m["recall"] for m in elig])) if elig else None,
                       "median_fpr": float(np.median([m["fpr"] for m in ms if m["fpr"] is not None])),
                       "median_false_alerts_per_h": float(np.median(fah)) if fah else None,
                       "p90_false_alerts_per_h": float(np.quantile(fah, 0.9)) if fah else None,
                       "entities_detected": f"{det}/{ents}",
                       "median_delay_s": float(np.median(delays)) if delays else None}  # fmt: skip
        out[variant] = summ
    return out


def main() -> None:
    t0 = time.perf_counter()
    caps = dev_captures()
    data = {}
    for name, src in caps.items():
        data[name] = windows(name, src)
        print("windows", name, data[name]["meta"]["flows"], flush=True)
    labelled = {n for n, d in data.items() if d["meta"]["flows"]["eval_attack"] > 0
                or d["meta"]["flows"]["cal_attack"] > 0 or n.startswith("CTU-Normal")}  # fmt: skip
    results = {}
    for name, d in data.items():
        others = [{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"],
                   "truth": data[o]["truth"]} for o in data if o != name and o in labelled
                  and data[o]["cal_clean"].height]  # fmt: skip
        results[name] = {"meta": {k: d["meta"][k] for k in ("flows", "eval_hours")}}
        for variant in ("clean", "unlabelled"):
            results[name][variant] = evaluate_target(name, d, others, variant)
        r = results[name]["clean"]
        print(name, {k: (round(v.get("pr_auc") or -1, 3), round(v.get("false_alerts_per_h") or 0, 2))
                     for k, v in r.items() if isinstance(v, dict) and "fpr" in v}, flush=True)  # fmt: skip
    summary = summarise(results)
    meta = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb(),
            "role": "exploratory (development, inspected captures)"}  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "dev_compare.json").write_text(json.dumps({"summary": summary, "results": results,
                                                      "meta": meta}, indent=1, default=str),
                                          "utf-8")  # fmt: skip
    for v, s in summary.items():
        print(f"== {v}")
        for k, m in sorted(s.items(), key=lambda kv: -(kv[1]["mean_pr_auc"] or 0)):
            print(f"  {k:22s} prauc={m['mean_pr_auc'] or float('nan'):.3f} n={m['eligible_units']} "
                  f"recall={m['mean_recall'] or float('nan'):.3f} fa/h med={m['median_false_alerts_per_h']} "
                  f"p90={m['p90_false_alerts_per_h']} ents={m['entities_detected']} delay={m['median_delay_s']}")  # fmt: skip
    print(meta)


if __name__ == "__main__":
    main()
