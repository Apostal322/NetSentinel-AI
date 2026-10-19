"""Audit of the context features: are the open-set gains genuine or dataset artefacts?

1. Per-day scale: rows, time span, benign flows per hour, and benign medians of the absolute
   rate features. Seven source files are truncated at the Excel row limit, so absolute rates
   may not be comparable across days.
2. No-learning rule baseline: each context feature ALONE, thresholded at benign-validation
   FPR <= 1e-3 (weighted), evaluated on all rows of each attack family (no training at all).
   If a single raw rate reproduces LightGBM's unseen-family recall, the "generalisation" is
   "high-volume floods are rare in benign traffic", not learned attack semantics.
3. Where a rule fires on benign traffic: per-day benign FPR of the best rule per family.
Validation + train rows only (test protected). No model is trained.

Usage: uv run python scripts/audit/audit_context.py   -> reports/audit/context.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.evaluation.metrics import threshold_at_fpr  # noqa: E402
from netsentinel.features.context import context_feature_names  # noqa: E402
from netsentinel.training.data import prepare  # noqa: E402

CTX_RUN = ROOT / "runs/20261019-125018_baseline_binary_flow_ctx_lightgbm"
OUT = ROOT / "reports/audit"
FAMILIES = ("bruteforce", "dos", "ddos", "web_attack", "botnet")
SCALE_INVARIANT = [c for c in context_feature_names() if any(
    t in c for t in ("_frac_", "_share_", "_surge_"))]  # fmt: skip


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    prep = prepare(joblib.load(CTX_RUN / "model.joblib")["config"])
    frame = prep.frame.filter(pl.col("split") != "test")  # never touch test rows
    ctx = context_feature_names()

    # 1. Per-day scale.
    meta = json.loads((ROOT / "data/interim/ids2018/ingest_report.json").read_text("utf-8"))
    day_rows = {m["day"]: m["rows_written"] for m in meta}
    per_day = []
    for (day,), g in frame.filter(pl.col("label") == "benign").group_by("day"):
        span_h = (g["event_sec"].max() - g["event_sec"].min()) / 3600
        benign_full = sum(m["label_counts"].get("benign", 0) for m in meta if m["day"] == day)
        per_day.append({
            "day": day, "file_rows": day_rows[day], "excel_limit_hit": day_rows[day] >= 1_048_566,
            "span_hours": round(span_h, 2), "benign_flows_per_hour": round(benign_full / span_h),
            **{f"median_{c}": float(g[c].median()) for c in
               ("ctx_flow_rate_300s", "ctx_port_flow_rate_300s", "ctx_uniq_ports_300s",
                "ctx_port_share_300s", "ctx_flow_surge_5_300")},
        })  # fmt: skip
    per_day.sort(key=lambda r: r["day"])

    # 2. Single-feature rules.
    benign_val = frame.filter((pl.col("split") == "val") & (pl.col("label") == "benign"))
    w_bv = benign_val["sample_weight"].to_numpy()
    zeros = np.zeros(benign_val.height, dtype=int)
    rules = {}
    for fam in FAMILIES:
        att = frame.filter(pl.col("family") == fam)
        w = att["sample_weight"].to_numpy()
        best = []
        for c in ctx:
            for sign in (1, -1):  # high or low values may indicate the attack
                bv = sign * benign_val[c].to_numpy().astype(np.float64)
                thr = threshold_at_fpr(zeros, bv, 1e-3, w_bv)
                s = sign * att[c].to_numpy().astype(np.float64)
                best.append({"feature": c, "direction": "high" if sign > 0 else "low",
                             "threshold": float(sign * thr),
                             "recall": float((w * (s > thr)).sum() / w.sum()),
                             "benign_val_fpr": float((w_bv * (bv > thr)).sum() / w_bv.sum()),
                             "scale_invariant": c in SCALE_INVARIANT})  # fmt: skip
        best.sort(key=lambda r: -r["recall"])
        top = best[0]
        bv = (1 if top["direction"] == "high" else -1) * benign_val[top["feature"]].to_numpy()
        thr = (1 if top["direction"] == "high" else -1) * top["threshold"]
        fires = benign_val.with_columns(pl.Series("fire", bv > thr))
        rules[fam] = {
            "rows": att.height,
            "best_any": top,
            "best_scale_invariant": next(r for r in best if r["scale_invariant"]),
            "top5": best[:5],
            "best_rule_benign_fpr_by_day": fires.group_by("day").agg(
                ((pl.col("fire") * pl.col("sample_weight")).sum()
                 / pl.col("sample_weight").sum()).alias("fpr")).sort("day").to_dicts(),
        }  # fmt: skip
    out = {"per_day_scale": per_day, "single_feature_rules": rules}
    (OUT / "context.json").write_text(json.dumps(out, indent=2), "utf-8")
    for r in per_day:
        print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()})
    for fam, r in rules.items():
        a, s = r["best_any"], r["best_scale_invariant"]
        print(f"{fam:11s} rows={r['rows']:>6} best={a['feature']}({a['direction']}) "
              f"recall={a['recall']:.3f} | best scale-inv={s['feature']}({s['direction']}) "
              f"recall={s['recall']:.3f}")  # fmt: skip


if __name__ == "__main__":
    main()
