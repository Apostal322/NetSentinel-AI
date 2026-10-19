"""Why does anomaly detection report ~zero recall at FPR 1e-3? Implementation or protocol?

Uses the saved validation scores of batch-v1 anomaly runs (no retraining of those runs):
1. Score distribution per label vs benign (median and tail shares of the 0-100 score).
2. Reference drift: share of benign VALIDATION flows above the 99 / 99.9 score levels. With a
   representative reference these would be ~1 % / ~0.1 %.
3. Recall at several FPRs (1e-3, 1e-2, 5e-2, 1e-1) and per-label ROC-AUC.
4. Implementation sanity: inject synthetic outliers (benign validation rows with heavy-tailed
   features scaled x50) into the stored Isolation Forest and robust-z models; a working
   detector must flag them at its own threshold.
Validation rows only.

Usage: uv run python scripts/audit/audit_anomaly.py  -> reports/audit/anomaly.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import polars as pl
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.evaluation.metrics import threshold_at_fpr  # noqa: E402
from netsentinel.models.service import service_category_expr  # noqa: E402
from netsentinel.training.data import prepare  # noqa: E402

OUT = ROOT / "reports/audit"
RUNS = sorted(
    p
    for p in (ROOT / "runs").glob(
        sys.argv[1] if len(sys.argv) > 1 else "20261019-1303*_anomaly_flow_*"
    )
    if p.is_dir()
)
INJECT_FEATURES = ("flow_byts_per_s", "fwd_pkt_len_max", "totlen_fwd_pkts", "flow_iat_max",
                   "bwd_pkts_per_s")  # fmt: skip


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    results = {}
    prepared: dict[str, pl.DataFrame] = {}
    for run in RUNS:
        art = joblib.load(run / "model.joblib")
        fs = art["config"]["feature_set"]
        if fs not in prepared:
            prepared.clear()  # one frame in memory at a time
            prepared[fs] = prepare({**art["config"], "task": "binary"}).frame.with_columns(
                service_category_expr()
            )
        val = prepared[fs].filter(pl.col("split") == "val")
        score = np.load(run / "val_scores.npy").astype(np.float64)
        if len(score) != val.height:
            raise RuntimeError(f"{run.name}: scores do not align")
        y = (val["label"] != "benign").to_numpy().astype(int)
        w = val["sample_weight"].to_numpy()
        ben = score[y == 0]
        wb = w[y == 0]
        rec = {}
        for fpr in (1e-3, 1e-2, 5e-2, 1e-1):
            thr = threshold_at_fpr(y, score, fpr, w)
            rec[f"recall_at_fpr_{fpr:g}"] = float((w * (score > thr) * y).sum() / (w * y).sum())
        per_label = []
        for lab in sorted(set(val["label"]) - {"benign"}):
            m = (val["label"] == lab).to_numpy()
            s = score[m]
            per_label.append({
                "label": lab, "rows": int(m.sum()), "median": float(np.median(s)),
                "share_above_99": float((s > 99).mean()), "share_above_99_9": float((s > 99.9).mean()),
                "roc_auc_vs_benign": float(roc_auc_score(np.r_[np.zeros(len(ben)), np.ones(len(s))],
                                                         np.r_[ben, s])),
            })  # fmt: skip
        # Implementation sanity: synthetic outliers.
        model, feats = art["model"], art["features"]
        sample = val.filter(pl.col("label") == "benign").sample(n=2000, seed=0)
        X = sample.select(feats).to_numpy().astype(np.float32)  # noqa: N806
        cols = [feats.index(f) for f in INJECT_FEATURES if f in feats]
        X_inj = X.copy()  # noqa: N806
        X_inj[:, cols] = np.abs(X_inj[:, cols]) * 50 + 1e6
        ctx = sample["service"].to_numpy()
        s_clean, _ = model.score(X, ctx)
        s_inj, _ = model.score(X_inj, ctx)
        thr = art["threshold"]
        results[run.name] = {
            "variant": run.name.split("_anomaly_")[-1],
            "benign_val_share_above_99": float((wb * (ben > 99)).sum() / wb.sum()),
            "benign_val_share_above_99_9": float((wb * (ben > 99.9)).sum() / wb.sum()),
            "benign_val_median": float(np.median(ben)),
            **rec,
            "per_label": per_label,
            "injection": {"threshold": thr, "clean_flag_rate": float((s_clean > thr).mean()),
                          "injected_flag_rate": float((s_inj > thr).mean())},
        }  # fmt: skip
    (OUT / ("anomaly.json" if len(sys.argv) < 3 else sys.argv[2])).write_text(
        json.dumps(results, indent=2), "utf-8"
    )
    for _name, r in results.items():
        print(
            f"== {r['variant']}: benign>99 {r['benign_val_share_above_99']:.4f} "
            f"benign>99.9 {r['benign_val_share_above_99_9']:.4f} | recall@1e-3 "
            f"{r['recall_at_fpr_0.001']:.3f} @1e-2 {r['recall_at_fpr_0.01']:.3f} "
            f"@5e-2 {r['recall_at_fpr_0.05']:.3f} @1e-1 {r['recall_at_fpr_0.1']:.3f} | inject "
            f"{r['injection']['clean_flag_rate']:.3f} -> {r['injection']['injected_flag_rate']:.3f}"
        )
        for p in r["per_label"]:
            print(f"     {p['label']:18s} median={p['median']:6.2f} >99={p['share_above_99']:.3f} "
                  f"auc={p['roc_auc_vs_benign']:.3f}")  # fmt: skip


if __name__ == "__main__":
    main()
