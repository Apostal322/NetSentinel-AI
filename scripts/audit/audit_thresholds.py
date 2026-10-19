"""Threshold and calibration audit on VALIDATION scores of the pre-registered threat runs.

1. Realised weighted benign FPR at the frozen threshold (target 1e-3) and how many benign
   validation rows sit above it (statistical support of the operating point).
2. Sensitivity: FPR and recall when the threshold is scaled x0.5, x2, x10 (fragility).
3. Per-day benign FPR at the frozen threshold.
4. Calibration: ECE of raw scores, of isotonic fitted in-sample on validation (what the bundle
   does), and of isotonic CROSS-FITTED by day (fit on half the days, evaluate on the others) -
   an honest out-of-sample estimate that does not touch test.

Usage: uv run python scripts/audit/audit_thresholds.py -> reports/audit/thresholds.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.isotonic import IsotonicRegression

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.evaluation.metrics import expected_calibration_error  # noqa: E402
from netsentinel.training.data import prepare  # noqa: E402

RUNS = ["20261019-124619_baseline_binary_lightgbm",
        "20261019-124729_baseline_binary_flow_noshortcut_lightgbm",
        "20261019-125018_baseline_binary_flow_ctx_lightgbm"]  # fmt: skip


def audit(run: Path) -> dict:
    art = joblib.load(run / "model.joblib")
    val = prepare(art["config"]).part("val")
    s = np.load(run / "val_scores.npy").astype(np.float64)
    assert len(s) == val.height
    y = (val["label"] != "benign").to_numpy().astype(int)
    w = val["sample_weight"].to_numpy()
    thr = art["threshold"]
    ben, att = y == 0, y == 1

    def fpr_recall(t: float) -> tuple[float, float]:
        return (float((w[ben] * (s[ben] > t)).sum() / w[ben].sum()),
                float((w[att] * (s[att] > t)).sum() / w[att].sum()))  # fmt: skip

    sens = {}
    for f in (0.5, 1.0, 2.0, 10.0):
        fp, rc = fpr_recall(thr * f)
        sens[f"x{f:g}"] = {"threshold": thr * f, "fpr": fp, "recall": rc}
    days = val["day"].to_numpy()
    per_day = {d: float((w[ben & (days == d)] * (s[ben & (days == d)] > thr)).sum()
                        / w[ben & (days == d)].sum()) for d in np.unique(days[ben])}  # fmt: skip
    # Calibration.
    iso_in = IsotonicRegression(out_of_bounds="clip").fit(s, y, sample_weight=w)
    uniq = np.unique(days)
    rng = np.random.default_rng(0)
    half = set(rng.choice(uniq, size=len(uniq) // 2, replace=False))
    a = np.isin(days, list(half))
    oof = np.empty_like(s)
    for fit_mask in (a, ~a):
        iso = IsotonicRegression(out_of_bounds="clip").fit(s[fit_mask], y[fit_mask],
                                                           sample_weight=w[fit_mask])  # fmt: skip
        oof[~fit_mask] = iso.predict(s[~fit_mask])
    return {
        "threshold": thr,
        "benign_val_rows_above_threshold": int((s[ben] > thr).sum()),
        "benign_val_rows": int(ben.sum()),
        "sensitivity": sens,
        "benign_fpr_by_day": per_day,
        "ece_raw": expected_calibration_error(y, s, w),
        "ece_isotonic_in_sample": expected_calibration_error(y, iso_in.predict(s), w),
        "ece_isotonic_cross_fitted_by_day": expected_calibration_error(y, oof, w),
        "cross_fit_day_halves": sorted(half),
    }


def main() -> None:
    out = {r: audit(ROOT / "runs" / r) for r in RUNS}
    (ROOT / "reports/audit/thresholds.json").write_text(json.dumps(out, indent=2, default=str))
    for r, d in out.items():
        print(
            f"== {r}\n   thr={d['threshold']:.3g} benign rows above={d['benign_val_rows_above_threshold']}"
            f"/{d['benign_val_rows']}  ECE raw={d['ece_raw']:.4f} iso-in={d['ece_isotonic_in_sample']:.4f}"
            f" iso-crossfit={d['ece_isotonic_cross_fitted_by_day']:.4f}"
        )
        for k, v in d["sensitivity"].items():
            print(f"   {k:5s} fpr={v['fpr']:.5f} recall={v['recall']:.4f}")
        print("   per-day FPR:", {k: round(v, 4) for k, v in d["benign_fpr_by_day"].items()})


if __name__ == "__main__":
    main()
