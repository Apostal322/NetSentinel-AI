"""Phase 8b scorers on identical device-window inputs (scripts/phase8b/harness.py).

Unsupervised / local (fit on the target's own calibration windows only):
* robust_z, guarded_ewma, lag_iforest, gru, tcn: the Phase 8B protocol
  (compare_temporal.compare_windows): fit on calibration windows before 70% of the span,
  split-conformal threshold (target FPR 1%) on the rest; evaluation scored with history;
* robust_z_product: the product path (calibrate_windows, cross-fit thresholds, vetted mode).
Supervised (trained on OTHER captures' labelled windows; never on the target):
* lgbm_raw: LightGBM on the 12 raw window features;
* lgbm_local: LightGBM on features standardised by each capture's own calibration windows
  (median/MAD), i.e. "how unusual is this window for this network", learned across networks.
Each LightGBM is reported with two thresholds: `source` (1% FPR on source benign windows,
transferred unchanged - the domain-shift setting) and `local` (split-conformal on the target's
calibration hold-out, like the unsupervised scorers).
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8"))
from compare_temporal import compare_windows  # noqa: E402

from netsentinel.behavior.profile import conformal_threshold  # noqa: E402
from netsentinel.behavior.temporal import RobustScaler  # noqa: E402
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402

FEATS = list(WINDOW_FEATURES)
UNSUP = [("robust_z", "base", {}), ("guarded_ewma", "base", {}), ("lag_iforest", "base", {}),
         ("gru", "base", {"epochs": 15, "hidden": 32, "seq_len": 8}),
         ("tcn", "base", {"epochs": 15, "hidden": 32, "seq_len": 8})]  # fmt: skip
TARGET = 0.01


def _x(df: pl.DataFrame) -> np.ndarray:
    return np.nan_to_num(df.select([pl.col(f).cast(pl.Float64) for f in FEATS]).to_numpy())


def split_cut(cal: pl.DataFrame) -> int:
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    return lo + int(math.floor((hi - lo + 1) * 0.7))


def unsupervised(cal: pl.DataFrame, ev: pl.DataFrame, truth: pl.DataFrame,
                 hours: float) -> dict[str, tuple[np.ndarray, float]]:  # fmt: skip
    r = compare_windows(cal, ev, truth, UNSUP, hours, keep_scores=True)
    if r.get("status"):
        return {}
    return {name: (r[f"{name}/{f}"]["_scores"], r[f"{name}/{f}"]["_threshold"])
            for name, f, _ in UNSUP}  # fmt: skip


def product(cal: pl.DataFrame, ev: pl.DataFrame, seen: set | None = None):
    """Product robust_z (cross-fit thresholds). Returns (scores aligned to ev, threshold)."""
    from netsentinel.behavior.calibrate import calibrate_windows
    from netsentinel.behavior.profile import BehaviorProfile

    lv = calibrate_windows({"device": cal}, 0, target_fpr=TARGET, min_windows=30,
                           mode="vetted_benign", top_k=2, threshold_method="crossfit")  # fmt: skip
    prof = BehaviorProfile(window_s=30, mode="vetted_benign", target_fpr=TARGET, min_windows=30,
                           top_k=2, levels=lv, known_dst=seen or set(), status="baseline_ready",
                           period={}, diagnostics={})  # fmt: skip
    sc = prof.score(ev.with_columns(pl.lit("device").alias("level")))
    aligned = ev.select("key", "win").join(sc.select("key", "win", "score"), on=["key", "win"],
                                           how="left")  # fmt: skip
    thr = lv["device"].threshold
    return aligned["score"].fill_null(0.0).to_numpy(), (math.inf if thr is None else float(thr))


def local_scaler(cal: pl.DataFrame) -> RobustScaler:
    return RobustScaler().fit(_x(cal), FEATS)


def lgbm_fit(sources: list[dict], local: bool, seed: int = 0):
    """sources: [{"X_cal": calibration windows, "ev": eval windows, "truth": truth}] (labelled
    OTHER captures). Each capture gets equal total weight."""
    import lightgbm as lgb

    xs, ys, ws = [], [], []
    for s in sources:
        ev = s["ev"].join(s["truth"], on=["key", "win"], how="left").with_columns(
            pl.col("y").fill_null(False))  # fmt: skip
        parts = [(_x(s["cal"]), np.zeros(s["cal"].height)), (_x(ev), ev["y"].to_numpy())]
        x = np.vstack([p[0] for p in parts])
        y = np.concatenate([p[1] for p in parts]).astype(int)
        if local:
            x = local_scaler(s["cal"]).transform(x)
        xs.append(x)
        ys.append(y)
        # equal weight per capture, balanced classes within it
        w = np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1))
        ws.append(w)
    X, y, w = np.vstack(xs), np.concatenate(ys), np.concatenate(ws)  # noqa: N806
    m = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15,
                           min_child_samples=20, subsample=0.8, subsample_freq=1,
                           colsample_bytree=0.8, random_state=seed, n_jobs=2, verbose=-1)  # fmt: skip
    m.fit(X, y, sample_weight=w * len(y))
    benign = m.predict_proba(X[y == 0])[:, 1]
    src_thr = float(np.quantile(benign, 1 - TARGET)) if len(benign) else 0.5
    return m, src_thr


def lgbm_score(model, cal: pl.DataFrame, ev: pl.DataFrame, local: bool):
    """Returns (eval scores, local split-conformal threshold from the calibration hold-out)."""
    xe, xc = _x(ev), _x(cal)
    if local:
        sc = local_scaler(cal)
        xe, xc = sc.transform(xe), sc.transform(xc)
    s_ev = model.predict_proba(xe)[:, 1]
    hold = (cal["win"] >= split_cut(cal)).to_numpy()
    thr, _ = conformal_threshold(model.predict_proba(xc[hold])[:, 1], TARGET)
    return s_ev, float(thr)
