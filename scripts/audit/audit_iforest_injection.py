"""Stricter outlier-injection test for the stored anomaly models: set k features of benign
validation rows to 10x the BENIGN TRAIN maximum (beyond the observed range in raw and in
signed-log space) and measure the flag rate at each model's own validation threshold.

Usage: uv run python scripts/audit/audit_iforest_injection.py -> reports/audit/injection.json
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
from netsentinel.models.service import service_category_expr  # noqa: E402
from netsentinel.training.data import prepare  # noqa: E402

RUNS = sorted(
    p
    for p in (ROOT / "runs").glob(
        sys.argv[1] if len(sys.argv) > 1 else "20261019-1303*_anomaly_flow_[ri]*"
    )
    if p.is_dir()
)


def main() -> None:
    first = joblib.load(RUNS[0] / "model.joblib")
    frame = prepare({**first["config"], "task": "binary"}).frame.with_columns(
        service_category_expr()
    )
    feats = first["features"]
    train_b = frame.filter((pl.col("split") == "train") & (pl.col("label") == "benign"))
    tmax = np.nanmax(np.where(np.isfinite(t := train_b.select(feats).to_numpy().astype(np.float64)),
                              t, np.nan), axis=0)  # fmt: skip
    del t
    sample = frame.filter((pl.col("split") == "val") & (pl.col("label") == "benign")).sample(
        n=2000, seed=0
    )
    X = sample.select(feats).to_numpy().astype(np.float32)  # noqa: N806
    ctx = sample["service"].to_numpy()
    rng = np.random.default_rng(0)
    continuous = [i for i, f in enumerate(feats) if tmax[i] > 10 and not f.startswith("proto_")]
    out = {}
    for run in RUNS:
        art = joblib.load(run / "model.joblib")
        model, thr = art["model"], art["threshold"]
        res = {"threshold": thr, "clean": float((model.score(X, ctx)[0] > thr).mean())}
        for k in (1, 3, 10):
            X_inj = X.copy()  # noqa: N806
            for r in range(len(X_inj)):
                cols = rng.choice(continuous, size=k, replace=False)
                X_inj[r, cols] = (tmax[cols] * 10).astype(np.float32)
            res[f"beyond_range_{k}_features"] = float((model.score(X_inj, ctx)[0] > thr).mean())
        out[run.name.split("_anomaly_")[-1]] = res
        print(run.name.split("_anomaly_")[-1], res)
    (ROOT / ("reports/audit/injection.json" if len(sys.argv) < 3 else sys.argv[2])).write_text(
        json.dumps(out, indent=2), "utf-8"
    )


if __name__ == "__main__":
    main()
