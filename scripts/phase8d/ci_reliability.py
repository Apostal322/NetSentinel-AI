"""Phase 8d, Mission 4 (POST-HOC on the consumed ToN_IoT result; frozen verdicts unchanged).

How reliable are the X3/X4 intervals that came from only 4 hourly bootstrap blocks?
Re-estimates the PR-AUC differences E - robust_z_product (X3) and E - new_dst_frac (X4) with
moving-block bootstraps of 60 / 15 / 5 min blocks and an iid window bootstrap (2,000
resamples, seed 0), and reports how many DISTINCT resamples the 4-block design allows.
Usage: uv run --extra torch python scripts/phase8d/ci_reliability.py
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl
from sklearn.metrics import average_precision_score as ap

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "phase8c"))
sys.path.insert(0, str(HERE.parents[0] / "phase8b"))
import scorers as S  # noqa: E402, N812
from confirm_external import EXCLUDED_FROM_TRAINING  # noqa: E402
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402

TON = Path("data/derived/phase8c_external/toniot")
OUT = Path("reports/phase8d/ci_reliability.json")


def boot(end, y, s1, s2, block_ms: int | None, B=2000, seed=0) -> dict:
    rng = np.random.default_rng(seed)
    if block_ms is None:  # iid windows
        idx = [np.array([i]) for i in range(len(y))]
    else:
        blocks = ((end - end.min()) // block_ms).astype(np.int64)
        idx = [np.where(blocks == b)[0] for b in np.unique(blocks)]
    ds = []
    for _ in range(B):
        pick = np.concatenate([idx[i] for i in rng.integers(0, len(idx), len(idx))])
        yy = y[pick]
        if 0 < yy.sum() < len(yy):
            ds.append(ap(yy, s1[pick]) - ap(yy, s2[pick]))
    d = np.array(ds)
    k = len(idx)
    return {"blocks": k,
            "distinct_resample_multisets": math.comb(2 * k - 1, k) if k <= 30 else ">1e15",
            "ci95": [float(np.quantile(d, 0.025)), float(np.quantile(d, 0.975))],
            "resamples_used": len(d)}  # fmt: skip


def main() -> None:
    names = [n for n in dev_captures() if n not in EXCLUDED_FROM_TRAINING
             and (Path("data/derived/phase8b") / n / "meta.json").exists()]  # fmt: skip
    srcs = []
    for n in names:
        dd = load(Path("data/derived/phase8b") / n)
        if dd["cal_clean"].height:
            srcs.append({"cal": dd["cal_clean"], "ev": dd["eval_clean"], "truth": dd["truth"]})
    model, _ = S.lgbm_fit(srcs, False)
    d = load(TON)
    cal, ev = d["cal_clean"], d["eval_clean"]
    e = with_truth(ev.select("key", "win", "window_end_ms"), d["truth"])
    y = e["y"].to_numpy().astype(int)
    end = e["window_end_ms"].to_numpy()
    s_e = model.predict_proba(S._x(ev))[:, 1]
    s_rz, _ = S.product(cal, ev)
    s_sig = np.nan_to_num(ev["new_dst_frac"].cast(pl.Float64).to_numpy())
    res = {"role": "post-hoc on consumed ToN_IoT; frozen X3/X4 verdicts unchanged",
           "point": {"X3": float(ap(y, s_e) - ap(y, s_rz)), "X4": float(ap(y, s_e) - ap(y, s_sig))},
           "X3": {}, "X4": {}}  # fmt: skip
    for label, bm in (("60min", 3_600_000), ("15min", 900_000), ("5min", 300_000), ("iid", None)):
        res["X3"][label] = boot(end, y, s_e, s_rz, bm)
        res["X4"][label] = boot(end, y, s_e, s_sig, bm)
    # attack share per hour: how heterogeneous is the 4-hour evaluation?
    hrs = (end - end.min()) // 3_600_000
    res["per_hour"] = [{"hour": int(h), "windows": int((hrs == h).sum()),
                        "attack_share": float(y[hrs == h].mean())} for h in np.unique(hrs)]  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
