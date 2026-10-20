"""Mission 3 validity check: WHY does the target-benign autoencoder separate attacks so well?

Reproduces one v5 cell (target = chronological validation partition, clean calibration sample
drawn proportional to sample weights, detector fit on the first half and thresholded at
FPR 1e-3 on the second half), with the same autoencoder architecture as training/adapt.py,
and reports:
* per-feature share of reconstruction error on attack vs benign flows;
* recall per attack label at the calibrated threshold;
* ablations: drop the TTL / TCP-window shortcut suspects; drop the top error features;
  Isolation Forest on the same inputs for reference.
No target attack label is used to fit or threshold anything; labels are used only to report.

Usage: uv run --extra torch python scripts/audit/audit_autoencoder.py [--dataset unsw|ids]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.features.nf_schema import NF_SHORTCUT_SUSPECTS
from netsentinel.seed import set_seed
from netsentinel.training.adapt import RobustScaler, _cal_threshold, _evaluate
from netsentinel.training.data import prepare

DS = {
    "unsw": {"processed_dir": "data/processed/nf_unsw_nb15_v3", "drop_labels": [],
             "clean_labels": 0},
    "ids": {"processed_dir": "data/processed/nf_cicids2018_v3", "drop_labels": ["infiltration"],
            "clean_labels": 2},
}  # fmt: skip
SPLIT = {"protocol": "chronological", "purge_seconds": 150, "fractions": [0.6, 0.2, 0.2]}


def train_ae(fit_x: np.ndarray, seed: int, epochs: int = 15):
    """Identical to training/adapt.py::_autoencoder_scores (d-32-8-32-d, Adam 1e-3, bs 256)."""
    import torch
    from torch import nn

    torch.manual_seed(seed)
    d = fit_x.shape[1]
    net = nn.Sequential(nn.Linear(d, 32), nn.ReLU(), nn.Linear(32, 8), nn.ReLU(),
                        nn.Linear(8, 32), nn.ReLU(), nn.Linear(32, d))  # fmt: skip
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    x = torch.from_numpy(np.clip(fit_x, -20, 20))
    g = torch.Generator().manual_seed(seed)
    for _ in range(epochs):
        perm = torch.randperm(len(x), generator=g)
        for i in range(0, len(x), 256):
            b = x[perm[i : i + 256]]
            opt.zero_grad()
            ((net(b) - b) ** 2).mean().backward()
            opt.step()
    net.eval()

    def errors(xs: np.ndarray) -> np.ndarray:  # per-feature squared error
        with torch.no_grad():
            t = torch.from_numpy(np.clip(xs, -20, 20))
            return ((net(t) - t) ** 2).numpy()

    return errors


def iforest(fit_x, xs, seed):
    from sklearn.ensemble import IsolationForest

    m = IsolationForest(n_estimators=200, max_samples=min(512, len(fit_x)), random_state=seed,
                        n_jobs=2).fit(fit_x)  # fmt: skip
    return [-m.score_samples(x) for x in xs]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="unsw", choices=sorted(DS))
    ap.add_argument("--n", type=int, default=50_000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    set_seed(a.seed)
    prep = prepare({"seed": a.seed, "data": DS[a.dataset], "feature_set": "nf_flow",
                    "split": SPLIT, "task": "binary"})  # fmt: skip
    feats = prep.features
    pool, ev = prep.part("train"), prep.part("val")
    hours = (ev["day"] + "_" + (ev["event_sec"] // 900).cast(pl.Utf8)).n_unique() * 0.25
    Xe = ev.select(feats).to_numpy().astype(np.float32)  # noqa: N806
    ye, we = (ev["label"] != "benign").to_numpy().astype(int), ev["sample_weight"].to_numpy()
    labels = ev["label"].to_numpy()
    ben = pool.filter(pl.col("label") == "benign")
    wp = ben["sample_weight"].to_numpy().astype(float)
    rng = np.random.default_rng(a.seed)
    idx = rng.choice(ben.height, size=min(a.n, ben.height), replace=False, p=wp / wp.sum())
    Xc = ben.select(feats).to_numpy().astype(np.float32)[idx]  # noqa: N806
    half = len(Xc) // 2
    sc = RobustScaler().fit(Xc[:half])
    F, T, E = sc.transform(Xc[:half]), sc.transform(Xc[half:]), sc.transform(Xe)  # noqa: N806
    out: dict = {"dataset": a.dataset, "n_calibration": len(Xc), "features": feats,
                 "eval_rows": len(Xe), "eval_attack_rows": int(ye.sum())}  # fmt: skip

    def run(name: str, cols: list[int], detail: bool = False) -> None:
        err = train_ae(F[:, cols], a.seed)
        e_thr, e_ev = err(T[:, cols]), err(E[:, cols])
        thr = _cal_threshold(e_thr.mean(1), 1e-3)
        s = e_ev.mean(1)
        res = _evaluate(ye, we, s, thr, hours)
        i_thr, i_ev = iforest(F[:, cols], [T[:, cols], E[:, cols]], a.seed)
        res["iforest_same_inputs"] = _evaluate(ye, we, i_ev, _cal_threshold(i_thr, 1e-3), hours)
        if detail:
            share = lambda m: (e_ev[m].sum(0) / e_ev[m].sum()).tolist()  # noqa: E731
            sa, sb = share(ye == 1), share(ye == 0)
            order = np.argsort(sa)[::-1]
            res["error_share_top"] = [{"feature": feats[cols[i]], "attack": round(sa[i], 4),
                                       "benign": round(sb[i], 4)} for i in order[:12]]  # fmt: skip
            # scaled-value contrast for the top features (median |z| attack vs benign)
            res["median_abs_z_top"] = {feats[cols[i]]: {
                "attack": round(float(np.median(np.abs(E[ye == 1][:, cols[i]]))), 3),
                "benign": round(float(np.median(np.abs(E[ye == 0][:, cols[i]]))), 3)}
                for i in order[:6]}  # fmt: skip
            res["recall_by_label"] = {lab: round(float((s[labels == lab] > thr).mean()), 4)
                                      for lab in sorted(set(labels)) if lab != "benign"}  # fmt: skip
            res["_top_idx"] = [int(cols[i]) for i in order[:5]]
        out[name] = res
        print(
            name,
            {k: res[k] for k in ("recall", "fpr", "roc_auc")},
            "iforest",
            res["iforest_same_inputs"]["recall"],
            flush=True,
        )

    all_cols = list(range(len(feats)))
    run("ae_all_flow", all_cols, detail=True)
    run("ae_no_shortcut", [i for i in all_cols if feats[i] not in NF_SHORTCUT_SUSPECTS], True)
    top = out["ae_all_flow"].pop("_top_idx")
    out["ae_no_shortcut"].pop("_top_idx", None)
    for k in (1, 3, 5):
        run(f"ae_drop_top{k}", [i for i in all_cols if i not in top[:k]])
    path = Path(f"reports/audit/autoencoder_{a.dataset}.json")
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
