"""Phase 8h exploratory diagnostics [E, post hoc]: why within-network transfer works and
cross-network transfer fails (docs/phase8h/FINAL_RESEARCH_REPORT.md section 8).

NetFlow family only (NF-CIC development days and NF-UNSW); Zeek and NetFlow features are not
compared, because their fields differ in meaning.
1. Per-feature distribution shift of LABEL-BENIGN evaluation windows: two-sample KS statistic
   (NF-CIC pooled vs NF-UNSW; and NF-CIC day vs NF-CIC other days) and 5/50/95% quantiles.
2. Attack windows per held-out attack domain: quantiles of the same features, entity counts
   and the share of attack windows from the heaviest source.
3. Domain-identity negative control: a LightGBM (same settings as B-raw, seed 0) trained to
   tell NF-CIC from NF-UNSW using benign windows only, 50/50 split by time within each
   domain. ROC-AUC near 1 means the features encode network identity.
Output: reports/phase8h/shift_diagnostics.json.
Usage: uv run python scripts/phase8h/shift_diagnostics.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lodo  # noqa: E402

OUT = Path("reports/phase8h/shift_diagnostics.json")
FEATS = lodo.FEATS
CAP = 50_000


def sample(x: np.ndarray, n: int = CAP, seed: int = 0) -> np.ndarray:
    if len(x) <= n:
        return x
    return x[np.random.default_rng(seed).choice(len(x), n, replace=False)]


def q(x: np.ndarray) -> list[float]:
    return [float(v) for v in np.quantile(x, [0.05, 0.5, 0.95])] if len(x) else []


def main() -> None:
    import lightgbm as lgb
    from scipy.stats import ks_2samp
    from sklearn.metrics import roc_auc_score

    doms = lodo.domains("netflow")
    ben = {k: lodo.S._x(d["ev"].filter(pl.col("benign"))) for k, d in doms.items()}
    cic = [k for k in doms if k.startswith("nfcic_")]
    unsw = "NF-UNSW-NB15-v3-dev"
    pooled_cic = sample(np.vstack([sample(ben[k], 10_000) for k in cic if len(ben[k])]))
    b_unsw = sample(ben[unsw])
    out: dict = {"label": "[E] exploratory diagnostics, NetFlow family"}
    out["benign_shift_cic_vs_unsw"] = {
        f: {"ks": float(ks_2samp(pooled_cic[:, i], b_unsw[:, i]).statistic),
            "q_cic": q(pooled_cic[:, i]), "q_unsw": q(b_unsw[:, i])}
        for i, f in enumerate(FEATS)}  # fmt: skip
    within = {}
    for k in cic:
        if len(ben[k]) < 60:
            continue
        rest = np.vstack([sample(ben[o], 10_000) for o in cic if o != k and len(ben[o])])
        within[k] = {f: float(ks_2samp(sample(ben[k])[:, i], rest[:, i]).statistic)
                     for i, f in enumerate(FEATS)}  # fmt: skip
    out["benign_shift_within_cic_median_ks"] = {
        f: float(np.median([v[f] for v in within.values()])) for f in FEATS}  # fmt: skip
    att = {}
    for k in lodo.PRIMARY["netflow"] + lodo.SECONDARY["netflow"]:
        ev = doms[k]["ev"].filter(pl.col("y"))
        per = ev.group_by("key").len().sort("len", descending=True)
        x = lodo.S._x(ev)
        att[k] = {"attack_windows": ev.height, "attack_entities": per.height,
                  "top_entity_share": float(per["len"][0] / ev.height) if ev.height else None,
                  "quantiles": {f: q(x[:, i]) for i, f in enumerate(FEATS)}}  # fmt: skip
    out["attack_windows"] = att
    # negative control: is the network identifiable from benign windows alone?
    xs, ys, part = [], [], []
    for label, keys in ((0, cic), (1, [unsw])):
        for k in keys:
            ev = doms[k]["ev"].filter(pl.col("benign")).sort("win")
            x = lodo.S._x(ev)
            if not len(x):
                continue
            x = x[np.sort(np.random.default_rng(0).choice(len(x), min(len(x), 20_000), False))]
            half = np.arange(len(x)) >= len(x) // 2
            xs.append(x)
            ys.append(np.full(len(x), label))
            part.append(half)
    X, y, test = np.vstack(xs), np.concatenate(ys), np.concatenate(part)  # noqa: N806
    w = np.where(y == 1, 0.5 / (y == 1).sum(), 0.5 / (y == 0).sum()) * len(y)
    m = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15,
                           min_child_samples=20, subsample=0.8, subsample_freq=1,
                           colsample_bytree=0.8, random_state=0, n_jobs=2, verbose=-1)  # fmt: skip
    m.fit(X[~test], y[~test], sample_weight=w[~test])
    p = m.predict_proba(X[test])[:, 1]
    imp = dict(zip(FEATS, m.booster_.feature_importance("gain").tolist(), strict=True))
    out["domain_identity_control"] = {
        "task": "benign window: NF-CIC (0) vs NF-UNSW (1); train first half, test second half",
        "test_roc_auc": float(roc_auc_score(y[test], p)), "n_train": int((~test).sum()),
        "n_test": int(test.sum()),
        "top_gain_features": sorted(imp, key=imp.get, reverse=True)[:5]}  # fmt: skip
    OUT.write_text(json.dumps(out, indent=1), "utf-8")
    print(json.dumps({"domain_identity_auc": out["domain_identity_control"]["test_roc_auc"],
                      "top": out["domain_identity_control"]["top_gain_features"],
                      "ks_cic_vs_unsw": {f: round(v["ks"], 2) for f, v in
                                         out["benign_shift_cic_vs_unsw"].items()}}, indent=1))  # fmt: skip


if __name__ == "__main__":
    main()
