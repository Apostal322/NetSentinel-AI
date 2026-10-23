"""Phase 8c: why does cross-capture LightGBM rank and detect better? Shortcut audit.

1. Feature contributions: mean |SHAP| (LightGBM pred_contrib) on development windows.
2. Single-feature baselines: PR-AUC of each raw feature (best sign) - does a trivial rule match
   LightGBM?
3. Topology control: PR-AUC restricted to PRIVATE source addresses (local devices only). If the
   advantage comes from telling transient external sources from busy local devices (a topology
   artifact), it shrinks here.
4. Ablation: LightGBM without its top-3 features.
5. Cross-dataset: trained on IoT-23 + CTU only -> NF-UNSW; trained on NF-UNSW + CTU only ->
   IoT-23 attack captures.
Development captures are evaluated leave-one-capture-out; the consumed Phase 8b captures are a
RETROSPECTIVE section (model trained on all development captures).
Usage: uv run python scripts/phase8c/lgbm_audit.py -> reports/phase8c/lgbm_audit.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score as ap

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import scorers as S  # noqa: E402, N812
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import RETRO, private  # noqa: E402

DEV = Path("data/derived/phase8b")
FRESH = Path("data/derived/phase8b_fresh")
OUT = Path("reports/phase8c/lgbm_audit.json")
FEATS = S.FEATS
ATTACK_DEV = ["CTU-IoT-Malware-Capture-3-1", "CTU-IoT-Malware-Capture-34-1",
              "NF-UNSW-NB15-v3-dev"]  # fmt: skip


def src(data, names):
    return [{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"], "truth": data[o]["truth"]}
            for o in names if data[o]["cal_clean"].height]  # fmt: skip


def fit(sources, drop=()):
    import lightgbm as lgb

    keep = [i for i, f in enumerate(FEATS) if f not in drop]
    xs, ys, ws = [], [], []
    for s in sources:
        ev = with_truth(s["ev"], s["truth"])
        x = np.vstack([S._x(s["cal"]), S._x(ev)])[:, keep]
        y = np.r_[np.zeros(s["cal"].height), ev["y"].to_numpy()].astype(int)
        xs.append(x)
        ys.append(y)
        ws.append(np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
    X, y, w = np.vstack(xs), np.concatenate(ys), np.concatenate(ws)  # noqa: N806
    m = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15,
                           min_child_samples=20, subsample=0.8, subsample_freq=1,
                           colsample_bytree=0.8, random_state=0, n_jobs=2, verbose=-1)  # fmt: skip
    m.fit(X, y, sample_weight=w * len(y))
    return m, keep


def target_eval(m, keep, d) -> dict:
    ev = with_truth(d["eval_clean"], d["truth"])
    X = S._x(ev)  # noqa: N806
    y = ev["y"].to_numpy().astype(int)
    s = m.predict_proba(X[:, keep])[:, 1]
    priv = np.array([private(k) for k in ev["key"].to_list()])
    out = {"windows": len(y), "attack": int(y.sum()), "private_share": float(priv.mean())}
    if 0 < y.sum() < len(y):
        out["pr_auc"] = float(ap(y, s))
    yp = y[priv]
    if 0 < yp.sum() < len(yp):
        out["pr_auc_private_only"] = float(ap(yp, s[priv]))
        out["base_rate_private_only"] = float(yp.mean())
    single = {}
    for i, f in enumerate(FEATS):
        if 0 < y.sum() < len(y):
            v = np.nan_to_num(X[:, i])
            single[f] = float(max(ap(y, v), ap(y, -v)))
    out["single_feature_pr_auc"] = dict(sorted(single.items(), key=lambda kv: -kv[1])[:4])
    out["base_rate"] = float(y.mean()) if len(y) else None
    return out


def shap_importance(m, keep, sources) -> dict:
    X = np.vstack([S._x(with_truth(s["ev"], s["truth"])) for s in sources])[:, keep]  # noqa: N806
    c = m.booster_.predict(X, pred_contrib=True)
    imp = np.abs(c[:, :-1]).mean(axis=0)
    names = [FEATS[i] for i in keep]
    return dict(sorted(zip(names, imp.round(4).tolist(), strict=True), key=lambda kv: -kv[1]))


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    data = {n: load(DEV / n) for n in names}
    res: dict = {"note": "development = leave-one-capture-out; retrospective = consumed captures"}
    m_all, keep_all = fit(src(data, names))
    res["shap_mean_abs_dev"] = shap_importance(m_all, keep_all, src(data, names))
    top3 = list(res["shap_mean_abs_dev"])[:3]
    res["top3"] = top3
    dev = {}
    for n in ATTACK_DEV:
        others = [o for o in names if o != n]
        m, k = fit(src(data, others))
        m3, k3 = fit(src(data, others), drop=top3)
        r = target_eval(m, k, data[n])
        r["pr_auc_without_top3"] = target_eval(m3, k3, data[n]).get("pr_auc")
        dev[n] = r
    # cross-dataset
    iot_ctu = [o for o in names if not o.startswith("NF-")]
    unsw_ctu = [o for o in names if o.startswith(("NF-", "CTU-Normal"))]
    m, k = fit(src(data, iot_ctu))
    dev["NF-UNSW-NB15-v3-dev"]["pr_auc_trained_iot23_ctu_only"] = target_eval(
        m, k, data["NF-UNSW-NB15-v3-dev"]).get("pr_auc")  # fmt: skip
    m, k = fit(src(data, unsw_ctu))
    for n in ("CTU-IoT-Malware-Capture-3-1", "CTU-IoT-Malware-Capture-34-1"):
        dev[n]["pr_auc_trained_unsw_ctu_only"] = target_eval(m, k, data[n]).get("pr_auc")
    res["development"] = dev
    m3, k3 = fit(src(data, names), drop=top3)
    retro = {}
    for n in RETRO:
        p = FRESH / n
        if (p / "meta.json").exists():
            d = load(p)
            r = target_eval(m_all, keep_all, d)
            r["pr_auc_without_top3"] = target_eval(m3, k3, d).get("pr_auc")
            r["shap_mean_abs"] = shap_importance(m_all, keep_all, [{"cal": d["cal_clean"],
                                                 "ev": d["eval_clean"], "truth": d["truth"]}])  # fmt: skip
            retro[n] = r
    res["retrospective_consumed"] = retro
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print("SHAP (dev):", res["shap_mean_abs_dev"])
    for title, block in (("DEV", dev), ("RETRO", retro)):
        for n, r in block.items():
            print(title, n[:30], {k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()
                                  if k not in ("shap_mean_abs",)})  # fmt: skip


if __name__ == "__main__":
    main()
