"""Phase 6D: application classification ablations, abstention, cross-dataset shift, artifacts.

Pre-stated choices: docs/phase6/DEVELOPMENT_LOG.md ("6D ... pre-stated choices").
Data: benign NF-v3 flows, episode train / validation (A: thresholds, B: reported); the
episode test partition is excluded by `prepare`. Labels: nDPI master protocol (proxy).

Usage: uv run python scripts/phase6/train_appid_v2.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import polars as pl
import yaml

from netsentinel.appintel.model import AppClassifier, save_classifier
from netsentinel.features.nf_schema import NF_PORTABLE_COLUMNS, NF_SHORTCUT_SUSPECTS, nf_feature_set
from netsentinel.models.baselines import fit_weighted, make_model
from netsentinel.resources import peak_rss_mb
from netsentinel.seed import set_seed
from netsentinel.training.appid import _load, _name, _port_key, _port_table, _scores

OUT = Path("reports/phase6")
MODELS = Path("models/appintel")
FULL = nf_feature_set("nf_flow")
NOSC = [f for f in FULL if f not in NF_SHORTCUT_SUSPECTS]
SETS = {
    "full": FULL,
    "full_noport": [f for f in FULL if f != "port_class"],
    "noshortcut": NOSC,
    "pcap_safe": [f for f in NOSC if not f.endswith("_second_bytes")],
    "portable": [*NF_PORTABLE_COLUMNS, "proto_tcp", "proto_udp", "proto_other", "port_class"],
    "portable_noport": [*NF_PORTABLE_COLUMNS, "proto_tcp", "proto_udp", "proto_other"],
}
PREFERENCE = ("portable", "pcap_safe", "noshortcut")  # product choice order (pre-stated)


def weighted_f1(y, pred, w, classes) -> float:
    f1s, ws = [], []
    for c in classes:
        tp = float(w[(y == c) & (pred == c)].sum())
        p_den, r_den = float(w[pred == c].sum()), float(w[y == c].sum())
        if not r_den:
            continue
        prec = tp / p_den if p_den else 0.0
        rec = tp / r_den
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
        ws.append(r_den)
    return float(np.average(f1s, weights=ws)) if f1s else 0.0


def conf_threshold(conf, ok, w, target=0.95) -> float:
    order = np.argsort(-conf)
    acc = np.cumsum((ok * w)[order]) / np.cumsum(w[order])
    good = np.where(acc >= target)[0]
    return float(conf[order][good[-1]]) if len(good) else 1.01


def coverage_curve(conf, ok, w) -> list[dict]:
    out = []
    for t in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99):
        m = conf >= t
        out.append({"threshold": t, "coverage": float(w[m].sum() / w.sum()),
                    "accepted_accuracy": float(np.average(ok[m], weights=w[m])) if m.any()
                    else None})  # fmt: skip
    return out


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="diagnostic: one dataset, no artifacts")
    a = ap.parse_args()
    t0 = time.perf_counter()
    cfg = yaml.safe_load(open("configs/experiments/appid_nf.yaml", encoding="utf-8"))
    if a.only:
        cfg["datasets"] = {a.only: cfg["datasets"][a.only]}
    seed = int(cfg.get("seed", 42))
    set_seed(seed)
    res: dict = {"sets": {k: v for k, v in SETS.items()}, "datasets": {}}
    models: dict = {}
    vals: dict = {}
    for name, ds in cfg["datasets"].items():
        parts = _load(cfg, ds, seed, int(cfg.get("max_rows", 400_000)))
        tr = parts["train"]
        share = tr.group_by("app").agg(pl.col("sample_weight").sum()).sort(
            "sample_weight", descending=True)  # fmt: skip
        top = share["app"].head(int(cfg.get("top_k", 10))).to_list()
        y = {k: np.where(np.isin(v["app"].to_numpy(), top), v["app"].to_numpy(), -1)
             for k, v in parts.items()}  # fmt: skip
        w = {k: v["sample_weight"].to_numpy().astype(float) for k, v in parts.items()}
        classes = np.array(sorted(set(y["train"].tolist())))
        r: dict = {"rows": {k: v.height for k, v in parts.items()},
                   "classes": [_name(c) for c in classes], "models": {}}  # fmt: skip
        table = _port_table(_port_key(tr), y["train"], w["train"])
        maj = classes[np.argmax([w["train"][y["train"] == c].sum() for c in classes])]
        pl_pred = np.array([table.get(x, maj) for x in _port_key(parts["val_b"]).tolist()])
        r["models"]["port_lookup"] = {**_scores(y["val_b"], pl_pred, w["val_b"], classes),
                                      "weighted_f1": weighted_f1(y["val_b"], pl_pred, w["val_b"],
                                                                 classes)}  # fmt: skip
        for fs, feats in SETS.items():
            t1 = time.perf_counter()
            m = make_model("lightgbm", cfg.get("lightgbm_params"), seed=seed)
            Xtr = tr.select(feats).to_numpy().astype(np.float32)  # noqa: N806
            fit_weighted(m, Xtr, y["train"], w["train"])
            sub = np.random.default_rng(0).choice(len(Xtr), size=min(20_000, len(Xtr)),
                                                  replace=False)  # fmt: skip
            train_acc = float((m.classes_[m.predict_proba(Xtr[sub]).argmax(1)]
                               == y["train"][sub]).mean())  # fmt: skip
            lo = np.nanpercentile(Xtr, 0.5, axis=0)
            hi = np.nanpercentile(Xtr, 99.5, axis=0)
            pa = m.predict_proba(parts["val_a"].select(feats).to_numpy().astype(np.float32))
            pb = m.predict_proba(parts["val_b"].select(feats).to_numpy().astype(np.float32))
            pred_a, pred_b = m.classes_[pa.argmax(1)], m.classes_[pb.argmax(1)]
            ok_a = (pred_a == y["val_a"]).astype(float)
            ok_b = (pred_b == y["val_b"]).astype(float)
            thr = conf_threshold(pa.max(1), ok_a, w["val_a"], 0.95)
            Xb = parts["val_b"].select(feats).to_numpy().astype(np.float32)  # noqa: N806
            ood_b = ((Xb < lo) | (Xb > hi)).mean(axis=1) > 0.3
            acc_m = pb.max(1) >= thr
            sc = _scores(y["val_b"], pred_b, w["val_b"], classes)
            conf_mat = {_name(t): {_name(p): round(float(w["val_b"][(y["val_b"] == t)
                                                   & (pred_b == p)].sum()), 1)
                                   for p in classes} for t in classes}  # fmt: skip
            r["models"][fs] = {
                **sc, "weighted_f1": weighted_f1(y["val_b"], pred_b, w["val_b"], classes),
                "confidence_threshold_95": thr,
                "coverage_at_threshold": float(w["val_b"][acc_m].sum() / w["val_b"].sum()),
                "accepted_accuracy_at_threshold": float(np.average(ok_b[acc_m],
                                                                   weights=w["val_b"][acc_m]))
                if acc_m.any() else None,
                "ood_share_val_b": float(ood_b.mean()),
                "coverage_curve": coverage_curve(pb.max(1), ok_b, w["val_b"]),
                "confusion_val_b_weighted": conf_mat,
                "fit_seconds": round(time.perf_counter() - t1, 1),
                "train_accuracy_sample": train_acc,
            }  # fmt: skip
            models[(name, fs)] = (m, feats, [_name(c) for c in m.classes_], thr, lo, hi)
            print(name, fs, {k: round(r["models"][fs][k], 4) for k in
                             ("accuracy", "macro_f1", "weighted_f1", "coverage_at_threshold")},
                  flush=True)  # fmt: skip
        vals[name] = (parts["val_b"], y["val_b"], w["val_b"])
        res["datasets"][name] = r
        del parts, tr
    if a.only:
        print(json.dumps({k: v["macro_f1"] for k, v in res["datasets"][a.only]["models"].items()}))
        return
    # cross-dataset shift: model trained on A, evaluated on B's validation flows whose (proxy)
    # class exists in A's label set (excluding 'other')
    names = list(cfg["datasets"])
    for a, b in ((names[0], names[1]), (names[1], names[0])):
        vb, yb, wb = vals[b]
        for fs in SETS:
            m, feats, cls, thr, lo, hi = models[(a, fs)]
            lab_b = np.array([_name(c) for c in yb], dtype=object)
            shared = np.isin(lab_b, [c for c in cls if c != "other"])
            if not shared.any():
                continue
            p = m.predict_proba(vb.select(feats).to_numpy().astype(np.float32)[shared])
            pred = np.asarray(cls, dtype=object)[p.argmax(1)]
            ok = (pred == lab_b[shared]).astype(float)
            ww = wb[shared]
            sel = p.max(1) >= thr
            res.setdefault("cross", {})[f"{a}->{b}/{fs}"] = {
                "shared_classes": sorted(set(lab_b[shared].tolist())),
                "rows": int(shared.sum()),
                "accuracy": float(np.average(ok, weights=ww)),
                "coverage_at_source_threshold": float(ww[sel].sum() / ww.sum()),
                "accepted_accuracy": float(np.average(ok[sel], weights=ww[sel]))
                if sel.any() else None}  # fmt: skip
    # H6 and product selection (pre-stated rules)
    ids = res["datasets"][names[0]]["models"]
    res["H6"] = {"full_macro_f1": ids["full"]["macro_f1"],
                 "noshortcut_macro_f1": ids["noshortcut"]["macro_f1"],
                 "supported": ids["noshortcut"]["macro_f1"] >= 0.9 * ids["full"]["macro_f1"]}  # fmt: skip
    chosen = next((fs for fs in PREFERENCE if ids[fs]["macro_f1"] >= 0.9 * ids["full"]["macro_f1"]),
                  "full")  # fmt: skip
    m, feats, cls, thr, lo, hi = models[(names[0], chosen)]
    clf = AppClassifier(model=m, features=feats, classes=cls, feature_set=chosen,
                        confidence_threshold=thr, ood_low=lo, ood_high=hi,
                        metadata={"training_data": f"{names[0]} benign flows, episode train",
                                  "validation": {k: ids[chosen][k] for k in
                                                 ("accuracy", "macro_f1", "weighted_f1",
                                                  "coverage_at_threshold",
                                                  "accepted_accuracy_at_threshold")},
                                  "selection_rule": "most portable set with macro-F1 >= 0.9x "
                                                    "full on NF-IDS2018 validation B",
                                  "evaluation_status": "validation only (proxy labels)"})  # fmt: skip
    path = save_classifier(clf, MODELS)
    res["product_model"] = {"feature_set": chosen, "artifact": str(path)}
    if chosen != "portable" and (names[0], "portable") in models:
        # Zeek logs provide only portable fields: keep that model for the external H7 check
        m, feats, cls, thr, lo, hi = models[(names[0], "portable")]
        extra = AppClassifier(model=m, features=feats, classes=cls, feature_set="portable",
                              confidence_threshold=thr, ood_low=lo, ood_high=hi,
                              metadata={"role": "research-only (Zeek-compatible, H7 check)",
                                        "validation": {k: ids["portable"][k] for k in
                                                       ("accuracy", "macro_f1")}})  # fmt: skip
        res["portable_model"] = str(save_classifier(extra, MODELS))
    res["meta"] = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "appid_v2.json").write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({k: res[k] for k in ("H6", "product_model", "meta")}, indent=1))


if __name__ == "__main__":
    main()
