"""Phase 8D: application-ID abstention on DEVELOPMENT data, and the product artifact rebuild.

Compared: port_only, ml_only, hybrid (Phase 7 product policy), hybrid+consistency (Phase 8
class transport/port consistency abstention), hybrid+consistency+per-class thresholds
(per-class minimum confidence selected on NF-IDS2018 validation A for precision >= 0.95).
Reported on NF-IDS2018 validation B, NF-UNSW validation B restricted to shared classes and -
for abstention on protocols the model does not know - NF-UNSW validation B flows whose class is
NOT in the model's label set (the correct output there is to abstain).
Class profiles and the port table come from NF-IDS2018 TRAINING flows only; no retraining.

Adoption rule (fixed before running; docs/phase8/DEVELOPMENT_LOG.md 8D): a variant replaces the
product policy if, against hybrid, (a) IDS val B accepted accuracy drops by <= 0.005 and
coverage by <= 0.02, (b) UNSW shared accepted accuracy does not drop, and (c) the abstention
rate on unknown-class UNSW flows rises by >= 0.05. Among qualifying variants, the simpler wins.

Usage: uv run python scripts/phase8/app_abstention.py models/appintel/<product-artifact>
"""

from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl
import yaml

from netsentinel.appintel.model import (
    AppClassifier,
    build_class_profiles,
    load_classifier,
    resolve_policy,
    save_classifier,
)
from netsentinel.resources import peak_rss_mb
from netsentinel.training.appid import _load, _name

OUT = Path("reports/phase8")


def true_names(df: pl.DataFrame) -> np.ndarray:
    return np.array([_name(int(a)) for a in df["app"].to_list()], dtype=object)


def raw_predict(clf: AppClassifier, df: pl.DataFrame) -> dict:
    raw = copy.copy(clf)
    raw.port_table, raw.class_profiles = {}, {}
    p = raw.predict(df)
    return {"ml": np.array(p["app_ml_class"].to_list(), dtype=object),
            "top": np.array(p["app_top_class"].to_list(), dtype=object),
            "conf": p["app_confidence"].to_numpy(),
            "st": np.array(p["app_status"].to_list(), dtype=object),
            "proto": df["protocol"].cast(pl.Int64).to_numpy(),
            "port": df["dst_port"].cast(pl.Int64).to_numpy()}  # fmt: skip


def decide(r: dict, variant: str, clf: AppClassifier, profiles: dict, pc_thr: dict) -> np.ndarray:
    if variant == "ml_only":
        return r["ml"]
    if variant == "port_only":
        return np.array([(clf.port_table.get(int(a) * 65536 + int(b)) or {}).get("label")
                         for a, b in zip(r["proto"], r["port"], strict=True)], dtype=object)  # fmt: skip
    prof = profiles if variant != "hybrid" else None
    lab, method, _, _ = resolve_policy(r["ml"], r["top"], r["conf"], r["st"], r["proto"],
                                       r["port"], clf.port_table, clf.policy, prof)  # fmt: skip
    lab = np.array(lab, dtype=object)
    if variant.endswith("+pcthr"):
        ml_used = np.array([m == "ml" for m in method])
        low = np.array([c is not None and r["conf"][i] < pc_thr.get(c, 0.0)
                        for i, c in enumerate(lab)])  # fmt: skip
        lab = np.where(ml_used & low, None, lab)
    return lab


def score(lab: np.ndarray, y: np.ndarray, mask: np.ndarray | None = None) -> dict:
    m = np.ones(len(y), bool) if mask is None else mask
    lab, y = lab[m], y[m]
    cov = np.array([x is not None for x in lab])
    ok = np.array([a == b for a, b in zip(lab, y, strict=True)])
    per = {}
    for c in np.unique(y):
        cm = y == c
        per[str(c)] = {"n": int(cm.sum()), "coverage": float(cov[cm].mean()),
                       "accepted_accuracy": float(ok[cm & cov].mean()) if (cm & cov).any()
                       else None}  # fmt: skip
    return {"rows": int(m.sum()), "coverage": float(cov.mean()),
            "accepted_accuracy": float(ok[cov].mean()) if cov.any() else None,
            "per_class": per}  # fmt: skip


def per_class_thresholds(r: dict, y: np.ndarray, classes, target: float = 0.95) -> dict:
    """Smallest confidence t_c with precision(ml == c, conf >= t_c) >= target on val A."""
    out = {}
    for c in classes:
        m = r["ml"] == c
        if m.sum() < 50:
            continue
        conf, ok = r["conf"][m], (y[m] == c)
        order = np.argsort(-conf)
        prec = np.cumsum(ok[order]) / np.arange(1, m.sum() + 1)
        good = np.where(prec >= target)[0]
        # lowest threshold whose cumulative precision still meets the target
        out[str(c)] = float(conf[order][good.max()]) if len(good) else 1.01
    return out


def main() -> None:
    t0 = time.perf_counter()
    clf, _ = load_classifier(sys.argv[1])
    cfg = yaml.safe_load(open("configs/experiments/appid_nf.yaml", encoding="utf-8"))
    ids = _load(cfg, cfg["datasets"]["nf_cicids2018"], 42, int(cfg.get("max_rows", 400_000)))
    classes = list(clf.classes)

    def lab(df):
        n = true_names(df)
        return np.where(np.isin(n, classes), n, "other")

    tr = ids["train"]
    profiles = build_class_profiles(tr["protocol"].cast(pl.Int64).to_numpy(),
                                    tr["dst_port"].cast(pl.Int64).to_numpy(), lab(tr),
                                    tr["sample_weight"].to_numpy())  # fmt: skip
    del ids["train"], tr
    ra = raw_predict(clf, ids["val_a"])
    pc_thr = per_class_thresholds(ra, lab(ids["val_a"]), classes)
    rb, yb = raw_predict(clf, ids["val_b"]), lab(ids["val_b"])
    del ids
    unsw = _load(cfg, cfg["datasets"]["nf_unsw_nb15"], 42, int(cfg.get("max_rows", 400_000)))
    yu = true_names(unsw["val_b"])
    known = [c for c in classes if c != "other"]
    shared, unknown = np.isin(yu, known), ~np.isin(yu, classes)
    ru = raw_predict(clf, unsw["val_b"])
    del unsw
    variants = ("port_only", "ml_only", "hybrid", "hybrid+consistency",
                "hybrid+consistency+pcthr")  # fmt: skip
    res: dict = {"product_artifact": Path(sys.argv[1]).name, "policy": clf.policy,
                 "per_class_thresholds": pc_thr, "variants": {}}  # fmt: skip
    for v in variants:
        lb, lu = decide(rb, v, clf, profiles, pc_thr), decide(ru, v, clf, profiles, pc_thr)
        abst = np.array([x is None for x in lu])[unknown]
        res["variants"][v] = {"ids_val_b": score(lb, yb),
                              "unsw_val_b_shared": score(lu, yu, shared),
                              "unsw_unknown_abstention": float(abst.mean()) if len(abst) else None,
                              "unsw_unknown_rows": int(unknown.sum()),
                              "unsw_unknown_classes": sorted({str(c) for c in yu[unknown]})[:20]}  # fmt: skip
        r = res["variants"][v]
        print(f"{v:26s} ids cov={r['ids_val_b']['coverage']:.3f} "
              f"acc={r['ids_val_b']['accepted_accuracy'] or 0:.4f} | unsw cov="
              f"{r['unsw_val_b_shared']['coverage']:.3f} "
              f"acc={r['unsw_val_b_shared']['accepted_accuracy'] or 0:.4f} | unknown abstain="
              f"{r['unsw_unknown_abstention'] or 0:.3f}", flush=True)  # fmt: skip
    h = res["variants"]["hybrid"]
    qual = []
    for v in ("hybrid+consistency", "hybrid+consistency+pcthr"):
        r = res["variants"][v]
        a = (h["ids_val_b"]["accepted_accuracy"] - r["ids_val_b"]["accepted_accuracy"] <= 0.005
             and h["ids_val_b"]["coverage"] - r["ids_val_b"]["coverage"] <= 0.02)  # fmt: skip
        b = (r["unsw_val_b_shared"]["accepted_accuracy"]
             >= h["unsw_val_b_shared"]["accepted_accuracy"])  # fmt: skip
        c = (r["unsw_unknown_abstention"] or 0) - (h["unsw_unknown_abstention"] or 0) >= 0.05
        res["variants"][v]["adoption_checks"] = {"a": a, "b": b, "c": c}
        if a and b and c:
            qual.append(v)
    res["adopted"] = qual[0] if qual else "hybrid"
    if res["adopted"] != "hybrid":
        new = copy.copy(clf)
        new.class_profiles = profiles
        new.metadata = {**clf.metadata, "role": "product (Phase 8 consistency abstention)",
                        "class_profiles_source": "NF-CICIDS2018 episode-train flows",
                        "base_artifact": Path(sys.argv[1]).name,
                        "selection": "scripts/phase8/app_abstention.py"}  # fmt: skip
        if res["adopted"].endswith("+pcthr"):
            new.policy = {**clf.policy, "per_class_min_confidence": pc_thr}
        res["artifact"] = Path(save_classifier(new, Path(sys.argv[1]).parent)).name
    res["meta"] = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "app_abstention.json").write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({k: res.get(k) for k in ("adopted", "artifact", "meta")}, indent=1))


if __name__ == "__main__":
    main()
