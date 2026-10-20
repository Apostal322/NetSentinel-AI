"""Phase 7 P3: select the conservative application-ID policy on DEVELOPMENT data, then build a
policy-equipped classifier artifact (schema appintel-1.1.0) around the existing product model.

Pre-stated selection rule: on NF-IDS2018 validation A, among candidate policies with coverage
>= 0.95, maximise accepted accuracy (ties: higher coverage). Reported afterwards: NF-IDS2018
validation B, NF-UNSW validation B (classes shared with the IDS label set), and - descriptively,
already inspected in Phase 6 - the CTU Zeek logs with Zeek `service` as reference.
The port table comes from NF-IDS2018 TRAINING flows only. No model is retrained.

Usage: uv run python scripts/phase7/select_app_policy.py models/appintel/<product-artifact>
"""

from __future__ import annotations

import copy
import itertools
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl
import yaml

from netsentinel.appintel.model import (
    AppClassifier,
    build_port_table,
    load_classifier,
    resolve_policy,
    save_classifier,
)
from netsentinel.resources import peak_rss_mb
from netsentinel.training.appid import _load, _name

POLICIES = [{"min_purity": p, "min_support": n, "conflict": c}
            for p, n, c in itertools.product((0.90, 0.95, 0.99), (50, 200), ("port", "unknown"))]  # fmt: skip


def labels_for(df: pl.DataFrame, classes: list[str]) -> np.ndarray:
    names = np.array([_name(int(a)) for a in df["app"].to_list()], dtype=object)
    return np.where(np.isin(names, classes), names, "other")


def evaluate(clf: AppClassifier, df: pl.DataFrame, y: np.ndarray, table: dict, policy: dict | None,
             mask: np.ndarray | None = None) -> dict:  # fmt: skip
    raw = copy.copy(clf)
    raw.port_table = {}  # policy-free ML output; the policy is applied explicitly below
    p = raw.predict(df)
    proto = df["protocol"].cast(pl.Int64).to_numpy()
    port = df["dst_port"].cast(pl.Int64).to_numpy()
    ml = np.array(p["app_ml_class"].to_list(), dtype=object)
    top = np.array(p["app_top_class"].to_list(), dtype=object)
    conf = p["app_confidence"].to_numpy()
    st = np.array(p["app_status"].to_list(), dtype=object)  # model's own (policy-free) status
    if policy is None:  # ML only
        lab = ml
    elif policy == "port_only":
        lab = np.array([(table.get(int(a) * 65536 + int(b)) or {}).get("label")
                        for a, b in zip(proto, port, strict=True)], dtype=object)  # fmt: skip
    else:
        lab = np.array(resolve_policy(ml, top, conf, st, proto, port, table, policy)[0],
                       dtype=object)  # fmt: skip
    m = np.ones(len(y), bool) if mask is None else mask
    lab, yy = lab[m], y[m]
    cov = np.array([x is not None for x in lab])
    ok = np.array([a == b for a, b in zip(lab, yy, strict=True)])
    return {"coverage": float(cov.mean()), "accepted_accuracy": float(ok[cov].mean())
            if cov.any() else None, "accuracy_abstain_wrong": float(ok.mean()), "rows": int(m.sum())}  # fmt: skip


def main() -> None:
    t0 = time.perf_counter()
    base, _ = load_classifier(sys.argv[1])
    clf = AppClassifier(model=base.model, features=base.features, classes=base.classes,
                        feature_set=base.feature_set,
                        confidence_threshold=base.confidence_threshold, ood_low=base.ood_low,
                        ood_high=base.ood_high, metadata=dict(base.metadata))  # fmt: skip
    cfg = yaml.safe_load(open("configs/experiments/appid_nf.yaml", encoding="utf-8"))
    ids = _load(cfg, cfg["datasets"]["nf_cicids2018"], 42, int(cfg.get("max_rows", 400_000)))
    classes = [c for c in clf.classes]
    y_tr = labels_for(ids["train"], classes)
    table = build_port_table(ids["train"]["protocol"].to_numpy(), ids["train"]["dst_port"].to_numpy(),
                             y_tr, ids["train"]["sample_weight"].to_numpy())  # fmt: skip
    clf.port_table = table
    y_a, y_b = labels_for(ids["val_a"], classes), labels_for(ids["val_b"], classes)
    cand = {
        "ml_only": None,
        "port_only": "port_only",
        **{f"pur{p['min_purity']}_sup{p['min_support']}_{p['conflict']}": p for p in POLICIES},
    }
    res: dict = {"selection_rule": "IDS val A: coverage >= 0.95, max accepted accuracy",
                 "port_table_entries": len(table), "candidates": {}}  # fmt: skip
    for name, pol in cand.items():
        res["candidates"][name] = {"ids_val_a": evaluate(clf, ids["val_a"], y_a, table, pol)}
    ok = {k: v for k, v in res["candidates"].items() if k not in ("ml_only", "port_only")
          and v["ids_val_a"]["coverage"] >= 0.95}  # fmt: skip
    chosen = max(ok, key=lambda k: (ok[k]["ids_val_a"]["accepted_accuracy"],
                                    ok[k]["ids_val_a"]["coverage"]))  # fmt: skip
    res["chosen"] = chosen
    del ids["train"]
    unsw = _load(cfg, cfg["datasets"]["nf_unsw_nb15"], 42, int(cfg.get("max_rows", 400_000)))
    y_u = np.array([_name(int(a)) for a in unsw["val_b"]["app"].to_list()], dtype=object)
    shared = np.isin(y_u, [c for c in classes if c != "other"])
    for name in ("ml_only", "port_only", chosen):
        pol = cand[name]
        res["candidates"][name]["ids_val_b"] = evaluate(clf, ids["val_b"], y_b, table, pol)
        res["candidates"][name]["unsw_val_b_shared"] = evaluate(clf, unsw["val_b"], y_u, table,
                                                                pol, shared)  # fmt: skip
        print(name, json.dumps(res["candidates"][name], default=lambda x: round(x, 4)), flush=True)
    clf.policy = cand[chosen]
    clf.metadata = {**clf.metadata, "role": "product (Phase 7 conservative policy)",
                    "policy_selection": res["selection_rule"], "policy": cand[chosen],
                    "port_table_source": "NF-CICIDS2018 benign episode-train flows",
                    "base_artifact": Path(sys.argv[1]).name}  # fmt: skip
    path = save_classifier(clf, Path(sys.argv[1]).parent)
    res["artifact"] = str(path)
    res["meta"] = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}
    out = Path("reports/phase7/app_policy_selection.json")
    out.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({k: res[k] for k in ("chosen", "artifact", "meta")}, indent=1))


if __name__ == "__main__":
    main()
