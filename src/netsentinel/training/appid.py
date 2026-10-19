"""Mission 4: application/service identification from flow statistics, with abstention.

Target: the nDPI *master* protocol in the NF-v3 `L7_PROTO` field (integer part of the
`master.app` code). It is the dataset authors' DPI output, not ground truth, and the
sub-application part is not used (the CSVs store `L7_PROTO` as a decimal number, so
`7.37` and `7.370` are indistinguishable). Names come from nDPI 4.8 `ndpi_protocol_ids.h`;
the nDPI version behind NF-v3 is not documented, so the names are an assumption (stability of
the IDs across nDPI versions was not verified).

Question: how much of the DPI label is recoverable from flow shape, beyond the destination
port? Encrypted traffic: TLS (91) is one class. We do not claim to identify applications
*inside* TLS/QUIC.

Benign flows only. The standard leakage-checked split (`prepare`, episode protocol as for all
NF in-domain runs) is used: train = its train partition; its validation partition is cut in
time into validation A (earlier half: abstention threshold) and validation B (later half:
reported). Test-partition rows are dropped before anything is fitted.

Models:
- majority;
- port lookup (most frequent class per (protocol, dst_port) in train, else majority);
- LightGBM on flow shape without any port information (`nf_flow` minus `port_class`);
- LightGBM on flow shape + `port_class`.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import numpy as np
import polars as pl

from netsentinel.features.nf_schema import nf_feature_set
from netsentinel.ledger import Run
from netsentinel.models.baselines import fit_weighted, make_model
from netsentinel.seed import set_seed
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)

NDPI_NAMES = {0: "unknown", 1: "ftp_control", 3: "smtp", 4: "imap", 5: "dns", 7: "http",
              9: "ntp", 10: "netbios", 11: "nfs", 36: "edonkey", 37: "bittorrent", 41: "smb2/3",
              77: "telnet", 88: "rdp", 91: "tls", 92: "ssh", 100: "sip", 103: "dhcpv6",
              131: "http_proxy", 154: "llmnr", 175: "ftp_data", 188: "quic"}  # fmt: skip


def _load(cfg: dict, ds: dict, seed: int, max_rows: int) -> dict[str, pl.DataFrame]:
    prep = prepare({**cfg, "data": ds, "feature_set": "nf_flow", "split": cfg["split"],
                    "task": "binary"})  # fmt: skip
    df = prep.frame.filter((pl.col("label") == "benign")
                           & pl.col("split").is_in(["train", "val"]))  # fmt: skip
    app = pl.col("l7_proto").floor().cast(pl.Int32).alias("app")
    l7 = pl.concat([
        pl.scan_parquet(f"{ds['interim_dir']}/{day}.parquet")
        .select(pl.lit(day).alias("day"), "row_id", app)
        .join(df.lazy().filter(pl.col("day") == day).select("day", "row_id"),
              on=["day", "row_id"])
        .collect() for day in df["day"].unique().sort().to_list()])  # fmt: skip
    df = df.join(l7, on=["day", "row_id"], how="inner").sort(["day", "event_sec"])
    rng = np.random.default_rng(seed)
    out = {}
    for part, cap in (("train", max_rows), ("val", max_rows // 2)):
        d = df.filter(pl.col("split") == part)
        if d.height > cap:  # weight-proportional subsample keeps the population estimate
            w = d["sample_weight"].to_numpy().astype(float)
            keep = np.sort(rng.choice(d.height, size=cap, replace=False, p=w / w.sum()))
            d = d[keep].with_columns(pl.lit(1.0, dtype=pl.Float32).alias("sample_weight"))
        out[part] = d
    v = out.pop("val")  # sorted by time; earlier half -> A, later half -> B
    out["val_a"], out["val_b"] = v.head(v.height // 2), v.tail(v.height - v.height // 2)
    return out


def _scores(y, pred, w, classes) -> dict[str, Any]:
    acc = float(np.average(y == pred, weights=w))
    per = {}
    f1s = []
    for c in classes:
        tp = float(w[(y == c) & (pred == c)].sum())
        p_den, r_den = float(w[pred == c].sum()), float(w[y == c].sum())
        prec = tp / p_den if p_den else 0.0
        rec = tp / r_den if r_den else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        if r_den:
            f1s.append(f1)
        per[_name(c)] = {
            "recall": round(rec, 4), "precision": round(prec, 4), "support_w": round(r_den, 1)}
    return {"accuracy": round(acc, 4), "macro_f1": round(float(np.mean(f1s)), 4), "per_class": per}


def _selective(conf_a, ok_a, w_a, conf_b, ok_b, w_b, target: float) -> dict[str, Any]:
    """Lowest confidence threshold whose accepted accuracy on val A reaches `target`."""
    order = np.argsort(-conf_a)
    cum_ok = np.cumsum((ok_a * w_a)[order])
    cum_w = np.cumsum(w_a[order])
    acc = cum_ok / cum_w
    good = np.where(acc >= target)[0]
    if not len(good):
        return {"target_accuracy": target, "threshold": None}
    thr = float(conf_a[order][good[-1]])
    acc_b = conf_b >= thr
    cov = float(w_b[acc_b].sum() / w_b.sum())
    sel_acc = float(np.average(ok_b[acc_b], weights=w_b[acc_b])) if acc_b.any() else None
    return {"target_accuracy": target, "threshold": round(thr, 4), "coverage_b": round(cov, 4),
            "accepted_accuracy_b": None if sel_acc is None else round(sel_acc, 4)}  # fmt: skip


def _name(c: int) -> str:
    return NDPI_NAMES.get(int(c), str(int(c))) if c >= 0 else "other"


def _port_key(d: pl.DataFrame) -> np.ndarray:
    return (d["protocol"].cast(pl.Int64) * 65536 + d["dst_port"].cast(pl.Int64)).to_numpy()


def _port_table(keys: np.ndarray, y: np.ndarray, w: np.ndarray) -> dict[int, int]:
    """Most frequent (weighted) class per (protocol, dst_port) key."""
    agg: dict[tuple[int, int], float] = {}
    for k, c, wt in zip(keys.tolist(), y.tolist(), w.tolist(), strict=True):
        agg[(k, c)] = agg.get((k, c), 0.0) + wt
    best: dict[int, tuple[float, int]] = {}
    for (k, c), s in agg.items():
        if s > best.get(k, (-1.0, 0))[0]:
            best[k] = (s, c)
    return {k: c for k, (_, c) in best.items()}


def run_appid(cfg: dict[str, Any]) -> list[str]:
    t0 = time.perf_counter()
    seed = int(cfg.get("seed", 42))
    set_seed(seed)
    results: dict[str, Any] = {"label": "nDPI master protocol (L7_PROTO integer part)",
                               "names_source": "nDPI 4.8 ndpi_protocol_ids.h (assumed)",
                               "datasets": {}}  # fmt: skip
    flat: dict[str, float] = {}
    shape = [f for f in nf_feature_set("nf_flow") if f != "port_class"]
    for name, ds in cfg["datasets"].items():
        parts = _load(cfg, ds, seed, int(cfg.get("max_rows", 400_000)))
        tr = parts["train"]
        share = tr.group_by("app").agg(pl.col("sample_weight").sum()).sort(
            "sample_weight", descending=True)
        top = share["app"].head(int(cfg.get("top_k", 10))).to_list()
        y = {k: np.where(np.isin(v["app"].to_numpy(), top), v["app"].to_numpy(), -1)
             for k, v in parts.items()}  # -1 = other  # fmt: skip
        w = {k: v["sample_weight"].to_numpy().astype(float) for k, v in parts.items()}
        classes = np.array(sorted(set(y["train"].tolist())))
        tot = w["train"].sum()
        res: dict[str, Any] = {
            "rows": {k: v.height for k, v in parts.items()},
            "classes": [_name(c) for c in classes],
            "train_class_share": {_name(c): round(float(w["train"][y["train"] == c].sum() / tot), 4)
                                  for c in classes},
            "models": {}}  # fmt: skip
        maj = classes[np.argmax([w["train"][y["train"] == c].sum() for c in classes])]
        evals = ("val_a", "val_b")
        preds = {"majority": {k: np.full(len(y[k]), maj) for k in evals}}
        confs: dict[str, dict[str, np.ndarray]] = {}
        table = _port_table(_port_key(tr), y["train"], w["train"])
        preds["port_lookup"] = {
            k: np.array([table.get(x, maj) for x in _port_key(parts[k]).tolist()]) for k in evals}
        unseen = [x not in table for x in _port_key(parts["val_b"]).tolist()]
        res["port_lookup_unseen_share_b"] = round(float(np.mean(unseen)), 4)
        for mname, feats in (("lgbm_shape_noport", shape),
                             ("lgbm_shape_portclass", nf_feature_set("nf_flow"))):  # fmt: skip
            model = make_model("lightgbm", cfg.get("lightgbm_params"), seed=seed)
            fit_weighted(model, tr.select(feats).to_numpy().astype(np.float32), y["train"],
                         w["train"])  # fmt: skip
            preds[mname], confs[mname] = {}, {}
            for k in evals:
                p = model.predict_proba(parts[k].select(feats).to_numpy().astype(np.float32))
                preds[mname][k] = model.classes_[p.argmax(1)]
                confs[mname][k] = p.max(1)
        for mname, pr in preds.items():
            r = _scores(y["val_b"], pr["val_b"], w["val_b"], classes)
            if mname in confs:
                ok = {k: (pr[k] == y[k]).astype(float) for k in evals}
                r["selective"] = [
                    _selective(confs[mname]["val_a"], ok["val_a"], w["val_a"],
                               confs[mname]["val_b"], ok["val_b"], w["val_b"], t)
                    for t in cfg.get("selective_targets", [0.95, 0.99])]  # fmt: skip
            res["models"][mname] = r
            flat[f"{name}/{mname}/accuracy"] = r["accuracy"]
            flat[f"{name}/{mname}/macro_f1"] = r["macro_f1"]
        results["datasets"][name] = res
        log.info("%s done: %s", name, {m: v["macro_f1"] for m, v in res["models"].items()})
    run = Run(cfg, name=cfg.get("experiment", "appid"))
    run.save_json("appid_results.json", results)
    run.log_metrics(flat)
    run.log_metrics({"seconds": time.perf_counter() - t0}, prefix="cost/")
    run.finish(notes="application identification (nDPI master protocol) from flow shape")
    return [run.id]
