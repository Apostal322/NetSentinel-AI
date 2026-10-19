"""Missions 2-3: adapting a source-network detector to a target network with little or no
labelled target data, and normal-behaviour (anomaly) models trained on target traffic.

Terminology (kept distinct in all outputs):
* source-only            - no target data at all (domain *generalisation* setting).
* adaptation (label-free) - uses an UNLABELLED or benign-only target *calibration* sample:
    target threshold calibration, per-domain robust normalisation, shift-robust feature subset.
* target normal modelling - one-class detectors fit on the target calibration sample only.
* supervised retraining   - uses target attack labels (reported elsewhere: in-domain runs).

Protocol (no target attack label influences fitting, normalisation or thresholds):
* Target split is CHRONOLOGICAL per day (calibration pool = first 60 % of time, evaluation =
  next 20 %, last 20 % = protected test), purge 150 s. Calibration data precedes evaluation.
* Calibration samples of size n are drawn (seeded, proportional to the inverse-probability
  sample weights, i.e. at the full capture's class mix) from the pool:
    - `clean`: benign rows only (assumes an attack-free capture is available - an assumption,
      implemented by using labels to select benign rows; stated in every result);
    - `unlabelled`: all rows, attacks included at their natural prevalence (realistic).
* Thresholds from calibration scores: the (1 - 1e-3) quantile of calibration scores (for the
  unlabelled variant this treats contamination as benign, as a deployment would).
* Evaluation on the target evaluation split: PR-AUC, ROC-AUC, recall and benign FPR at the
  threshold, false-alert flows per hour (prevalence-weighted, observed hours).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from netsentinel.evaluation.metrics import binary_metrics, threshold_at_fpr
from netsentinel.ledger import Run
from netsentinel.models.baselines import FiniteSignedLog, fit_weighted, make_model
from netsentinel.seed import set_seed
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------- transforms
class RobustScaler:
    """signed-log, then (x - median) / IQR with statistics from one domain's benign data."""

    def fit(self, X: np.ndarray) -> RobustScaler:  # noqa: N803
        Z = FiniteSignedLog().transform(X)  # noqa: N806
        self.med = np.nan_to_num(np.nanmedian(Z, axis=0))
        q75, q25 = np.nanpercentile(Z, 75, axis=0), np.nanpercentile(Z, 25, axis=0)
        self.iqr = np.maximum(np.nan_to_num(q75 - q25), 0.1)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:  # noqa: N803
        Z = FiniteSignedLog().transform(X)  # noqa: N806
        return np.nan_to_num((Z - self.med) / self.iqr, nan=0.0).astype(np.float32)


def ks_stat(a: np.ndarray, b: np.ndarray) -> float:
    a, b = a[np.isfinite(a)], b[np.isfinite(b)]
    if not len(a) or not len(b):
        return 1.0
    a, b = np.sort(a), np.sort(b)
    grid = np.unique(np.r_[a, b])
    return float(np.max(np.abs(np.searchsorted(a, grid, "right") / len(a)
                              - np.searchsorted(b, grid, "right") / len(b))))  # fmt: skip


# ----------------------------------------------------------------------------- detectors
def _autoencoder_scores(fit_x: np.ndarray, score_xs: list[np.ndarray], seed: int,
                        epochs: int = 15) -> list[np.ndarray]:  # fmt: skip
    """Small MLP autoencoder on robust-scaled inputs; score = per-row mean squared error."""
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
            loss = ((net(b) - b) ** 2).mean()
            loss.backward()
            opt.step()
    net.eval()
    out = []
    with torch.no_grad():
        for xs in score_xs:
            t = torch.from_numpy(np.clip(xs, -20, 20))
            out.append(((net(t) - t) ** 2).mean(dim=1).numpy())
    return out


def one_class_scores(kind: str, fit_x: np.ndarray, score_xs: list[np.ndarray],
                     seed: int) -> list[np.ndarray]:  # fmt: skip
    """fit_x / score_xs are already robust-scaled with the TARGET calibration statistics."""
    if kind == "robust_z":
        return [np.abs(x).max(axis=1) for x in score_xs]  # scaled input: |z| per feature
    if kind == "iforest":
        from sklearn.ensemble import IsolationForest

        m = IsolationForest(n_estimators=200, max_samples=min(512, len(fit_x)),
                            random_state=seed, n_jobs=2).fit(fit_x)  # fmt: skip
        return [-m.score_samples(x) for x in score_xs]
    if kind == "autoencoder":
        return _autoencoder_scores(fit_x, score_xs, seed)
    raise ValueError(kind)


# ----------------------------------------------------------------------------- evaluation
def _boot_ci(y, w, alert, groups, n_boot: int = 200, seed: int = 0) -> dict:
    """95% percentile CIs of weighted recall and FPR, resampling whole 15-min blocks."""
    uniq, inv = np.unique(groups, return_inverse=True)
    G = len(uniq)  # noqa: N806
    tp = np.bincount(inv, weights=w * (alert & (y == 1)), minlength=G)
    pos = np.bincount(inv, weights=w * (y == 1), minlength=G)
    fp = np.bincount(inv, weights=w * (alert & (y == 0)), minlength=G)
    neg = np.bincount(inv, weights=w * (y == 0), minlength=G)
    cnt = np.random.default_rng(seed).multinomial(G, np.full(G, 1 / G), size=n_boot)
    with np.errstate(invalid="ignore", divide="ignore"):
        rec, fpr = (cnt @ tp) / (cnt @ pos), (cnt @ fp) / (cnt @ neg)
    q = lambda a: [float(np.nanpercentile(a, 2.5)), float(np.nanpercentile(a, 97.5))]  # noqa: E731
    return {"recall_ci95": q(rec), "fpr_ci95": q(fpr), "blocks": G}


def _evaluate(y: np.ndarray, w: np.ndarray, score: np.ndarray, thr: float, hours: float,
              groups: np.ndarray | None = None) -> dict:  # fmt: skip
    m = binary_metrics(y, score, thr, w, is_probability=False, fpr_targets=(1e-3, 1e-2))
    fa = float((w * ((score > thr) & (y == 0))).sum())
    m["false_alert_flows_per_hour"] = fa / hours if hours else float("nan")
    keys = ("pr_auc", "roc_auc", "recall", "fpr", "recall_at_fpr_0.001", "recall_at_fpr_0.01",
            "false_alert_flows_per_hour")  # fmt: skip
    out = {k: m[k] for k in keys if k in m}
    if groups is not None:
        out.update(_boot_ci(y, w, score > thr, groups))
    return out


def _cal_threshold(cal_scores: np.ndarray, fpr: float) -> float:
    return threshold_at_fpr(np.zeros(len(cal_scores), dtype=int), cal_scores, fpr)


def run_adapt(cfg: dict[str, Any]) -> list[str]:
    seed = cfg["seed"]
    set_seed(seed)
    fpr = cfg.get("target_fpr", 1e-3)
    sizes = cfg.get("calibration_sizes", [100, 1000, 10000, 50000])
    detectors = cfg.get("detectors", ["robust_z", "iforest", "autoencoder"])
    t0 = time.perf_counter()

    src = prepare({**cfg, "data": cfg["source"], "split": cfg["source_split"], "task": "binary"})
    feats = src.features
    ctx_idx = [i for i, f in enumerate(feats) if f.startswith("ctx_")]
    flow_idx = [i for i, f in enumerate(feats) if not f.startswith("ctx_")]
    views = {"flow": flow_idx, "ctx": ctx_idx, "all": list(range(len(feats)))}
    if cfg.get("noshortcut_view"):
        from netsentinel.features.nf_schema import NF_SHORTCUT_SUSPECTS

        views["flow_noshortcut"] = [i for i in flow_idx if feats[i] not in NF_SHORTCUT_SUSPECTS]
    final = cfg.get("evaluation", "validation") == "final_test"
    if final:
        marker = Path(cfg.get("final_dir", "reports/final")) / f"{cfg['experiment']}.json"
        if marker.exists():
            raise RuntimeError(f"{marker} exists: this final evaluation was already run")
    s_tr, s_va = src.part("train"), src.part("val")
    if cfg.get("max_train_rows") and s_tr.height > cfg["max_train_rows"]:
        s_tr = s_tr.sample(n=cfg["max_train_rows"], seed=seed)

    def xy(df):
        X = df.select(feats).to_numpy().astype(np.float32)  # noqa: N806
        y = (df["label"] != "benign").to_numpy().astype(int)
        return X, y, df["sample_weight"].to_numpy()

    Xs, ys, _ = xy(s_tr)  # noqa: N806
    Xsv, ysv, wsv = xy(s_va)  # noqa: N806
    src_scaler = RobustScaler().fit(Xs[ys == 0])
    raw_model = fit_weighted(make_model("lightgbm", cfg.get("model_params"), seed), Xs, ys)
    norm_model = fit_weighted(make_model("lightgbm", cfg.get("model_params"), seed),
                              src_scaler.transform(Xs), ys)  # fmt: skip
    src_thr_raw = threshold_at_fpr(ysv, raw_model.predict_proba(Xsv)[:, 1], fpr, wsv)
    src_thr_norm = threshold_at_fpr(ysv, norm_model.predict_proba(src_scaler.transform(Xsv))[:, 1],
                                    fpr, wsv)  # fmt: skip
    del src, s_va, Xsv

    tgt = prepare({**cfg, "data": cfg["target"], "split": cfg["target_split"], "task": "binary"})
    pool = tgt.part("train")
    if final:
        # Final test rows: chronological test AND test under the episode protocol used by every
        # other NF experiment (pre-registration, docs/experiments/final_preregistration_nf.md).
        epi = prepare({**cfg, "data": cfg["target"], "split": cfg["final_episode_split"],
                       "feature_set": "nf_portable", "task": "binary"})  # fmt: skip
        keep = epi.frame.filter(pl.col("split") == "test").select("day", "row_id")
        ev = tgt.part("test").join(keep, on=["day", "row_id"], how="semi")
        del epi, keep
    else:
        ev = tgt.part("val")
    Xe, ye, we = xy(ev)  # noqa: N806
    groups = (ev["day"] + "_" + (ev["event_sec"] // 900).cast(pl.Utf8)).to_numpy()
    blocks = len(np.unique(groups))
    hours = blocks * 0.25
    g = groups if final else None
    raw_eval = raw_model.predict_proba(Xe)[:, 1]
    results: dict[str, Any] = {
        "evaluation": "final_test" if final else "validation",
        "source_only": _evaluate(ye, we, raw_eval, src_thr_raw, hours, g),
        "eval_rows": int(len(ye)), "eval_attack_rows": int(ye.sum()), "eval_hours": hours,
        "calibration": {},
    }  # fmt: skip
    rng = np.random.default_rng(seed)
    pools = {"clean": pool.filter(pl.col("label") == "benign"), "unlabelled": pool}
    for variant, p in pools.items():
        Xp, yp, wp = xy(p)  # noqa: N806
        # Draw proportionally to the inverse-probability weights so the calibration sample
        # reflects the FULL capture (true attack prevalence), not the stratified sample.
        prob = wp / wp.sum()
        for n in sizes:
            if n > len(Xp):
                continue
            idx = rng.choice(len(Xp), size=n, replace=False, p=prob)
            Xc = Xp[idx]  # noqa: N806
            contamination = float(yp[idx].mean())
            half = n // 2  # detectors: fit on one half, threshold on the other (no reuse)
            r: dict[str, Any] = {"contamination": contamination}
            # 1) target threshold calibration of the unchanged source model
            r["source_model_target_threshold"] = _evaluate(
                ye, we, raw_eval, _cal_threshold(raw_model.predict_proba(Xc)[:, 1], fpr), hours, g
            )
            # 2) per-domain robust normalisation (target statistics from calibration only)
            tgt_scaler = RobustScaler().fit(Xc)
            ne = norm_model.predict_proba(tgt_scaler.transform(Xe))[:, 1]
            nc = norm_model.predict_proba(tgt_scaler.transform(Xc))[:, 1]
            r["normalized_source_threshold"] = _evaluate(ye, we, ne, src_thr_norm, hours, g)
            r["normalized_target_threshold"] = _evaluate(ye, we, ne, _cal_threshold(nc, fpr),
                                                         hours, g)  # fmt: skip
            # 3) shift-robust feature subset: features whose benign-source vs calibration KS < 0.3
            Zs, Zc = src_scaler.transform(Xs[ys == 0][:20000]), tgt_scaler.transform(Xc)  # noqa: N806
            keep = [i for i in range(len(feats)) if ks_stat(Zs[:, i], Zc[:, i]) < 0.3]
            r["robust_subset_size"] = len(keep)
            if len(keep) >= 3:
                sub = fit_weighted(make_model("lightgbm", cfg.get("model_params"), seed),
                                   src_scaler.transform(Xs)[:, keep], ys)  # fmt: skip
                se = sub.predict_proba(tgt_scaler.transform(Xe)[:, keep])[:, 1]
                sc = sub.predict_proba(Zc[:, keep])[:, 1]
                r["robust_subset_target_threshold"] = _evaluate(
                    ye, we, se, _cal_threshold(sc, fpr), hours, g
                )
            # 4) target normal modelling: one-class detectors fit on one half of the
            #    calibration sample (scaling statistics from that half only), thresholds from
            #    the other half; feature views: flow-only, context-only (multi-scale windows),
            #    and both.
            if n >= 200:
                det_scaler = RobustScaler().fit(Xc[:half])
                fit_all, thr_all = det_scaler.transform(Xc[:half]), det_scaler.transform(Xc[half:])
                ev_all = det_scaler.transform(Xe)
                for view, cols in views.items():
                    if not cols:
                        continue
                    for kind in detectors:
                        s_thr, s_ev = one_class_scores(
                            kind, fit_all[:, cols], [thr_all[:, cols], ev_all[:, cols]], seed
                        )
                        r[f"target_{kind}_{view}"] = _evaluate(
                            ye, we, s_ev, _cal_threshold(s_thr, fpr), hours, g
                        )
            results["calibration"][f"{variant}_{n}"] = r
            log.info("%s n=%d done (%.0fs)", variant, n, time.perf_counter() - t0)
    if final:
        results["eval_label_counts"] = {r["label"]: int(r["len"]) for r in
                                        ev.group_by("label").len().to_dicts()}  # fmt: skip
    run = Run(cfg, name=cfg["experiment"])
    run.save_json("adapt_results.json", results)
    if final:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({"run": run.id, **results}, indent=1, default=str), "utf-8")
    flat: dict[str, float] = {}

    def put(prefix: str, m: dict) -> None:
        for k, v in m.items():
            if isinstance(v, list):  # bootstrap CI
                flat[f"{prefix}/{k}_lo"], flat[f"{prefix}/{k}_hi"] = v
            else:
                flat[f"{prefix}/{k}"] = v

    put("source_only", results["source_only"])
    for key, r in results["calibration"].items():
        for meth, m in r.items():
            if isinstance(m, dict):
                put(f"{key}/{meth}", m)
    run.log_metrics(flat)
    run.log_metrics({"seconds": time.perf_counter() - t0}, prefix="cost/")
    run.finish(notes=f"adapt {cfg['source']['processed_dir']} -> {cfg['target']['processed_dir']} "
                     f"{cfg['feature_set']}")  # fmt: skip
    return [run.id]
