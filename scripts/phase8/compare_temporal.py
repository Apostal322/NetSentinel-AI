"""Phase 8B development comparison of temporal scorers (EXPLORATORY; development data only).

Data
* iot23: the 9 IoT-23 scenarios already inspected in Phase 6/7 (data/raw/iot23). Per scenario:
  calibration = flows ending in the first 50% of the time span, evaluation = the rest.
* unsw:  NF-UNSW-NB15-v3 development part (first 78% of each day; the consumed final test is
  the last 20% of each day). Calibration = before the 50% time quantile, evaluation = after.
Calibration variants: clean (benign-labelled calibration flows only, oracle-vetted) and
unlabelled (all calibration flows, natural contamination).

Protocol (identical for every scorer)
* entity-window features at `level` (device, service), window 30 s, optional causal 300 s
  context (multi-scale, `ms` configs);
* fit on calibration windows before 70% of the calibration span, split-conformal threshold at
  target FPR 1% from the remaining calibration windows (scored WITH their causal history);
* evaluation windows scored with the full calibration history before them.
Metrics: PR-AUC (average precision), ROC-AUC, recall/FPR/false alerts per hour at the
conformal threshold, recall at 1% FPR (oracle threshold: ranking quality only), median detection
delay, fit seconds, scoring microseconds per window, parameters.

Selection rule (fixed BEFORE running, docs/phase8/DEVELOPMENT_LOG.md 8B): see `select()`.

Usage: uv run --extra torch python scripts/phase8/compare_temporal.py iot23|unsw [--quick]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.behavior.profile import conformal_threshold
from netsentinel.behavior.temporal import SCORERS, multiscale_windows
from netsentinel.behavior.windows import WINDOW_FEATURES, _key_expr, prepare_flows
from netsentinel.resources import peak_rss_mb

OUT = Path("reports/phase8")
TARGET = 0.01
WINDOW = 30
COARSE = (300,)
LEVELS = ("device", "service")
MS_NAMES = [*WINDOW_FEATURES, *[f"{f}_c300" for f in WINDOW_FEATURES]]


def configs(quick: bool) -> list[tuple[str, str, dict]]:
    nn = {"epochs": 3 if quick else 15, "hidden": 32, "seq_len": 8}
    out = []
    for feats in ("base", "ms"):
        out += [(n, feats, {}) for n in ("robust_z", "guarded_ewma", "lag_iforest")]
        out += [(n, feats, nn) for n in ("gru", "tcn")]
    return out


def truth(flows: pl.DataFrame, level: str) -> pl.DataFrame:
    start = pl.col("end_ms") - pl.col("dur_ms")
    return (flows.with_columns((pl.col("end_ms") // (WINDOW * 1000)).alias("win"), _key_expr(level))
            .group_by("key", "win")
            .agg((pl.col("is_attack").max() > 0).alias("y"),
                 start.filter(pl.col("is_attack") > 0).min().alias("first_attack_ms")))  # fmt: skip


def ap_score(s: np.ndarray, y: np.ndarray) -> tuple[float | None, float | None]:
    from sklearn.metrics import average_precision_score, roc_auc_score

    if y.sum() == 0 or y.sum() == len(y):
        return None, None
    return float(average_precision_score(y, s)), float(roc_auc_score(y, s))


def metrics(s, thr, ev, tr, hours) -> dict:
    d = ev.select("key", "win", "window_end_ms").with_columns(pl.Series("score", s))
    d = d.join(tr, on=["key", "win"], how="left").with_columns(pl.col("y").fill_null(False))
    y = d["y"].to_numpy().astype(int)
    a = s > thr
    ap, roc = ap_score(s, y)
    out = {"windows": len(y), "attack_windows": int(y.sum()), "pr_auc": ap, "roc_auc": roc,
           "recall": float(a[y == 1].mean()) if y.sum() else None,
           "fpr": float(a[y == 0].mean()) if (y == 0).sum() else None,
           "fa_per_h": float((a & (y == 0)).sum()) / hours if hours else None,
           "base_rate": float(y.mean()) if len(y) else None}  # fmt: skip
    if y.sum() and (y == 0).sum():
        t1 = np.quantile(s[y == 0], 0.99)
        out["recall_at_fpr1_oracle"] = float((s[y == 1] > t1).mean())
    det = a & (y == 1)
    if det.any():
        delay = (d["window_end_ms"].to_numpy()[det] - d["first_attack_ms"].to_numpy()[det]) / 1000
        out["median_delay_s"] = float(np.median(delay))
    return out


def compare_level(cal: pl.DataFrame, ev: pl.DataFrame, level: str, cfgs, hours) -> dict:
    """cal/ev: prepare_flows output with is_attack."""
    cal_w = multiscale_windows(cal, level, WINDOW, COARSE)
    if cal_w.height < 60:
        return {"status": f"too few calibration windows ({cal_w.height})"}
    lo, hi = int(cal_w["win"].min()), int(cal_w["win"].max())
    cut = lo + int(math.floor((hi - lo + 1) * 0.7))
    fit_w = cal_w.filter(pl.col("win") < cut)
    known = set(cal["dst"].unique().to_list())
    ev_w = multiscale_windows(ev, level, WINDOW, COARSE, known_dst=known)
    tr = truth(ev, level)
    hold_mask = (cal_w["win"] >= cut).to_numpy()
    both = pl.concat([cal_w, ev_w], how="diagonal_relaxed")
    ev_mask = np.r_[np.zeros(cal_w.height, bool), np.ones(ev_w.height, bool)]
    res: dict = {"cal_windows": cal_w.height, "fit_windows": fit_w.height,
                 "hold_windows": int(hold_mask.sum()), "eval_windows": ev_w.height}  # fmt: skip
    if fit_w.height < 30 or hold_mask.sum() < 10 or not ev_w.height:
        res["status"] = "too few windows"
        return res
    for name, feats, kw in cfgs:
        s = SCORERS[name](**kw)
        s.names = list(WINDOW_FEATURES) if feats == "base" else MS_NAMES
        t0 = time.perf_counter()
        s.fit(fit_w)
        fit_s = time.perf_counter() - t0
        thr, reliable = conformal_threshold(s.score(cal_w)[hold_mask], TARGET)
        t0 = time.perf_counter()
        sc = s.score(both)[ev_mask]
        us = (time.perf_counter() - t0) / both.height * 1e6
        m = metrics(sc, thr, ev_w, tr, hours)
        m.update(fit_seconds=round(fit_s, 3), score_us_per_window=round(us, 2),
                 threshold_reliable=reliable)  # fmt: skip
        if hasattr(s, "n_parameters"):
            m["parameters"] = s.n_parameters()
        res[f"{name}/{feats}"] = m
    return res


def run_pair(cal_raw: pl.DataFrame, ev_raw: pl.DataFrame, cfgs) -> dict:
    hours = (int(ev_raw["flow_end_milliseconds"].max())
             - int(ev_raw["flow_end_milliseconds"].min())) / 3.6e6  # fmt: skip
    ev = prepare_flows(ev_raw)
    out: dict = {"eval_hours": hours, "cal_attack_share": float(cal_raw["is_attack"].mean())}
    for variant, data in (("clean", cal_raw.filter(pl.col("is_attack") == 0)),
                          ("unlabelled", cal_raw)):  # fmt: skip
        if not data.height:
            out[variant] = {"status": "no calibration flows"}
            continue
        cal = prepare_flows(data)
        out[variant] = {lv: compare_level(cal, ev, lv, cfgs, hours) for lv in LEVELS}
    return out


def iot23(cfgs) -> dict:
    from netsentinel.streaming.offline import load_capture

    def is_attack(d: dict) -> float:
        return 1.0 if str(d.get("label", "")).lower().startswith("malicious") else 0.0

    res = {}
    for f in sorted(Path("data/raw/iot23").glob("*/conn.log.labeled")):
        frame, _, _ = load_capture(f, "zeek", zeek_extras={"IS_ATTACK": is_attack})
        if frame is None:
            continue
        end = frame["flow_end_milliseconds"]
        mid = int(end.min() + (end.max() - end.min()) // 2)
        res[f.parent.name] = run_pair(frame.filter(pl.col("flow_end_milliseconds") < mid),
                                      frame.filter(pl.col("flow_end_milliseconds") >= mid),
                                      cfgs)  # fmt: skip
        print(f.parent.name, brief(res[f.parent.name]), flush=True)
    return res


def unsw(cfgs) -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase6"))
    from eval_nf_dev import read_day  # noqa: PLC0415  (Phase 6 development-share loader)

    files = sorted(Path("data/interim/nf_unsw_nb15_v3").glob("[0-9]*.parquet"))
    days = [read_day(f, []) for f in files]
    allf = pl.concat(days, how="diagonal_relaxed")
    cal_end = int(allf["flow_end_milliseconds"].quantile(0.5))
    del days
    cal = allf.filter(pl.col("flow_end_milliseconds") < cal_end)
    ev = allf.filter(pl.col("flow_end_milliseconds") >= cal_end)
    del allf
    r = run_pair(cal, ev, cfgs)
    print("unsw", brief(r), flush=True)
    return {"NF-UNSW-NB15-v3-dev": r}


def brief(r: dict) -> dict:
    out = {}
    for lv in LEVELS:
        d = r.get("clean", {}).get(lv, {}) if isinstance(r.get("clean"), dict) else {}
        out[lv] = {k: (None if v.get("pr_auc") is None else round(v["pr_auc"], 3),
                       None if v.get("fpr") is None else round(v["fpr"], 4))
                   for k, v in d.items() if isinstance(v, dict)}  # fmt: skip
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=("iot23", "unsw"))
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    t0 = time.perf_counter()
    cfgs = configs(a.quick)
    res = iot23(cfgs) if a.dataset == "iot23" else unsw(cfgs)
    meta = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb(),
            "window_s": WINDOW, "coarse_s": COARSE, "target_fpr": TARGET, "quick": a.quick}  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    name = f"temporal_{a.dataset}{'_quick' if a.quick else ''}.json"
    (OUT / name).write_text(json.dumps({"results": res, "meta": meta}, indent=1, default=str),
                            "utf-8")  # fmt: skip
    print(meta)


if __name__ == "__main__":
    main()
