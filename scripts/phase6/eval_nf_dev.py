"""Phase 6 exploratory NF experiments (development data only): H2 (service conditioning),
H3 (device context), H4 (Isolation Forest vs robust statistics), H5 (injected contamination).

Data: full (unsampled) interim NF-v3 flows. The consumed final-test rows lie in the last 20%
of EACH DAY's time span (chronological split is per day, data/splits.py), so only flows that
end in the first 78% of their day's span are used (margin for the 150 s purge). Within this
development data: calibration = flows ending before the 50% time quantile, evaluation = the
rest. Global silent windows are dropped (the excluded day ends would otherwise appear as
artificial silence). Processed one day file at a time (bounded memory).

Calibration variants: clean (benign flows only - oracle-vetted), natural (all flows, true
contamination), inj{1,5,10} (benign + a random sample of the period's attack flows so that
about 1/5/10% of calibration FLOWS are attacks).

Usage: uv run python scripts/phase6/eval_nf_dev.py unsw|ids [--window 30]
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

from netsentinel.behavior.calibrate import calibrate_windows
from netsentinel.behavior.profile import BehaviorProfile, conformal_threshold
from netsentinel.behavior.windows import WINDOW_FEATURES, _key_expr, aggregate, prepare_flows
from netsentinel.resources import peak_rss_mb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import auc  # noqa: E402

DS = {"unsw": ("data/interim/nf_unsw_nb15_v3", []),
      "ids": ("data/interim/nf_cicids2018_v3", ["infiltration"])}  # fmt: skip
COLS = ["flow_start_milliseconds", "flow_end_milliseconds", "ipv4_src_addr", "ipv4_dst_addr",
        "dst_port", "protocol", "in_bytes", "out_bytes", "in_pkts", "out_pkts",
        "flow_duration_milliseconds", "client_tcp_flags", "server_tcp_flags", "label"]  # fmt: skip
LEVELS = ("global", "device", "service")
VARIANTS = {"clean": None, "natural": "all", "inj1": 0.01, "inj5": 0.05, "inj10": 0.10}
TARGET = 0.01
DEV_SHARE = 0.78  # of each day's time span; the consumed test starts at 0.80
OUT = Path("reports/phase6")


def read_day(path: Path, drop: list[str]) -> pl.DataFrame:
    df = pl.read_parquet(path, columns=COLS)
    if drop:
        df = df.filter(~pl.col("label").is_in(drop))
    e = df["flow_end_milliseconds"]
    df = df.filter(pl.col("flow_end_milliseconds") < int(e.min() + DEV_SHARE * (e.max() - e.min())))
    return df.with_columns(
        ((pl.col("client_tcp_flags") & 4) > 0).cast(pl.Int8).alias("cli_rst"),
        ((pl.col("server_tcp_flags") & 4) > 0).cast(pl.Int8).alias("srv_rst"),
        (pl.col("label") != "benign").cast(pl.Float64).alias("is_attack"),
    )


def nonsilent(agg: pl.DataFrame) -> pl.DataFrame:
    return agg.filter(pl.col("n_flows") > 0)


def truth(flows: pl.DataFrame, level: str, w: int) -> pl.DataFrame:
    return (flows.with_columns((pl.col("end_ms") // (w * 1000)).alias("win"), _key_expr(level))
            .group_by("key", "win").agg((pl.col("is_attack").max() > 0).alias("y")))  # fmt: skip


def fpr_at_recall(score: np.ndarray, y: np.ndarray, recall: float) -> float | None:
    if not y.sum() or not (y == 0).sum() or recall is None:
        return None
    pos = np.sort(score[y == 1])[::-1]
    k = max(1, math.ceil(recall * len(pos)))
    thr = pos[k - 1]
    return float((score[y == 0] >= thr).mean())


def summarize(scored: pl.DataFrame, tr: pl.DataFrame, hours: float) -> dict:
    d = scored.join(tr, on=["key", "win"], how="left").with_columns(pl.col("y").fill_null(False))
    y = d["y"].to_numpy().astype(int)
    a = d["anomalous"].to_numpy().astype(bool)
    s = d["score"].to_numpy()
    return {"windows": d.height, "attack_windows": int(y.sum()),
            "recall": float(a[y == 1].mean()) if y.sum() else None,
            "fpr": float(a[y == 0].mean()) if (y == 0).sum() else None,
            "fa_per_h": float((a & (y == 0)).sum()) / hours,
            "roc_auc": auc(s, y), "_scores": s, "_y": y}  # fmt: skip


def iforest_level(fit: pl.DataFrame, hold: pl.DataFrame, ev: pl.DataFrame, seed: int = 0):
    from sklearn.ensemble import IsolationForest

    def x(df):
        return np.nan_to_num(df.select(WINDOW_FEATURES).to_numpy().astype(np.float64))

    m = IsolationForest(n_estimators=200, max_samples=min(256, fit.height), random_state=seed,
                        n_jobs=1).fit(x(fit))  # fmt: skip
    thr, _ = conformal_threshold(-m.score_samples(x(hold)), TARGET)
    s = -m.score_samples(x(ev))
    return ev.select("key", "win").with_columns(pl.Series("score", s),
                                                pl.Series("anomalous", s > thr))  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=sorted(DS))
    ap.add_argument("--window", type=int, default=30)
    a = ap.parse_args()
    t0 = time.perf_counter()
    root, drop = DS[a.dataset]
    files = sorted(Path(root).glob("[0-9]*.parquet"))
    ends = pl.concat(
        [
            read_day(f, drop).select(
                "flow_end_milliseconds", (pl.col("is_attack") > 0).alias("att")
            )
            for f in files
        ]
    )
    dev = ends
    dev_end = int(ends["flow_end_milliseconds"].max()) + 1
    cal_end = int(dev["flow_end_milliseconds"].quantile(0.5))
    calp = dev.filter(pl.col("flow_end_milliseconds") < cal_end)
    n_ben, n_att = int((~calp["att"]).sum()), int(calp["att"].sum())
    rates = {v: (c / (1 - c) * n_ben / n_att if isinstance(c, float) and n_att else None)
             for v, c in VARIANTS.items()}  # fmt: skip
    info = {"dataset": a.dataset, "dev_end_ms": dev_end, "cal_end_ms": cal_end,
            "cal_flows_benign": n_ben, "cal_flows_attack": n_att,
            "eval_flows": int(dev.height - calp.height),
            "inj_sampling_rates": rates}  # fmt: skip
    del ends, dev, calp
    print(info, flush=True)
    rng = np.random.default_rng(0)
    w = a.window
    cal_win = {v: {lv: [] for lv in LEVELS} for v in VARIANTS}
    seen = {v: set() for v in VARIANTS}
    for f in files:  # pass 1: calibration windows per variant
        day = read_day(f, drop)
        day = day.filter(pl.col("flow_end_milliseconds") < cal_end)
        if not day.height:
            continue
        flows = prepare_flows(day)
        u = rng.random(flows.height)
        for v, c in VARIANTS.items():
            if c is None:
                sub = flows.filter(pl.col("is_attack") == 0)
            elif c == "all":
                sub = flows
            else:
                sub = flows.filter((pl.col("is_attack") == 0) | pl.Series(u < (rates[v] or 0)))
            for lv in LEVELS:
                cal_win[v][lv].append(nonsilent(aggregate(sub, lv, w, prior_dst=seen[v])))
            seen[v] |= set(sub["dst"].unique().to_list())
    profiles, ifo = {}, {}
    for v in VARIANTS:
        wins = {lv: pl.concat(cal_win[v][lv], how="diagonal_relaxed") for lv in LEVELS}
        g = wins["global"]["win"]
        cut = int(g.min()) + int(math.floor((int(g.max()) - int(g.min()) + 1) * 0.7))
        lv_prof = calibrate_windows(wins, cut, target_fpr=TARGET, min_windows=30,
                                    mode="vetted_benign" if v == "clean" else "unlabelled")  # fmt: skip
        profiles[v] = BehaviorProfile(window_s=w, mode="research", target_fpr=TARGET,
                                      min_windows=30, top_k=2, levels=lv_prof, known_dst=seen[v],
                                      status="baseline_ready", period={}, diagnostics={})  # fmt: skip
        ifo[v] = {lv: (wins[lv].filter(pl.col("win") < cut), wins[lv].filter(pl.col("win") >= cut))
                  for lv in LEVELS}  # fmt: skip
    del cal_win
    ev_win = {v: {lv: [] for lv in LEVELS} for v in VARIANTS}
    ev_truth = {lv: [] for lv in LEVELS}
    ev_hours = 0.0
    for f in files:  # pass 2: evaluation windows (frozen destination set per variant)
        day = read_day(f, drop)
        day = day.filter(pl.col("flow_end_milliseconds") >= cal_end)
        if not day.height:
            continue
        flows = prepare_flows(day)
        ev_hours += (int(flows["end_ms"].max()) - int(flows["end_ms"].min())) / 3.6e6
        for lv in LEVELS:
            ev_truth[lv].append(truth(flows, lv, w))
            for v in VARIANTS:
                ev_win[v][lv].append(
                    nonsilent(aggregate(flows, lv, w, known_dst=profiles[v].known_dst))
                )
    hours = ev_hours  # summed per-day evaluation spans (excludes gaps between days)
    tr = {lv: pl.concat(ev_truth[lv]) for lv in LEVELS}
    res: dict = {"info": info, "eval_hours": hours}
    raw: dict = {}
    for v in VARIANTS:
        res[v] = {}
        for lv in LEVELS:
            evw = pl.concat(ev_win[v][lv], how="diagonal_relaxed")
            sc = profiles[v].score(evw.with_columns(pl.lit(lv).alias("level")))
            m = summarize(sc, tr[lv], hours)
            raw[(v, "robustz", lv)] = (m.pop("_scores"), m.pop("_y"))
            res[v][f"robustz_{lv}"] = m
            fit, hold = ifo[v][lv]
            if fit.height >= 30 and hold.height:
                m = summarize(iforest_level(fit, hold, evw), tr[lv], hours)
                raw[(v, "iforest", lv)] = (m.pop("_scores"), m.pop("_y"))
                res[v][f"iforest_{lv}"] = m
        print(v, {k: (round(x["recall"] or 0, 3), round(x["fpr"] or 0, 4),
                      None if x["roc_auc"] is None else round(x["roc_auc"], 3))
                  for k, x in res[v].items()}, flush=True)  # fmt: skip
    # H2: service-conditioned FPR at the global operating recall (clean calibration)
    for model in ("robustz", "iforest"):
        r_g = res["clean"].get(f"{model}_global", {}).get("recall")
        if r_g is not None and (("clean", model, "service") in raw):
            res.setdefault("h2", {})[model] = {
                "global_recall": r_g, "global_fpr": res["clean"][f"{model}_global"]["fpr"],
                "service_fpr_at_global_recall": fpr_at_recall(*raw[("clean", model, "service")], r_g),
                "device_fpr_at_global_recall": fpr_at_recall(*raw[("clean", model, "device")], r_g)
                if ("clean", model, "device") in raw else None}  # fmt: skip
    # Secondary (NOT pre-specified): FPR at fixed recall per level, clean and natural
    for v in ("clean", "natural"):
        for (vv, model, lv), (sc, y) in raw.items():
            if vv == v:
                res.setdefault("fpr_at_recall", {})[f"{v}/{model}/{lv}"] = {
                    "r0.5": fpr_at_recall(sc, y, 0.5),
                    "r0.8": fpr_at_recall(sc, y, 0.8),
                }
    res["meta"] = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"nf_dev_{a.dataset}.json").write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({"h2": res.get("h2"), "fpr_at_recall": res.get("fpr_at_recall"),
                      "meta": res["meta"]}, indent=1, default=str))  # fmt: skip


if __name__ == "__main__":
    main()
