"""Phase 8m Stage 1: what the destination-novelty feature does to the scores (no training).

Two parts, each labelled in the output:

1. DEVELOPMENT (correlational; existing Phase 8j P1x artifacts, 9 domains x 3 seeds). The source
   models of Phase 8j were not saved, so only associations are measured: T0 from the P1x
   hold-out, false alerts on verified-benign evaluation windows, and how often those windows
   carry destination novelty, against the benign base rate; recall split by novelty; novelty
   against time since the calibration end; hosts first seen after calibration.
2. DEDALE (POST-HOC retrospective diagnostic; consumed data; the Phase 8l result is unchanged).
   The frozen models and thresholds are reused read-only:
   - reproduction of the confirmatory FPR (integrity check);
   - LightGBM SHAP contributions (`pred_contrib`) on false-alert and sampled benign windows;
   - counterfactual: `new_dst_frac` set to 0 in every evaluation window (scores recomputed);
   - novelty in calibration (expanding memory) vs evaluation (frozen memory), by day;
   - reconciliation of the alert-rate denominators (windows, hours, days, hosts).

Output: reports/phase8m/novelty_audit.json
Usage: uv run python scripts/run_capped.py -- <abs python> scripts/phase8m/novelty_audit.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
DEV = ROOT / "data" / "derived" / "phase8j"
DED = ROOT / "data" / "derived" / "phase8l" / "dedale"
OUT = ROOT / "reports" / "phase8m" / "novelty_audit.json"
ALPHA = 0.01
H_MS = 3_600_000


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def k_of(n: int) -> int:
    return min(math.ceil((n + 1) * (1 - ALPHA)), n)


def lift(flag: np.ndarray, alert: np.ndarray, base: np.ndarray) -> dict:
    """P(flag | alert) against P(flag) over the base set (all arrays boolean, same length)."""
    na = int(alert.sum())
    p_alert = float(flag[alert].mean()) if na else float("nan")
    p_base = float(flag[base].mean()) if base.any() else float("nan")
    return {"alerts": na, "p_novel_given_alert": p_alert, "p_novel_base": p_base,
            "lift": p_alert / p_base if p_base > 0 else float("nan")}  # fmt: skip


# ----------------------------------------------------------------------------- development
def dev_domain(npz: Path) -> dict:
    d = np.load(npz)
    net, dom = str(d["network"]), npz.name.split("__")[1]
    ev = pl.read_parquet(DEV / "p1x" / net / dom / "eval_p1x.parquet",
                         columns=["key", "win", "new_dst_frac", "n_flows"])  # fmt: skip
    cal = pl.read_parquet(DEV / "p1x" / net / dom / "cal_p1x.parquet", columns=["key", "win"])
    idx = pl.DataFrame({"key": d["ev_key"], "win": d["ev_win"]}).with_row_index("i")
    j = idx.join(ev, on=["key", "win"], how="left").sort("i")
    nov = j["new_dst_frac"].fill_null(0).to_numpy() > 0
    hold = d["cal_s"][d["cal_hold"]]
    t0 = float(np.sort(hold)[k_of(hold.size) - 1])
    alert = d["ev_s"] > t0
    benign, y = d["ev_benign"], d["ev_y"]
    cal_end = int(d["cal_end"].max())
    age_h = (d["ev_end"] - cal_end) / H_MS
    seen = np.isin(d["ev_key"], np.unique(cal["key"].to_numpy()))
    fa = alert & benign
    bins = [0, 1, 6, 24, 72, 1e9]
    by_age = []
    for lo, hi in zip(bins[:-1], bins[1:], strict=True):
        m = benign & (age_h >= lo) & (age_h < hi)
        if m.sum():
            by_age.append({"age_h": [lo, hi], "windows": int(m.sum()),
                           "novel_share": float(nov[m].mean()), "fpr": float(alert[m].mean())})  # fmt: skip
    rec = {}
    for name, m in (("novel", y & nov), ("not_novel", y & ~nov)):
        rec[name] = {"attack_windows": int(m.sum()),
                     "recall": float(alert[m].mean()) if m.any() else None}  # fmt: skip
    return {
        "domain": f"{net}/{dom}", "t0": t0, "benign_windows": int(benign.sum()),
        "fpr": float(alert[benign].mean()) if benign.any() else None,
        "novelty_vs_false_alerts": lift(nov, fa, benign),
        "false_alert_share_from_unseen_hosts": float((fa & ~seen).sum() / fa.sum()) if fa.any() else None,
        # share of BENIGN windows (the run saved at 40fab1f divided by all evaluation windows;
        # NOVELTY_FAILURE_ANALYSIS.md erratum)
        "benign_share_from_unseen_hosts": float((benign & ~seen).sum() / benign.sum()) if benign.any() else None,
        "recall_by_novelty": rec, "by_calibration_age": by_age,
    }  # fmt: skip


# ----------------------------------------------------------------------------- DEDALE post hoc
def dedale() -> dict:
    import lightgbm as lgb

    c = _load("common_8i", ROOT / "scripts/phase8i/common.py")
    an = _load("phase8l_dedale_analysis", ROOT / "scripts/phase8l/dedale_analysis.py")
    st_a = _load("phase8l_dedale_stage_a", ROOT / "scripts/phase8l/dedale_stage_a.py")
    rep_m = json.loads((ROOT / "reports/phase8l/dedale_source_models.json").read_text("utf-8"))
    n8 = json.loads((ROOT / "reports/phase8l/dedale_n8.json").read_text("utf-8"))
    final = json.loads((ROOT / "reports/phase8l/dedale_final.json").read_text("utf-8"))
    models = [lgb.Booster(model_file=str(ROOT / rep_m["models"][str(k)]["file"].replace("\\", "/")))
              for k in (0, 1, 2)]  # fmt: skip
    thr = np.array([n8["per_seed"][str(k)]["t0"] for k in (0, 1, 2)])
    feats = list(c.S.FEATS)
    leases = pl.read_parquet(DED / "leases.parquet")
    internal = an.a_internal(st_a)
    ev = pl.read_parquet(DED / "eval_p1x.parquet")
    ev = ev.with_columns(an.attribute_hosts(ev["key"], ev["window_end_ms"], leases, internal))
    ev = ev.join(pl.read_parquet(DED / "eval_truth.parquet"), on=["key", "win"], how="left")
    ev = ev.with_columns(pl.col("y1").fill_null(False), pl.col("y2").fill_null(False))
    x = c.S._x(ev)
    s = np.column_stack([m.predict(x) for m in models])
    alert = (s > thr).astype(float)
    a = alert.mean(1)
    elig = set(n8["eligible_hosts"])
    host = ev["host"].to_numpy()
    y1, y2 = ev["y1"].to_numpy(), ev["y2"].to_numpy()
    vb = np.isin(host, sorted(elig)) & ~(y1 | y2)
    nov = ev["new_dst_frac"].fill_null(0).to_numpy() > 0
    out: dict = {"status": "POST-HOC retrospective diagnostic (consumed DEDALE data)",
                 "fpr_reproduced": float(a[vb].mean()), "fpr_confirmatory": final["H1"]["fpr"]}  # fmt: skip
    if abs(out["fpr_reproduced"] - out["fpr_confirmatory"]) > 1e-12:
        raise SystemExit("could not reproduce the confirmatory FPR")
    fa = vb & (a > 0)
    out["novelty_vs_false_alerts"] = lift(nov, fa, vb)
    out["novelty_in_attack_windows"] = {"attack_windows": int(y1.sum()),
                                        "novel_share": float(nov[y1].mean()),
                                        "recall_novel": float(a[y1 & nov].mean()) if (y1 & nov).any() else None,
                                        "recall_not_novel": float(a[y1 & ~nov].mean()) if (y1 & ~nov).any() else None}  # fmt: skip
    # counterfactual: novelty removed from every evaluation window
    x0 = x.copy()
    x0[:, feats.index("new_dst_frac")] = 0.0
    a0 = (np.column_stack([m.predict(x0) for m in models]) > thr).mean(1)
    out["counterfactual_new_dst_frac_zero"] = {
        "fpr": float(a0[vb].mean()), "fpr_original": float(a[vb].mean()),
        "false_alerts": float(a0[vb].sum()), "false_alerts_original": float(a[vb].sum()),
        "attack_window_recall": float(a0[y1].mean()), "attack_window_recall_original": float(a[y1].mean()),
        "note": "all other features unchanged; models and thresholds frozen; a counterfactual input, not a deployable feature",
    }  # fmt: skip
    # SHAP contributions (log-odds) on false-alert windows and a benign sample
    rng = np.random.default_rng(0)
    fa_idx = np.flatnonzero(fa)
    bn_idx = rng.choice(
        np.flatnonzero(vb & (a == 0)), size=min(5000, int((vb & (a == 0)).sum())), replace=False
    )
    shap = {}
    for name, idx in (("false_alert_windows", fa_idx), ("benign_sample", bn_idx)):
        contrib = np.mean(
            [m.predict(x[idx], pred_contrib=True)[:, : len(feats)] for m in models], axis=0
        )
        mean_abs = np.abs(contrib).mean(0)
        order = np.argsort(-mean_abs)
        shap[name] = {"windows": int(idx.size),
                      "mean_contribution": {feats[i]: float(contrib[:, i].mean()) for i in order},
                      "mean_abs_contribution": {feats[i]: float(mean_abs[i]) for i in order},
                      "new_dst_frac_rank_by_abs": int(np.where(order == feats.index("new_dst_frac"))[0][0]) + 1}  # fmt: skip
    out["shap"] = shap
    # novelty by day: calibration (expanding memory) vs evaluation (frozen)
    cal = pl.read_parquet(
        DED / "cal_p1x.parquet", columns=["key", "win", "window_end_ms", "new_dst_frac"]
    )
    cal = cal.filter(
        pl.col("key").is_in(sorted({k for k, h in zip(ev["key"], host, strict=True) if h in elig}))
    )
    evd = pl.DataFrame(
        {"t": ev["window_end_ms"].to_numpy() - 1, "n": nov.astype(float), "vb": vb}
    ).filter(pl.col("vb"))
    cald = cal.select(
        (pl.col("window_end_ms") - 1).alias("t"),
        (pl.col("new_dst_frac") > 0).cast(pl.Float64).alias("n"),
    )
    daily = []
    for part, df in (("calibration_expanding_memory", cald), ("evaluation_frozen_memory", evd)):
        g = (
            df.group_by((pl.col("t") // 86_400_000).alias("d"))
            .agg(pl.col("n").mean(), pl.len())
            .sort("d")
        )
        for d_, n_, ln in g.iter_rows():
            daily.append({"part": part, "utc_day": str(np.datetime64(int(d_), "D")), "windows": int(ln),
                          "novel_share": float(n_)})  # fmt: skip
    out["novelty_by_day"] = daily
    # per-host concentration of false alerts
    per = (
        pl.DataFrame({"h": host[fa], "a": a[fa]})
        .group_by("h")
        .agg(pl.col("a").sum())
        .sort("a", descending=True)
    )
    tot = float(per["a"].sum())
    out["false_alerts_by_host"] = {"hosts_with_false_alerts": per.height,
                                   "top1_share": float(per["a"][0] / tot) if tot else None,
                                   "top5_share": float(per["a"][:5].sum() / tot) if tot else None,
                                   "per_host_min_max": [float(per["a"].min()), float(per["a"].max())]}  # fmt: skip
    # alert-rate reconciliation
    tw = ev["window_end_ms"].to_numpy() - 1
    days = np.unique(tw[vb] // 86_400_000)
    hh = pl.DataFrame({"h": host[vb], "hr": tw[vb] // H_MS}).unique().height
    out["alert_rate_reconciliation"] = {
        "verified_benign_windows": int(vb.sum()), "seed_mean_false_alerts": float(a[vb].sum()),
        "fpr_per_window": float(a[vb].mean()),
        "days_with_benign_windows": int(days.size),
        "false_alerts_per_active_day_mean": float(a[vb].sum() / days.size),
        "false_alerts_per_calendar_day_14": float(a[vb].sum() / 14),
        "active_host_hours": hh, "false_alerts_per_active_host_hour": float(a[vb].sum() / hh),
        "false_alerts_per_host_per_active_day": float(a[vb].sum() / days.size / len(elig)),
        "note": "Phase 8l's '~200 a day' was the upper part of the daily range (20-251); the mean over the 10 working days with benign windows is the figure above",
    }  # fmt: skip
    return out


def main() -> None:
    t0 = time.perf_counter()
    rep = {"development": {"status": "exploratory (correlational; existing Phase 8j artifacts)",
                           "domains": {}}}  # fmt: skip
    for npz in sorted((DEV / "dev").glob("*__seed*.npz")):
        r = dev_domain(npz)
        rep["development"]["domains"].setdefault(r.pop("domain"), {})[npz.stem.split("__")[-1]] = r
    rep["dedale"] = dedale()
    from netsentinel.resources import peak_rss_mb

    rep["peak_rss_mb"], rep["seconds"] = peak_rss_mb(), round(time.perf_counter() - t0, 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rep, indent=1, default=str), "utf-8")
    print("done", rep["seconds"], "s")


if __name__ == "__main__":
    main()
