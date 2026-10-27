"""Phase 8f M1: why does calibration -> evaluation shift inflate false positives?
DEVELOPMENT data only (scripts/phase8b/dev_compare.dev_captures; no consumed capture).

Deployed scoring (robust per-key median/MAD z, top-2 |z|, cross-fit 1% threshold) on the
cached Phase 8b device windows and the Phase 8e global/service windows. Labels are used only
to select benign evaluation windows for the realised FPR and to measure recall. Per capture:
 1. realised FPR per level (target 1%);
 2. leave-one-feature-out (LOFO): realised device FPR with each feature dropped (threshold
    recomputed on the held-out scores without it) -> which features inflate false alarms;
 3. attribution: the top-|z| feature of every false-alert window;
 4. feature shift: median benign evaluation z per feature and the |z| > 3 tail rate vs the
    calibration held-out rate;
 5. entity changes: false alerts from keys with an own profile / pooled fallback / keys never
    seen in calibration;
 6. traffic intensity and telemetry coverage: flows per global window, active entities per
    window, share of windows without byte counts;
 7. profile age: realised FPR in the first vs the second half of the evaluation period;
 8. calibration sample size: held-out windows and fold-to-fold threshold variability;
 9. contamination: clean vs unlabelled calibration (attack captures);
10. autocorrelation of global window features in calibration (block length for drift tests).
Usage: uv run python scripts/phase8f/shift_diagnosis.py -> reports/phase8f/shift_diagnosis.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import polars as pl
from scipy.stats import spearmanr

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8c"))
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import crossfit  # noqa: E402

from netsentinel.behavior.profile import _zs, conformal_threshold  # noqa: E402
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

DEV = Path("data/derived/phase8b")
POP = Path("data/derived/phase8e")
OUT = Path("reports/phase8f/shift_diagnosis.json")
T = 0.01
F = list(WINDOW_FEATURES)


def top2(z: np.ndarray) -> np.ndarray:
    a = np.sort(np.abs(z), axis=1)[:, ::-1]
    return a[:, :2].mean(axis=1)


def fold_thresholds(cal: pl.DataFrame, zh: np.ndarray) -> list[float]:
    """Threshold from each cross-fit fold's held-out block alone (same order as crossfit)."""
    wins = np.sort(cal["win"].unique().to_numpy())
    out, i = [], 0
    for block in np.array_split(wins, 5):
        n = cal.filter(pl.col("win").is_between(int(block[0]), int(block[-1]))).height
        s = top2(zh[i : i + n])
        i += n
        if len(s) >= 30:
            out.append(conformal_threshold(s, T)[0])
    return out


def level_fpr(cal, ev, tr):
    prof, zh, kh, oh = crossfit(cal)
    ze = _zs(prof, ev)
    t = conformal_threshold(top2(zh), T)[0]
    y = with_truth(ev.select("key", "win"), tr)["y"].to_numpy().astype(bool)
    se = top2(ze)
    return prof, zh, kh, oh, ze, t, y, se


def acf(x: np.ndarray, lags: int) -> list[float]:
    x = x - x.mean()
    v = float((x * x).sum())
    return [float((x[:-k] * x[k:]).sum() / v) if v > 0 else 0.0 for k in range(1, lags + 1)]


def analyse(name: str) -> dict | None:
    d = load(DEV / name)
    cal, ev, tr = d["cal_clean"], d["eval_clean"], d["truth"]
    hours = d["meta"]["eval_hours"]
    if cal.height < 60 or not ev.height:
        return None
    prof, zh, kh, oh, ze, t, y, se = level_fpr(cal, ev, tr)
    ben = ~y
    alert = se > t
    fa = alert & ben
    r: dict = {"eval_hours": hours, "benign_windows": int(ben.sum()),
               "attack_windows": int(y.sum()), "holdout_windows": len(zh),
               "device_fpr": float(fa.sum() / ben.sum()) if ben.any() else None,
               "device_recall": float(alert[y].mean()) if y.any() else None}  # fmt: skip
    # 2. LOFO
    lofo = {}
    for j, f in enumerate(F):
        keep = [i for i in range(len(F)) if i != j]
        tj = conformal_threshold(top2(zh[:, keep]), T)[0]
        aj = top2(ze[:, keep]) > tj
        lofo[f] = {"fpr": float((aj & ben).sum() / ben.sum()) if ben.any() else None,
                   "recall": float(aj[y].mean()) if y.any() else None}  # fmt: skip
    r["lofo"] = lofo
    # 3. attribution of false alerts
    top = np.argmax(np.abs(ze[fa]), axis=1) if fa.any() else np.array([], int)
    r["false_alert_top_feature"] = {F[k]: int((top == k).sum()) for k in range(len(F))}
    # 4. feature shift on benign evaluation windows vs held-out calibration
    r["median_z_shift"] = {f: float(np.median(ze[ben, j])) if ben.any() else None
                           for j, f in enumerate(F)}  # fmt: skip
    r["tail_rate_eval"] = {f: float((np.abs(ze[ben, j]) > 3).mean()) if ben.any() else None
                           for j, f in enumerate(F)}  # fmt: skip
    r["tail_rate_holdout"] = {f: float((np.abs(zh[:, j]) > 3).mean()) for j, f in enumerate(F)}
    # 5. entity changes
    ke = np.array(ev["key"].to_list(), dtype=object)
    seen = set(cal["key"].unique().to_list())
    own = np.array([k in prof.keys for k in ke])
    new = np.array([k not in seen for k in ke])
    r["false_alerts_by_entity"] = {"own_profile": int((fa & own).sum()),
                                   "pooled_seen_in_calibration": int((fa & ~own & ~new).sum()),
                                   "never_seen_in_calibration": int((fa & new).sum())}  # fmt: skip
    r["eval_windows_by_entity"] = {"own_profile": int(own.sum()),
                                   "pooled_seen": int((~own & ~new).sum()),
                                   "never_seen": int(new.sum())}  # fmt: skip
    # 7. profile age: first vs second half of evaluation
    w = ev["win"].to_numpy()
    mid = np.median(w)
    for part, m in (("first_half", w <= mid), ("second_half", w > mid)):
        b = ben & m
        r[f"device_fpr_{part}"] = float((fa & m).sum() / b.sum()) if b.any() else None
    # 8. calibration sample size / threshold stability
    ft = fold_thresholds(cal, zh)
    r["threshold"] = t
    r["fold_thresholds"] = ft
    r["fold_threshold_cv"] = float(np.std(ft) / np.mean(ft)) if len(ft) >= 2 else None
    r["threshold_reliable"] = bool(conformal_threshold(top2(zh), T)[1])
    # 9. contamination: unlabelled calibration (only differs where calibration had attacks)
    if d["meta"]["flows"]["cal_attack"]:
        cu = d["cal_unlabelled"]
        eu = d["eval_unlabelled"]
        _, zhu, _, _, zeu, tu, yu, seu = level_fpr(cu, eu, tr)
        au = seu > tu
        r["contamination"] = {
            "calibration_attack_flows": d["meta"]["flows"]["cal_attack"],
            "fpr_unlabelled_cal": float((au & ~yu).sum() / (~yu).sum()) if (~yu).any() else None,
            "recall_unlabelled_cal": float(au[yu].mean()) if yu.any() else None,
            "threshold_ratio_unlabelled_vs_clean": tu / t if t else None}  # fmt: skip
    # global / service levels
    for level in ("global", "service"):
        p = POP / level / name
        if not (p / "meta.json").exists():
            continue
        g = load(p)
        gc, ge = g["cal_clean"], g["eval_clean"]
        if gc.height < 60 or not ge.height:
            continue
        _, gzh, _, _, gze, gt, gy, gse = level_fpr(gc, ge, g["truth"])
        gb = ~gy
        ga = (gse > gt) & gb
        r[f"{level}_fpr"] = float(ga.sum() / gb.sum()) if gb.any() else None
        if level == "global":
            # 6. intensity / coverage (unlabelled, all windows)
            def cov(df):
                nob = ((df["up"] == 0) & (df["down"] == 0)).mean()
                return {"median_flows_per_window": float(df["n_flows"].median()),
                        "share_windows_without_bytes": float(nob)}  # fmt: skip

            ent = {n_: float(df_.group_by("win").len()["len"].mean())
                   for n_, df_ in (("cal", cal), ("eval", ev))}  # fmt: skip
            r["intensity"] = {"cal": cov(gc), "eval": cov(ge),
                              "entities_per_window": ent,
                              "median_z_shift_log_flows": float(np.median(gze[gb, 0]))
                              if gb.any() else None}  # fmt: skip
            # 10. autocorrelation of global features in calibration (ordered by window)
            x = gc.sort("win").select(F).to_numpy().astype(float)
            r["global_acf"] = {f: acf(x[:, j], 30) for j, f in enumerate(F)
                               if np.std(x[:, j]) > 0}  # fmt: skip
        if level == "service":
            ks = np.array(ge["key"].to_list(), dtype=object)
            r["service_false_alerts"] = {str(k): int((ga & (ks == k)).sum())
                                         for k in sorted(set(ks[ga]))}  # fmt: skip
    return r


def pooled(rows: dict) -> dict:
    out: dict = {}
    rows = {n: r for n, r in rows.items() if r["benign_windows"]}  # FPR needs benign windows
    ben = {n: r["benign_windows"] for n, r in rows.items()}
    fa = {n: r["device_fpr"] * r["benign_windows"] for n, r in rows.items()}
    tot_fa = sum(fa.values())
    out["device_false_alerts"] = tot_fa
    # pooled LOFO: false alerts removed by dropping a feature (excluding NF-UNSW sensitivity)
    for tag, keep in (("all", rows), ("excluding_nf_unsw",
                      {n: r for n, r in rows.items() if not n.startswith("NF-")})):  # fmt: skip
        b = sum(ben[n] for n in keep)
        base = sum(fa[n] for n in keep)
        lo = {}
        for f in F:
            fa_f = sum(r["lofo"][f]["fpr"] * r["benign_windows"] for r in keep.values())
            lo[f] = {"pooled_fpr": fa_f / b, "false_alerts_change": fa_f - base}
        out[f"lofo_{tag}"] = {"pooled_fpr_all_features": base / b, "features": lo}
        attr = {f: sum(r["false_alert_top_feature"][f] for r in keep.values()) for f in F}
        s = sum(attr.values()) or 1
        out[f"false_alert_attribution_{tag}"] = {f: v / s for f, v in sorted(
            attr.items(), key=lambda kv: -kv[1])}  # fmt: skip
        ent = {
            k: sum(r["false_alerts_by_entity"][k] for r in keep.values())
            for k in ("own_profile", "pooled_seen_in_calibration", "never_seen_in_calibration")
        }
        out[f"false_alerts_by_entity_{tag}"] = ent
    # per-capture correlates of the FPR excess (descriptive; n = captures)
    names = [n for n, r in rows.items() if r["benign_windows"] >= 30]
    exc = np.array([rows[n]["device_fpr"] / T for n in names])
    cand = {
        "holdout_windows": [rows[n]["holdout_windows"] for n in names],
        "fold_threshold_cv": [rows[n]["fold_threshold_cv"] or 0 for n in names],
        "share_eval_windows_never_seen": [
            rows[n]["eval_windows_by_entity"]["never_seen"]
            / max(1, sum(rows[n]["eval_windows_by_entity"].values()))
            for n in names
        ],  # fmt: skip
        "max_abs_median_z_shift": [
            max(abs(v) for v in rows[n]["median_z_shift"].values() if v is not None) for n in names
        ],  # fmt: skip
        "flow_intensity_shift_z": [
            abs((rows[n].get("intensity") or {}).get("median_z_shift_log_flows") or 0)
            for n in names
        ],  # fmt: skip
        "eval_hours": [rows[n]["eval_hours"] for n in names],
    }
    out["fpr_excess_spearman"] = {}
    for k, v in cand.items():
        rho, p = spearmanr(exc, v)
        out["fpr_excess_spearman"][k] = {"rho": float(rho), "p": float(p), "n": len(names)}
    halves = [(rows[n]["device_fpr_first_half"], rows[n]["device_fpr_second_half"])
              for n in names if rows[n]["device_fpr_first_half"] is not None
              and rows[n]["device_fpr_second_half"] is not None]  # fmt: skip
    out["age_first_vs_second_half"] = {
        "captures": len(halves),
        "median_first": float(np.median([a for a, _ in halves])),
        "median_second": float(np.median([b for _, b in halves])),
        "second_higher": sum(b > a for a, b in halves)}  # fmt: skip
    # autocorrelation: lag where the median ACF over features and captures drops below 0.2/0.1
    acfs = [v for r in rows.values() for v in (r.get("global_acf") or {}).values()]
    if acfs:
        med = np.median(np.array(acfs), axis=0)
        out["global_acf_median_by_lag"] = [float(x) for x in med]
        for c in (0.2, 0.1):
            below = np.where(med < c)[0]
            out[f"acf_below_{c}_at_lag_windows"] = int(below[0] + 1) if len(below) else None
    cont = {n: r["contamination"] for n, r in rows.items() if "contamination" in r}
    out["contamination"] = cont
    return out


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    rows, skipped = {}, []
    for n in names:
        r = analyse(n)
        (skipped.append(n) if r is None else rows.__setitem__(n, r))
        print(n, "skipped" if r is None else f"fpr {r['device_fpr']}", flush=True)
    res = {"role": "development (no consumed capture)", "target_fpr": T, "features": F,
           "skipped": skipped, "pooled": pooled(rows), "captures": rows,
           "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    p = res["pooled"]
    print(json.dumps({k: p[k] for k in p if k not in ("contamination", "global_acf_median_by_lag")},
                     indent=1)[:6000])  # fmt: skip


if __name__ == "__main__":
    main()
