"""Phase 8f M3/M5: recalibration strategies over the evaluation timeline (rule: PLAN.md s.3-4).
DEVELOPMENT data only; device level (the flow-alerting level, where attackers are measured).

The evaluation half of every capture is cut into 1 h segments. Segment k is scored by the
baseline active at its start; a strategy may then replace the baseline using windows seen so
far (each replacement is a new version; the previous one stays available = rollback):
  S1 fixed clean calibration (Phase 8e negative-result baseline)
  S2 every 2 h: refit on the last 2 h, unfiltered
  S3 after a segment with a confirmed shift (behavior.validity): refit on that segment
  S4 every 2 h: refit on the last 2 h minus windows anomalous under the current baseline or
     >= 2x its held-out maximum (the update gate's strong-outlier rule); unlabelled
  S4o as S4 with label-benign windows only (oracle "vetted"; not deployable)
  S5 every 2 h: candidate from the last 2 h, activated only if the update gate passes (device
     alert rate not > 2x target with binomial p < 0.01, no strong outlier) and the candidate's
     threshold diagnostics are reliable; else keep the current baseline (review_required)
  S1u / S5u: S1 and S5 started from the UNLABELLED calibration (contamination robustness)
Usage: uv run python scripts/phase8f/recalibration_sim.py -> reports/phase8f/recalibration.json
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl
from scipy.stats import binom

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8c"))
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import wilson  # noqa: E402

from netsentinel.behavior import validity as V  # noqa: E402
from netsentinel.behavior.profile import _zs, fit_level_crossfit, window_scores  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

DEV = Path("data/derived/phase8b")
OUT = Path("reports/phase8f/recalibration.json")
T = 0.01
SEG = 120
EVERY = 2  # segments (2 h)
STRATEGIES = ("S1", "S2", "S3", "S4", "S4o", "S5", "S1u", "S5u")
COSTS = (10, 100)


def fit(df: pl.DataFrame):
    if df.height < 60:
        return None
    return fit_level_crossfit(df.with_columns(pl.lit("device").alias("level")), "device", T, 30,
                              "vetted_benign")  # fmt: skip


def scores(prof, df: pl.DataFrame) -> np.ndarray:
    return window_scores(_zs(prof, df), 2) if df.height else np.zeros(0)


def gate(prof, df: pl.DataFrame) -> tuple[bool, str]:
    """Update gate at the device level: rate review or strong outlier -> review required."""
    s = scores(prof, df)
    n, al = len(s), int((s > prof.threshold).sum())
    p = float(binom.sf(al - 1, n, T)) if al else 1.0
    if n and al / n > 2 * T and p < 0.01:
        return False, "rate_review"
    hmax = float(np.max(prof.holdout_scores)) if len(prof.holdout_scores) else prof.threshold
    if hmax and (s >= 2 * hmax).any():
        return False, "strong_outlier"
    return True, "passed"


def run(strategy: str, d: dict) -> dict:
    cal = d["cal_unlabelled"] if strategy.endswith("u") else d["cal_clean"]
    ev = d["eval_clean"].sort("win")
    y = with_truth(ev.select("key", "win"), d["truth"])["y"].to_numpy().astype(bool)
    keys = np.array(ev["key"].to_list(), dtype=object)
    end = ev["window_end_ms"].to_numpy()
    w0 = int(ev["win"].min())
    seg = (ev["win"].to_numpy() - w0) // SEG
    prof = fit(cal)
    if prof is None:
        return {"status": "too few calibration windows"}
    alert = np.zeros(len(ev), bool)
    absorbed, refits, activations, reviews, refit_s, valid_segs, tested_segs = 0, 0, 0, 0, [], 0, 0
    base = strategy.rstrip("u")
    for k in np.unique(seg):
        m = seg == k
        part = ev.filter(pl.Series(m))
        s = scores(prof, part)
        alert[m] = s > prof.threshold
        # calibration validity of the active baseline for this segment (shift test only)
        t = V.shift_test(prof.validity_ref, V.level_blocks(prof, part), 199, seed=int(k))
        if t["status"] == "tested":
            tested_segs += 1
            valid_segs += int(t["p"] >= V.ALPHA_CONFIRMED)
        due = (k + 1) % EVERY == 0
        new, src_mask = None, None
        recent = (seg > k - EVERY) & (seg <= k)
        t_start = time.perf_counter()
        if base == "S2" and due:
            src_mask = recent
        elif base == "S3" and t["status"] == "tested" and t["p"] < V.ALPHA_CONFIRMED:
            src_mask = m
        elif base in ("S4", "S4o", "S5") and due:
            rs = scores(prof, ev.filter(pl.Series(recent)))
            hmax = float(np.max(prof.holdout_scores))
            keep = np.zeros(len(ev), bool)
            if base == "S4o":
                keep[recent] = ~y[recent]
            elif base == "S4":
                keep[recent] = (rs <= prof.threshold) & (rs < 2 * hmax)
            else:
                keep = recent
            src_mask = keep
        if src_mask is not None and src_mask.any():
            cand = fit(ev.filter(pl.Series(src_mask)))
            refits += 1
            if cand is not None and base == "S5":
                ok, why = gate(prof, ev.filter(pl.Series(src_mask)))
                if not ok or not cand.threshold_diag.get("reliable"):
                    reviews += 1
                    cand = None
            if cand is not None:
                new = cand
                absorbed += int((src_mask & y).sum())
        refit_s.append(time.perf_counter() - t_start)
        if new is not None:
            prof = new
            activations += 1
    hours = d["meta"]["eval_hours"]
    ben = ~y
    attackers = set(d["meta"]["first_attack_ms"])
    ents = sorted({k for k in keys[y] if k in attackers})
    det, delays = [], []
    for a in ents:
        mk = (keys == a) & y
        hit = mk & alert
        if hit.any():
            det.append(a)
            delays.append((end[hit].min() - end[mk].min()) / 1000)
    fa = int((alert & ben).sum())
    missed = int((y & ~alert).sum())
    return {"false_alerts": fa, "false_alerts_per_h": fa / hours if hours else None,
            "benign_windows": int(ben.sum()), "attack_windows": int(y.sum()),
            "attack_windows_detected": int((alert & y).sum()),
            "attackers": len(ents), "attackers_detected": len(det), "delays_s": delays,
            "absorbed_attack_windows": absorbed, "refits": refits, "activations": activations,
            "reviews_required": reviews, "segments_tested": tested_segs,
            "segments_valid": valid_segs,
            "refit_seconds_max": float(max(refit_s)) if refit_s else 0.0,
            "cost": {str(c): missed * c + fa for c in COSTS}, "hours": hours}  # fmt: skip


def summary(rows: dict) -> dict:
    out = {}
    for s in STRATEGIES:
        rs = [r[s] for r in rows.values() if "false_alerts" in r.get(s, {})]
        fah = [r["false_alerts_per_h"] for r in rs if r["hours"] >= 1 and r["benign_windows"] >= 30]
        aw = sum(r["attack_windows"] for r in rs)
        att = sum(r["attackers"] for r in rs)
        det = sum(r["attackers_detected"] for r in rs)
        delays = [x for r in rs for x in r["delays_s"]]
        tested = sum(r["segments_tested"] for r in rs)
        lo, hi = wilson(det, att) if att else (None, None)
        out[s] = {"captures": len(rs), "false_alerts": sum(r["false_alerts"] for r in rs),
                  "pooled_false_alerts_per_h": sum(r["false_alerts"] for r in rs)
                  / sum(r["hours"] for r in rs),
                  "median_false_alerts_per_h": float(np.median(fah)) if fah else None,
                  "max_false_alerts_per_h": float(max(fah)) if fah else None,
                  "window_recall": sum(r["attack_windows_detected"] for r in rs) / aw if aw else None,
                  "attackers_detected": f"{det}/{att}", "attacker_recall_ci95": [lo, hi],
                  "median_delay_s": float(np.median(delays)) if delays else None,
                  "absorbed_attack_windows": sum(r["absorbed_attack_windows"] for r in rs),
                  "absorbed_share": sum(r["absorbed_attack_windows"] for r in rs) / aw if aw
                  else None,
                  "activations": sum(r["activations"] for r in rs),
                  "reviews_required": sum(r["reviews_required"] for r in rs),
                  "valid_segment_share": sum(r["segments_valid"] for r in rs) / tested
                  if tested else None,
                  "cost": {str(c): sum(r["cost"][str(c)] for r in rs) for c in COSTS},
                  "max_refit_seconds": max(r["refit_seconds_max"] for r in rs)}  # fmt: skip
    ref = out["S1"]
    for s, e in out.items():
        d_att = int(e["attackers_detected"].split("/")[0])
        r_att = int(ref["attackers_detected"].split("/")[0])
        e["success_vs_S1"] = {
            "lower_false_alerts": e["pooled_false_alerts_per_h"] < ref["pooled_false_alerts_per_h"],
            "no_attacker_lost": d_att >= r_att,
            "window_recall_ge_0.9x": (e["window_recall"] or 0) >= 0.9 * (ref["window_recall"] or 0),
            "absorbed_le_1pct": (e["absorbed_share"] or 0) <= 0.01}  # fmt: skip
        e["succeeds"] = s not in ("S1", "S4o", "S1u") and all(e["success_vs_S1"].values())
    return out


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    rows = {}
    for n in names:
        d = load(DEV / n)
        if d["cal_clean"].height < 60 or not d["eval_clean"].height:
            continue
        rows[n] = {s: run(s, d) for s in STRATEGIES}
        print(
            n,
            {
                s: (
                    r.get("false_alerts"),
                    r.get("attackers_detected"),
                    r.get("absorbed_attack_windows"),
                )
                for s, r in rows[n].items()
            },
            flush=True,
        )
    summ = summary(rows)
    res = {"rule": "docs/phase8f/PLAN.md sections 3-4", "role": "development (no consumed capture)",
           "summary": summ, "captures": rows, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for s, e in summ.items():
        print(s, {k: e[k] for k in ("pooled_false_alerts_per_h", "max_false_alerts_per_h",
                                    "window_recall", "attackers_detected", "median_delay_s",
                                    "absorbed_attack_windows", "activations", "reviews_required",
                                    "valid_segment_share", "succeeds")})  # fmt: skip
    print("peak", res["peak_rss_mb"])


if __name__ == "__main__":
    main()
