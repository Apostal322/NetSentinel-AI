"""Phase 8c: trace the deployed decision path (robust_z_product) window by window.

For each capture (cached device windows from scripts/phase8b/harness.py, clean calibration):
1. fit the product profile exactly as deployed (calibrate_windows, cross-fit, vetted mode);
2. who sets the threshold: per-device share of held-out windows and of the held-out tail;
3. the attacking devices: own profile or pooled fallback, calibration window count, attack
   window scores vs threshold, which features carry their |z|;
4. what the attacker's OWN calibration windows look like (clean variant = benign-labelled
   flows of the infected device), compared with its attack windows.

Retrospective use of the consumed Phase 8b captures is ALLOWED for explanation only and is
labelled so in every output; no model or threshold choice may be based on it.
Usage: uv run python scripts/phase8c/trace.py
Writes reports/phase8c/trace.json.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
from harness import load, with_truth  # noqa: E402

from netsentinel.behavior.calibrate import calibrate_windows  # noqa: E402
from netsentinel.behavior.profile import POOLED, _zs, window_scores  # noqa: E402
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402

OUT = Path("reports/phase8c/trace.json")
CAPTURES = {  # name -> (cache dir, role)
    "CTU-IoT-Malware-Capture-1-1": ("data/derived/phase8b_fresh", "retrospective (consumed)"),
    "CTU-IoT-Malware-Capture-60-1": ("data/derived/phase8b_fresh", "retrospective (consumed)"),
    "CTU-IoT-Malware-Capture-9-1": ("data/derived/phase8b_fresh", "retrospective (consumed)"),
    "CTU-IoT-Malware-Capture-3-1": ("data/derived/phase8b", "development"),
    "CTU-IoT-Malware-Capture-34-1": ("data/derived/phase8b", "development"),
    "CTU-IoT-Malware-Capture-20-1": ("data/derived/phase8b", "development"),
    "CTU-IoT-Malware-Capture-44-1": ("data/derived/phase8b", "development"),
    "NF-UNSW-NB15-v3-dev": ("data/derived/phase8b", "development"),
}


def q(a, ps=(0.5, 0.9, 0.99, 1.0)):
    a = np.asarray(a, dtype=float)
    return {f"p{int(p * 100)}": float(np.quantile(a, p)) for p in ps} if len(a) else None


def fit(cal: pl.DataFrame):
    lv = calibrate_windows({"device": cal}, 0, target_fpr=0.01, min_windows=30,
                           mode="vetted_benign", top_k=2, threshold_method="crossfit")  # fmt: skip
    return lv["device"]


def heldout_by_device(cal: pl.DataFrame, prof, folds: int = 5) -> pl.DataFrame:
    """Re-create the cross-fit held-out scores WITH their device keys (the product stores only
    the sorted scores)."""
    from netsentinel.behavior.profile import LevelProfile, _fit_stats

    wins = np.sort(cal["win"].unique().to_numpy())
    parts = []
    for block in np.array_split(wins, folds):
        inside = pl.col("win").is_between(int(block[0]), int(block[-1]))
        train, test = cal.filter(~inside), cal.filter(inside)
        tmp = LevelProfile(level="device")
        tmp.keys, tmp.pooled, _, _ = _fit_stats(train, 30, "vetted_benign", 2)
        if tmp.pooled is not None and test.height:
            parts.append(test.select("key", "win").with_columns(
                pl.Series("score", window_scores(_zs(tmp, test), 2)),
                pl.Series("own_profile", [k in tmp.keys for k in test["key"].to_list()])))  # fmt: skip
    return pl.concat(parts)


def trace(name: str, d: dict) -> dict:
    cal, ev, tr = d["cal_clean"], d["eval_clean"], d["truth"]
    prof = fit(cal)
    thr = float(prof.threshold)
    hs = heldout_by_device(cal, prof)
    assert np.allclose(np.sort(hs["score"].to_numpy()), prof.holdout_scores), "trace mismatch"
    tail = hs.filter(pl.col("score") > np.quantile(hs["score"], 0.99))
    who = (hs.group_by("key").agg(pl.len().alias("n"), pl.col("score").quantile(0.99).alias("p99"),
                                  pl.col("own_profile").mean().alias("own"))
           .join(tail.group_by("key").agg(pl.len().alias("tail")), on="key", how="left")
           .with_columns(pl.col("tail").fill_null(0)).sort("tail", descending=True))  # fmt: skip
    Z = _zs(prof, ev)  # noqa: N806
    s = window_scores(Z, 2)
    e = with_truth(ev.select("key", "win", "n_flows"), tr).with_columns(pl.Series("score", s))
    attackers = sorted(d["meta"]["first_attack_ms"])
    out = {"role": CAPTURES[name][1], "threshold": thr, "threshold_diag": prof.threshold_diag,
           "heldout_windows": hs.height, "heldout_scores": q(hs["score"].to_numpy()),
           "devices_in_calibration": cal["key"].n_unique(),
           "devices_with_own_profile": len(prof.keys),
           "tail_owners": who.head(5).to_dicts(),
           "eval_benign_scores": q(e.filter(~pl.col("y"))["score"].to_numpy()),
           "attackers": {}}  # fmt: skip
    for a in attackers:
        m = (e["key"] == a).to_numpy() & e["y"].to_numpy()
        if not m.any():
            continue
        za = np.abs(Z[m])
        top_feat = np.argsort(-za, axis=1)[:, :2]
        feat_counts = {
            WINDOW_FEATURES[i]: int((top_feat == i).sum()) for i in range(len(WINDOW_FEATURES))
        }
        own_cal = cal.filter(pl.col("key") == a)
        prof_scope = prof.scope_for(a)
        med_own = prof.keys[a][0] if a in prof.keys else None
        att_med = np.nanmedian(ev.filter(pl.col("key") == a).select(WINDOW_FEATURES).to_numpy()
                               .astype(float), axis=0)  # fmt: skip
        out["attackers"][a] = {
            "profile_used": "own" if prof_scope != POOLED else "pooled",
            "calibration_windows_of_attacker": own_cal.height,
            "calibration_flows_of_attacker": int(own_cal["n_flows"].sum()) if own_cal.height else 0,
            "attack_windows": int(m.sum()),
            "attack_scores": q(s[m]),
            "share_above_threshold": float((s[m] > thr).mean()),
            "max_score_over_threshold": float(s[m].max() / thr),
            "top2_feature_counts": dict(sorted(feat_counts.items(), key=lambda kv: -kv[1])[:5]),
            "median_abs_z_per_feature": dict(zip(WINDOW_FEATURES, np.round(np.median(za, axis=0), 2).tolist(), strict=True)),
            "own_profile_median": dict(zip(WINDOW_FEATURES, np.round(med_own, 3).tolist(), strict=True)) if med_own is not None else None,
            "attack_window_median": dict(zip(WINDOW_FEATURES, np.round(att_med, 3).tolist(), strict=True)),
        }  # fmt: skip
    return out


def main() -> None:
    res = {}
    for name, (root, _) in CAPTURES.items():
        p = Path(root) / name
        if not (p / "meta.json").exists():
            continue
        res[name] = trace(name, load(p))
        r = res[name]
        print(
            f"\n## {name} [{r['role']}] thr={r['threshold']:.2f} heldout={r['heldout_windows']} "
            f"own_profiles={r['devices_with_own_profile']}/{r['devices_in_calibration']}"
        )
        print(
            "   heldout",
            {k: round(v, 2) for k, v in r["heldout_scores"].items()},
            "| eval benign",
            {k: round(v, 2) for k, v in (r["eval_benign_scores"] or {}).items()},
        )
        print(
            "   tail owners",
            [(t["key"], t["n"], t["tail"], round(t["p99"], 1)) for t in r["tail_owners"][:3]],
        )
        for a, x in r["attackers"].items():
            print(f"   attacker {a}: profile={x['profile_used']} cal_windows={x['calibration_windows_of_attacker']} "
                  f"cal_flows={x['calibration_flows_of_attacker']} attack_w={x['attack_windows']} "
                  f"above={x['share_above_threshold']:.3f} max/thr={x['max_score_over_threshold']:.2f} "
                  f"scores={ {k: round(v, 2) for k, v in x['attack_scores'].items()} } top={list(x['top2_feature_counts'])[:3]}")  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            res,
            indent=1,
            default=lambda o: None if isinstance(o, float) and math.isnan(o) else str(o),
        ),
        "utf-8",
    )


if __name__ == "__main__":
    main()
