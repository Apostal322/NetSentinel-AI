"""Phase 8f M2: evaluate the calibration-validity assessor (rule: docs/phase8f/PLAN.md s.2).
DEVELOPMENT data only. Product code: behavior.profile.fit_level_crossfit (builds the validity
reference) and behavior.validity.assess_validity; labels only for the outcome per segment.

Units: 1 h evaluation segments (120 windows) per capture. Comparators:
  A0 always valid;  A1 age expiry only (24 h);  A2 existing baseline_state rule (global alert
  rate > 2x target with binomial p < 0.01, or KS of global scores vs held-out > 0.3);
  A3 the new assessor (full status) and A3s its shift test alone.
C1 uses interleaved odd/even calibration reference blocks as a null.
Usage: uv run python scripts/phase8f/validity_eval.py -> reports/phase8f/validity_eval.json
"""

from __future__ import annotations

import json
import math
import sys
import time
from pathlib import Path
from types import SimpleNamespace

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
from netsentinel.behavior.monitor import _ks  # noqa: E402
from netsentinel.behavior.profile import _zs, fit_level_crossfit, window_scores  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

DEV = Path("data/derived/phase8b")
POP = Path("data/derived/phase8e")
OUT = Path("reports/phase8f/validity_eval.json")
T = 0.01
SEG = 120  # windows per segment (1 h)
LEVELS = ("global", "device", "service")
N_PERM = 999


def fit(cal: pl.DataFrame, level: str):
    return fit_level_crossfit(cal.with_columns(pl.lit(level).alias("level")), level, T, 30,
                              "vetted_benign")  # fmt: skip


def split_ref(ref: dict) -> tuple[dict, dict]:
    """Interleaved odd/even reference blocks (null: both halves from the calibration)."""
    idx = np.arange(len(ref["block"]))
    return tuple({k: np.asarray(v)[idx % 2 == r] for k, v in ref.items()} for r in (0, 1))


def capture(name: str) -> dict | None:
    data = {"device": load(DEV / name)}
    for lv in ("global", "service"):
        if (POP / lv / name / "meta.json").exists():
            data[lv] = load(POP / lv / name)
    d = data["device"]
    if d["cal_clean"].height < 60 or not d["eval_clean"].height:
        return None
    profs, evs = {}, {}
    for lv, dd in data.items():
        if dd["cal_clean"].height >= 60 and dd["eval_clean"].height:
            profs[lv] = fit(dd["cal_clean"], lv)
            evs[lv] = dd
    end = int(d["cal_clean"]["window_end_ms"].max())
    pseudo = SimpleNamespace(levels=profs, status="baseline_ready", period={"end_utc_ms": end})
    # ---- C1 null: interleaved calibration halves, Holm across levels
    ps = {}
    for lv, p in profs.items():
        if p.validity_ref is not None:
            a, b = split_ref(p.validity_ref)
            t = V.shift_test(a, b, N_PERM, seed=1)
            if t["status"] == "tested":
                ps[lv] = t["p"]
    null = {"levels_tested": len(ps),
            "confirmed": bool(ps) and min(V.holm(ps).values()) < V.ALPHA_CONFIRMED}  # fmt: skip
    # ---- evaluation segments
    dev_ev = d["eval_clean"]
    w0 = int(dev_ev["win"].min())
    y_dev = with_truth(dev_ev.select("key", "win"), d["truth"])["y"].to_numpy().astype(bool)
    dprof = profs["device"]
    s_dev = window_scores(_zs(dprof, dev_ev), 2)
    alert = s_dev > dprof.threshold
    seg_dev = (dev_ev["win"].to_numpy() - w0) // SEG
    segs = []
    gprof = profs.get("global")
    for k in np.unique(seg_dev):
        m = seg_dev == k
        ben = m & ~y_dev
        blocks = {}
        for lv, dd in evs.items():
            e = dd["eval_clean"]
            e = e.filter(((pl.col("win") - w0) // SEG) == int(k)).with_columns(
                pl.lit(lv).alias("level"))  # fmt: skip
            blocks[lv] = V.level_blocks(profs[lv], e)
        t0 = time.perf_counter()
        seg_end = int(dev_ev.filter(pl.col("win") - w0 < (int(k) + 1) * SEG)["window_end_ms"].max())
        a3 = V.assess_validity(pseudo, blocks, now_ms=seg_end, n_perm=N_PERM, seed=int(k))
        secs = time.perf_counter() - t0
        # A2: existing baseline_state rule on the segment's global windows
        a2 = "untested"
        if gprof is not None and "global" in evs:
            g = evs["global"]["eval_clean"].filter(((pl.col("win") - w0) // SEG) == int(k))
            if g.height >= 60:
                gs = window_scores(_zs(gprof, g), 2)
                al = int((gs > gprof.threshold).sum())
                p = float(binom.sf(al - 1, g.height, T)) if al else 1.0
                ks = _ks(gs, gprof.holdout_scores)
                a2 = "drift_suspected" if ((al / g.height > 2 * T and p < 0.01) or ks > 0.3) \
                    else "monitoring"  # fmt: skip
        shift_only = ("confirmed_shift" if a3["drift_detected"] else
                      "possible_shift" if "possible_shift" in a3["conditions"] else
                      ("valid" if a3["shift_test"] == "tested" else "untestable"))  # fmt: skip
        segs.append({"segment": int(k), "windows": int(m.sum()), "benign": int(ben.sum()),
                     "false_alerts": int((alert & ben).sum()),
                     "attack_windows": int((m & y_dev).sum()),
                     "A1": "expired" if "expired" in a3["conditions"] else "valid",
                     "A2": a2, "A3": a3["status"], "A3s": shift_only,
                     "A3_conditions": sorted(a3["conditions"]), "seconds": secs,
                     "levels": {lv: {k2: t.get(k2) for k2 in ("status", "p", "p_holm", "top")}
                                for lv, t in a3["levels"].items()}})  # fmt: skip
    return {"null": null, "segments": segs, "benign_only": name.startswith("CTU-Normal"),
            "device_threshold_reliable": bool(dprof.threshold_diag.get("reliable")),
            "reference_blocks": {lv: (0 if p.validity_ref is None else len(p.validity_ref["block"]))
                                 for lv, p in profs.items()}}  # fmt: skip


def table(rows: dict, key: str) -> dict:
    out: dict = {}
    for r in rows.values():
        for s in r["segments"]:
            st = s[key]
            e = out.setdefault(st, {"segments": 0, "benign": 0, "false_alerts": 0,
                                    "with_attacks": 0, "benign_only_segments": 0})  # fmt: skip
            e["segments"] += 1
            e["benign"] += s["benign"]
            e["false_alerts"] += s["false_alerts"]
            e["with_attacks"] += int(s["attack_windows"] > 0)
            e["benign_only_segments"] += int(r["benign_only"])
    for e in out.values():
        e["pooled_fpr"] = e["false_alerts"] / e["benign"] if e["benign"] else None
        lo, hi = wilson(e["false_alerts"], e["benign"]) if e["benign"] else (None, None)
        e["fpr_ci95"] = [lo, hi]
    return out


def criteria(rows: dict, key: str, valid_label: str, shift_label: str) -> dict:
    nulls = [r["null"] for r in rows.values() if r["null"]["levels_tested"]]
    c1 = sum(n["confirmed"] for n in nulls) / len(nulls) if nulls else None
    tab = table(rows, key)
    v, sh = tab.get(valid_label, {}), tab.get(shift_label, {})
    c2 = v.get("pooled_fpr")
    c3 = (sh["pooled_fpr"] / c2) if sh.get("pooled_fpr") is not None and c2 else (
        math.inf if sh.get("pooled_fpr") else None)  # fmt: skip
    bo = [s for r in rows.values() if r["benign_only"] for s in r["segments"]]
    c4 = sum(s[key] == valid_label for s in bo) / len(bo) if bo else None
    return {"C1_null_confirmed_share": c1, "C1_pass": c1 is not None and c1 <= 0.05,
            "C1_captures": len(nulls),
            "C2_valid_pooled_fpr": c2, "C2_valid_fpr_ci95": v.get("fpr_ci95"),
            "C2_pass": c2 is not None and c2 <= 2 * T,
            "C3_shift_to_valid_fpr_ratio": c3, "C3_pass": c3 is not None and c3 >= 2,
            "C4_benign_only_valid_share": c4, "C4_pass": c4 is not None and c4 >= 0.5,
            "table": tab}  # fmt: skip


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    rows, skipped = {}, []
    for n in names:
        r = capture(n)
        (skipped.append(n) if r is None else rows.__setitem__(n, r))
        print(n, "skipped" if r is None else
              f"{len(r['segments'])} segments, null {r['null']}", flush=True)  # fmt: skip
    secs = [s["seconds"] for r in rows.values() for s in r["segments"]]
    res = {"rule": "docs/phase8f/PLAN.md section 2", "role": "development (no consumed capture)",
           "skipped": skipped,
           "A3_full_assessor": criteria(rows, "A3", "valid", "confirmed_shift"),
           "A3s_shift_test_only": criteria(rows, "A3s", "valid", "confirmed_shift"),
           "A2_existing_baseline_state": criteria(rows, "A2", "monitoring", "drift_suspected"),
           "A1_age_only": criteria(rows, "A1", "valid", "expired"),
           "assessor_seconds_per_segment": {"median": float(np.median(secs)),
                                            "max": float(np.max(secs))},
           "captures": rows, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for k in ("A3_full_assessor", "A3s_shift_test_only", "A2_existing_baseline_state",
              "A1_age_only"):  # fmt: skip
        c = res[k]
        print(k, {x: c[x] for x in c if x != "table"})
        print("   ", {st: (e["segments"], e["pooled_fpr"], e["with_attacks"])
                      for st, e in c["table"].items()})  # fmt: skip
    print("seconds/segment", res["assessor_seconds_per_segment"], "peak", res["peak_rss_mb"])


if __name__ == "__main__":
    main()
