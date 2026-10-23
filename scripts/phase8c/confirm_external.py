"""Phase 8c external validation (ToN_IoT network data) - implements
docs/phase8c/EXTERNAL_VALIDATION_PLAN.md exactly. Frozen before the data is downloaded.

Usage:
  uv run --extra torch python scripts/phase8c/confirm_external.py <out.json> <csv> [<csv> ...]
CSV files are the ToN_IoT network-dataset files, passed in their numeric order.
Windows are cached in data/derived/phase8c_external/<name>.
"""

from __future__ import annotations

import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[0] / "phase8b"))
import scorers as S  # noqa: E402, N812
import toniot  # noqa: E402
from confirm import boot_delta, ci_verdict, clopper_pearson, incidents  # noqa: E402
from dev_compare import dev_captures  # noqa: E402
from harness import W, WindowBuilder, load, operational, with_truth  # noqa: E402
from policies import lgbm_policy, metrics, robust_policies  # noqa: E402

from netsentinel.behavior.calibrate import calibrate_windows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

CACHE = Path("data/derived/phase8c_external")
DEV = Path("data/derived/phase8b")
EXCLUDED_FROM_TRAINING = {"CTU-IoT-Malware-Capture-49-1", "NF-UNSW-NB15-v3-dev"}  # see plan


def build_windows(paths: list[str], out: Path) -> dict:
    from netsentinel.streaming.live import END, WindowStream
    from netsentinel.telemetry.frames import records_to_frame

    lo, hi, n = math.inf, -math.inf, 0
    for r in toniot.records(paths):
        lo, hi, n = min(lo, r[END]), max(hi, r[END]), n + 1
    b = WindowBuilder(int(lo + (hi - lo) // 2))
    ws = WindowStream(W, lateness_s=3700, max_buffer=1_500_000)
    stats: dict = {}
    pending: list[dict] = []
    for rec in toniot.records(paths, stats):
        for _, rs in ws.push(rec):
            pending += rs
        if len(pending) >= 200_000:
            b.add(records_to_frame(pending))
            pending = []
    for _, rs in ws.flush():
        pending += rs
    if pending:
        b.add(records_to_frame(pending))
    b.save(out, {"source": [Path(p).name for p in paths], "records": n,
                 "stream": ws.stats.as_dict(), "reader": stats})  # fmt: skip
    return load(out)


def main() -> None:
    out_path, paths = Path(sys.argv[1]), sys.argv[2:]
    t0 = time.perf_counter()
    cache = CACHE / "toniot"
    d = load(cache) if (cache / "meta.json").exists() else build_windows(paths, cache)
    cal, ev, tr = d["cal_clean"], d["eval_clean"], d["truth"]
    hours, fa = d["meta"]["eval_hours"], d["meta"]["first_attack_ms"]
    y = with_truth(ev.select("key", "win"), tr)["y"].to_numpy()
    testable = cal.height >= 60 and int(y.sum()) >= 5 and int((~y).sum()) >= 30
    res: dict = {"plan": "docs/phase8c/EXTERNAL_VALIDATION_PLAN.md", "meta": d["meta"],
                 "testability": {"cal_windows": cal.height, "attack": int(y.sum()),
                                 "benign": int((~y).sum()), "ok": testable}}  # fmt: skip
    H: dict = {}
    if testable:
        names = [n for n in dev_captures() if n not in EXCLUDED_FROM_TRAINING
                 and (DEV / n / "meta.json").exists()]  # fmt: skip
        srcs = []
        for n in names:
            dd = load(DEV / n)
            if dd["cal_clean"].height:
                srcs.append({"cal": dd["cal_clean"], "ev": dd["eval_clean"], "truth": dd["truth"]})
        model, src_thr = S.lgbm_fit(srcs, False)
        rp = robust_policies(cal, ev)
        e_norm, e_alert = lgbm_policy(model, cal, ev)
        pol = {"A": rp["A"], "C2": rp["C2"], "E": (e_norm, e_alert)}
        m = {k: metrics(ev, tr, n, a, hours, fa) for k, (n, a) in pol.items()}
        res["policy_metrics"] = m
        lp = calibrate_windows({"device": cal}, 0, target_fpr=0.01, min_windows=30,
                               mode="vetted_benign", threshold_method="crossfit")["device"]  # fmt: skip
        diag = {"tail_fallback_share": lp.tail_fallback_share,
                "warned": any("WITHOUT an own profile" in w for w in lp.warnings),
                "threshold_reliable": lp.threshold_diag.get("reliable")}  # fmt: skip
        res["tail_diagnostic"] = diag
        end = with_truth(ev.select("key", "win", "window_end_ms"), tr)["window_end_ms"].to_numpy()
        # X1: product FPR within 3x target
        a = pol["A"][1]
        k, nb = int((a & ~y).sum()), int((~y).sum())
        lo, hi = clopper_pearson(k, nb)
        H["X1"] = {"fpr": k / nb, "ci95": [lo, hi], "false_alerts_per_h": k / hours,
                   "verdict": "supported" if k / nb <= 0.03 and hi <= 0.05 else
                   "refuted" if lo > 0.03 else "inconclusive"}  # fmt: skip
        # X2: root-cause prediction
        b = boot_delta(end, y.astype(int), pol["C2"][0], pol["A"][0])
        rec_a, rec_c2 = m["A"]["window_recall"] or 0.0, m["C2"]["window_recall"] or 0.0
        if diag["warned"]:
            v = "supported" if rec_c2 > rec_a and m["C2"]["fpr"] <= 0.03 else "refuted"
        else:
            v = "supported" if abs(rec_c2 - rec_a) <= 0.05 else "refuted"
        H["X2"] = {"diagnostic_warned": diag["warned"], "window_recall_A": rec_a,
                   "window_recall_C2": rec_c2, "fpr_C2": m["C2"]["fpr"],
                   "attackers_A": m["A"]["attackers_detected"],
                   "attackers_C2": m["C2"]["attackers_detected"], "pr_auc_delta_C2_minus_A": b,
                   "verdict": v}  # fmt: skip
        # X3: LightGBM (no UNSW in training) ranks better than robust_z
        s_rz, _ = S.product(cal, ev)
        b3 = boot_delta(end, y.astype(int), e_norm, s_rz)
        H["X3"] = {**b3, "verdict": ci_verdict(b3["ci95"])}
        # X4: does LightGBM add anything beyond the pre-specified scan signature (new_dst_frac)?
        sig = np.nan_to_num(ev["new_dst_frac"].cast(pl.Float64).to_numpy())
        b4 = boot_delta(end, y.astype(int), e_norm, sig)
        H["X4"] = {**b4, "verdict": ci_verdict(b4["ci95"])}
        # X5: incidents, window-weighted purity >= 0.8 and reduction >= 5 (product)
        inc = incidents(ev, tr, pol["A"][0] * 1.0, 1.0, hours)  # normalised scores, thr = 1
        H["X5"] = {**inc, "verdict": "not_testable" if inc["incidents"] < 5 else (
            "supported" if (inc["window_weighted_purity"] or 0) >= 0.8
            and (inc["alert_reduction"] or 0) >= 5 else "refuted")}  # fmt: skip
        res["lgbm_source_threshold"] = operational(ev, tr, model.predict_proba(S._x(ev))[:, 1],
                                                   src_thr, hours, fa)  # fmt: skip
    else:
        H = {h: {"verdict": "not_testable"} for h in ("X1", "X2", "X3", "X4", "X5")}
    res["hypotheses"] = H
    res["run"] = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({h: v["verdict"] for h, v in H.items()}), res["run"])


if __name__ == "__main__":
    main()
