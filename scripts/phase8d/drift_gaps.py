"""Phase 8d, Mission 3: calibration gaps and drift (DEVELOPMENT data; ToN_IoT retrospective).

1. Gap curve: false-alert rate of the deployed policy (A) and of LightGBM with a local threshold
   (E_local, leave-one-capture-out) on benign evaluation windows, binned by hours since the end
   of calibration; pooled over development captures. KS distance between the calibration
   held-out scores and the benign evaluation scores per bin.
2. Aged calibration: the same with only the EARLIEST half of the calibration windows (the
   calibration is older relative to every evaluation window).
3. Natural long gap: NF-UNSW development data by calendar day (22/23 Jan vs 18 Feb 2015).
4. Safety policies over the evaluation timeline of each capture:
   P0 reuse thresholds indefinitely;
   P1 expiry: no alerts (state `unsupported`) once a window ends > T h after calibration;
   P2 drift suspension: an unlabelled monitor over the last 120 windows (alert rate > 3x target
      with binomial p < 0.01) sets `drift_suspected` and suppresses alerts from then on.
   Reported: false alerts avoided and attack windows / attackers lost vs P0.
RETROSPECTIVE: the ToN_IoT calibration/evaluation score shift (explanation only).
Usage: uv run --extra torch python scripts/phase8d/drift_gaps.py
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import polars as pl
from scipy.stats import binom, ks_2samp

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "phase8c"))
sys.path.insert(0, str(HERE.parents[0] / "phase8b"))
import scorers as S  # noqa: E402, N812
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import agg, crossfit, thr  # noqa: E402

from netsentinel.behavior.profile import _zs, conformal_threshold  # noqa: E402

DEV = Path("data/derived/phase8b")
TON = Path("data/derived/phase8c_external/toniot")
OUT = Path("reports/phase8d/drift_gaps.json")
BINS = [0, 1, 2, 4, 8, 16, 10_000]
T = 0.01


def robust(cal, ev):
    prof, Zh, _, _ = crossfit(cal)
    sh = agg(Zh, "top2")
    return sh, agg(_zs(prof, ev), "top2"), thr(sh)


def lgbm(model, cal, ev):
    sc = model.predict_proba(S._x(cal))[:, 1]
    hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
    t, _ = conformal_threshold(sc[hold], T)
    return sc[hold], model.predict_proba(S._x(ev))[:, 1], t


def timeline(d: dict, cal: pl.DataFrame, model) -> dict | None:
    ev, tr = d["eval_clean"], d["truth"]
    if cal.height < 60 or not ev.height:
        return None
    cal_end = int(cal["window_end_ms"].max())
    e = with_truth(ev.select("key", "win", "window_end_ms"), tr).with_columns(
        ((pl.col("window_end_ms") - cal_end) / 3.6e6).alias("gap_h"))  # fmt: skip
    out = {"cal_end_ms": cal_end, "gap_h": e["gap_h"].to_numpy(), "y": e["y"].to_numpy(),
           "key": np.array(e["key"].to_list(), dtype=object), "end": e["window_end_ms"].to_numpy()}  # fmt: skip
    out["robust"] = robust(cal, ev)
    out["lgbm"] = lgbm(model, cal, ev)
    return out


def gap_curve(tls: dict, fam: str) -> list[dict]:
    rows = []
    for lo, hi in zip(BINS[:-1], BINS[1:], strict=True):
        fa = n = 0
        ks = []
        for t in tls.values():
            hs, se, th = t[fam]
            m = (t["gap_h"] >= lo) & (t["gap_h"] < hi) & ~t["y"]
            fa += int((se[m] > th).sum())
            n += int(m.sum())
            if m.sum() >= 30:
                ks.append(ks_2samp(hs, se[m]).statistic)
        rows.append({"gap_h": f"[{lo},{hi})", "benign_windows": n,
                     "fpr": fa / n if n else None,
                     "median_ks_vs_calibration": float(np.median(ks)) if ks else None,
                     "captures_with_ks": len(ks)})  # fmt: skip
    return rows


def policies(tls: dict, fam: str, attackers: dict) -> dict:
    out = {}
    for name in ("P0", "P1_4h", "P1_8h", "P1_24h", "P2_drift"):
        fa = att_w = 0
        det = n_att = 0
        for cap, t in tls.items():
            hs, se, th = t[fam]
            alert = se > th
            order = np.argsort(t["end"], kind="stable")
            active = np.ones(len(se), bool)
            if name.startswith("P1"):
                active = t["gap_h"] <= float(name.split("_")[1][:-1])
            elif name == "P2_drift":
                a_sorted = alert[order]
                suspended_from = None
                for i in range(120, len(a_sorted) + 1):
                    k = int(a_sorted[i - 120 : i].sum())
                    if k / 120 > 3 * T and binom.sf(k - 1, 120, T) < 0.01:
                        suspended_from = i
                        break
                if suspended_from is not None:
                    act = np.ones(len(se), bool)
                    act[order[suspended_from:]] = False
                    active = act
            a = alert & active
            fa += int((a & ~t["y"]).sum())
            att_w += int((a & t["y"]).sum())
            for ent in attackers[cap]:
                m = (t["key"] == ent) & t["y"]
                if m.any():
                    n_att += 1
                    det += bool(a[m].any())
        out[name] = {"false_alerts": fa, "attack_windows_alerted": att_w,
                     "attackers_detected": f"{det}/{n_att}"}  # fmt: skip
    return out


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    data = {n: load(DEV / n) for n in names}

    def src(excl):
        return [{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"], "truth": data[o]["truth"]}
                for o in names if o != excl and data[o]["cal_clean"].height]  # fmt: skip

    models = {n: S.lgbm_fit(src(n), False)[0] for n in names}
    tls, aged = {}, {}
    for n in names:
        d = data[n]
        t = timeline(d, d["cal_clean"], models[n])
        if t:
            tls[n] = t
        cal = d["cal_clean"]
        if cal.height >= 120:
            w = np.sort(cal["win"].unique().to_numpy())
            early = cal.filter(pl.col("win") <= int(w[len(w) // 2]))
            t2 = timeline(d, early, models[n])
            if t2:
                aged[n] = t2
    attackers = {n: list(data[n]["meta"]["first_attack_ms"]) for n in names}
    res = {"role": "development (exploratory)",
           "gap_curve": {f: gap_curve(tls, f) for f in ("robust", "lgbm")},
           "aged_calibration_gap_curve": {f: gap_curve(aged, f) for f in ("robust", "lgbm")},
           "policies": {f: policies(tls, f, attackers) for f in ("robust", "lgbm")}}  # fmt: skip
    # natural long gap: NF-UNSW by calendar day
    u = tls.get("NF-UNSW-NB15-v3-dev")
    if u:
        day = np.array(
            [datetime.fromtimestamp(x / 1000, UTC).strftime("%Y-%m-%d") for x in u["end"]]
        )
        rows = {}
        for dd in sorted(set(day)):
            m = (day == dd) & ~u["y"]
            rows[dd] = {f: {"benign_windows": int(m.sum()),
                            "fpr": float((u[f][1][m] > u[f][2]).mean()) if m.any() else None,
                            "ks_vs_calibration": float(ks_2samp(u[f][0], u[f][1][m]).statistic)
                            if m.sum() >= 30 else None} for f in ("robust", "lgbm")}  # fmt: skip
        res["nf_unsw_by_day"] = rows
    # RETROSPECTIVE: ToN_IoT score shift between calibration and evaluation
    if (TON / "meta.json").exists():
        excl = {"CTU-IoT-Malware-Capture-49-1", "NF-UNSW-NB15-v3-dev"}
        keep = [o for o in names if o not in excl and data[o]["cal_clean"].height]
        model = S.lgbm_fit([{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"],
                             "truth": data[o]["truth"]} for o in keep], False)[0]  # fmt: skip
        d = load(TON)
        t = timeline(d, d["cal_clean"], model)
        b = ~t["y"]
        res["retrospective_toniot"] = {
            f: {"fpr": float((t[f][1][b] > t[f][2]).mean()),
                "ks_benign_eval_vs_calibration_heldout": float(ks_2samp(t[f][0], t[f][1][b]).statistic),
                "median_gap_h": float(np.median(t["gap_h"]))}
            for f in ("robust", "lgbm")}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "role"}, indent=1, default=str)[:6000])


if __name__ == "__main__":
    main()
