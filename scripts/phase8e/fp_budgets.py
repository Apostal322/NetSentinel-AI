"""Phase 8e M4: false-positive budgets per population on DEVELOPMENT data.
Rule (declared before any result): docs/phase8e/FP_BUDGETS.md. No consumed capture is read.

Scoring is the deployed one (robust per-key median/MAD, top-2 |z|, cross-fit held-out
calibration scores, scripts/phase8c/policies.crossfit); policies differ only in thresholds:
  Z never alert;  A one 1% threshold per level;  P one 1% threshold per device population;
  H per-population false-alerts-per-hour budget;  HX = H with external_transient abstaining.
Usage: uv run python scripts/phase8e/fp_budgets.py -> reports/phase8e/fp_budgets.json
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
sys.path.insert(0, str(ROOT / "scripts" / "phase8c"))
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import agg, crossfit, private, wilson  # noqa: E402

from netsentinel.behavior.profile import _zs, conformal_threshold  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

DEV = Path("data/derived/phase8b")
POP = Path("data/derived/phase8e")
OUT = Path("reports/phase8e/fp_budgets.json")
T = 0.01
BUDGET = {"local": 1.0, "external_transient": 0.5, "external_profiled": 0.5, "global": 0.5,
          "service": 1.0}  # fmt: skip
DEVICE_POPS = ("local", "external_transient", "external_profiled")
POLICIES = ("Z", "A", "P", "H", "HX")


def thr(s: np.ndarray, a: float) -> tuple[float, bool]:
    return conformal_threshold(s, a) if len(s) else (math.inf, False)


def cal_hours(cal: pl.DataFrame) -> float:
    w = cal["win"]
    return float((int(w.max()) - int(w.min()) + 1) * 30 / 3600)


def scores(cal: pl.DataFrame, ev: pl.DataFrame):
    prof, Zh, kh, oh = crossfit(cal)  # noqa: N806
    ke = np.array(ev["key"].to_list(), dtype=object)
    oe = np.array([k in prof.keys for k in ke])
    return agg(Zh, "top2"), kh, oh, agg(_zs(prof, ev), "top2"), ke, oe


def device_groups(keys: np.ndarray, own: np.ndarray) -> dict[str, np.ndarray]:
    loc = np.array([private(k) for k in keys], dtype=bool)
    return {"local": loc, "external_transient": ~loc & ~own, "external_profiled": ~loc & own}


def policy_thresholds(sh, gh: dict, ge: dict, hours_cal: float, n_eval: int):
    """-> {policy: (threshold per eval window, covered mask, unreliable-threshold count)}."""
    t_all, rel_all = thr(sh, T)
    wph_all = len(sh) / hours_cal if hours_cal else math.inf
    out = {"Z": (np.full(n_eval, math.inf), np.ones(n_eval, bool), 0),
           "A": (np.full(n_eval, t_all), np.ones(n_eval, bool), int(not rel_all))}  # fmt: skip
    for name in ("P", "H"):
        tt, bad = np.full(n_eval, t_all), 0
        for g, me in ge.items():
            mh = gh[g]
            if name == "P":
                t, rel = thr(sh[mh], T) if mh.any() else (t_all, rel_all)
            else:
                b = BUDGET[g]
                if mh.any():
                    a = min(T, b / (mh.sum() / hours_cal)) if hours_cal else T
                    t, rel = thr(sh[mh], a)
                else:  # population absent from calibration: whole-level scores, its budget
                    t, rel = thr(sh, min(T, b / wph_all))
                t = max(t, thr(sh[mh], T)[0] if mh.any() else t_all)
            tt[me] = t
            bad += int(me.any() and not rel)
        out[name] = (tt, np.ones(n_eval, bool), bad)
    tt, cov, bad = out["H"]
    cov = cov.copy()
    if "external_transient" in ge:
        cov[ge["external_transient"]] = False
    out["HX"] = (tt, cov, bad)
    return out


def measure(ev, tr, se, t, cov, mask, hours, attackers=None) -> dict:
    d = with_truth(ev.select("key", "win", "window_end_ms"), tr)
    y = d["y"].to_numpy().astype(bool)[mask]
    end = d["window_end_ms"].to_numpy()[mask]
    keys = np.array(d["key"].to_list(), dtype=object)[mask]
    c = cov[mask]
    a = (se[mask] > t[mask]) & c
    m = {"windows": int(mask.sum()), "benign_windows": int((~y).sum()),
         "attack_windows": int(y.sum()), "coverage": float(c.mean()) if len(c) else None,
         "false_alerts": int((a & ~y).sum()),
         "false_alerts_per_h": float((a & ~y).sum() / hours) if hours else None,
         "fpr": float(a[~y].mean()) if (~y).any() else None,
         "attack_windows_detected": int((a & y).sum()),
         "window_recall": float(a[y].mean()) if y.any() else None}  # fmt: skip
    delays = []
    if attackers is not None:
        ents = sorted({k for k in keys[y] if k in attackers})
        det = []
        for k in ents:
            mk = keys == k
            if (a & y & mk).any():
                det.append(k)
                delays.append((end[a & y & mk].min() - end[y & mk].min()) / 1000)
        m["attackers"], m["attackers_detected"] = len(ents), len(det)
    elif y.any() and (a & y).any():
        delays.append((end[a & y].min() - end[y].min()) / 1000)
    m["delays_s"] = [float(x) for x in delays]
    return m


def analyse(name: str) -> dict | None:
    dev = load(DEV / name)
    hours = dev["meta"]["eval_hours"]
    attackers = set(dev["meta"]["first_attack_ms"])
    res: dict = {"eval_hours": hours, "levels": {}}
    cal, ev = dev["cal_clean"], dev["eval_clean"]
    if cal.height < 60 or not ev.height:
        return None
    sh, kh, oh, se, ke, oe = scores(cal, ev)
    gh, ge = device_groups(kh, oh), device_groups(ke, oe)
    pol = policy_thresholds(sh, gh, ge, cal_hours(cal), len(se))
    res["levels"]["device"] = {
        p: {"unreliable_thresholds": bad,
            "coverage": float(cov.mean()),
            **{g: measure(ev, dev["truth"], se, t, cov, ge[g], hours, attackers)
               for g in DEVICE_POPS}}
        for p, (t, cov, bad) in pol.items()}  # fmt: skip
    for level in ("global", "service"):
        p_dir = POP / level / name
        if not (p_dir / "meta.json").exists():
            res["levels"][level] = {"status": "windows not built"}
            continue
        d = load(p_dir)
        cal, ev = d["cal_clean"], d["eval_clean"]
        if cal.height < 60 or not ev.height:
            res["levels"][level] = {"status": "too few windows"}
            continue
        sh, _, _, se, _, _ = scores(cal, ev)
        one = np.ones(len(se), bool)
        g = {level: np.ones(len(sh), bool)}
        pol = policy_thresholds(sh, g, {level: one}, cal_hours(cal), len(se))
        res["levels"][level] = {p: {"unreliable_thresholds": bad,
                                    level: measure(ev, d["truth"], se, t, cov, one, hours)}
                                for p, (t, cov, bad) in pol.items()}  # fmt: skip
    return res


def summarise(rows: dict) -> dict:
    out: dict = {}
    for p in POLICIES:
        s: dict = {"populations": {}}
        att, det, aw, awd, covs = 0, 0, 0, 0, []
        for pop in (*DEVICE_POPS, "global", "service"):
            lvl = "device" if pop in DEVICE_POPS else pop
            fah, ms, unrel = [], [], 0
            for r in rows.values():
                lv = r["levels"].get(lvl, {})
                if p not in lv:
                    continue
                m = lv[p][pop]
                ms.append(m)
                unrel += lv[p]["unreliable_thresholds"] if pop in (DEVICE_POPS[0], lvl) else 0
                if r["eval_hours"] >= 1 and m["benign_windows"] >= 30:
                    fah.append(m["false_alerts_per_h"])
            a_tot = sum(m["attack_windows"] for m in ms)
            a_det = sum(m["attack_windows_detected"] for m in ms)
            delays = [x for m in ms for x in m["delays_s"]]
            e = {"captures": len(ms), "captures_budget_eligible": len(fah),
                 "median_false_alerts_per_h": float(np.median(fah)) if fah else None,
                 "max_false_alerts_per_h": float(max(fah)) if fah else None,
                 "pooled_window_recall": a_det / a_tot if a_tot else None,
                 "attack_windows": a_tot, "median_delay_s": float(np.median(delays)) if delays
                 else None, "unreliable_thresholds": unrel}  # fmt: skip
            b = BUDGET[pop]
            e["budget"] = b
            e["within_budget"] = (not fah) or (e["median_false_alerts_per_h"] <= b
                                               and e["max_false_alerts_per_h"] <= 3 * b)  # fmt: skip
            if pop in DEVICE_POPS:
                pa = sum(m["attackers"] for m in ms)
                pd_ = sum(m["attackers_detected"] for m in ms)
                e["attackers_detected"] = f"{pd_}/{pa}"
                att, det, aw, awd = att + pa, det + pd_, aw + a_tot, awd + a_det
            s["populations"][pop] = e
        for r in rows.values():
            covs.append(r["levels"]["device"][p]["coverage"])
        lo, hi = wilson(det, att) if att else (None, None)
        s["device"] = {"attackers_detected": f"{det}/{att}",
                       "attacker_recall": det / att if att else None,
                       "attacker_recall_ci95": [lo, hi],
                       "pooled_window_recall": awd / aw if aw else None,
                       "median_coverage": float(np.median(covs)) if covs else None}  # fmt: skip
        s["sum_median_false_alerts_per_h"] = float(sum(
            e["median_false_alerts_per_h"] or 0 for e in s["populations"].values()))  # fmt: skip
        out[p] = s
    return out


def apply_rule(summ: dict) -> dict:
    ref = summ["A"]["device"]
    verdict = {}
    for p, s in summ.items():
        budget = all(e["within_budget"] for e in s["populations"].values())
        d = s["device"]
        nondeg = (d["median_coverage"] is not None and d["median_coverage"] >= 0.8
                  and (d["attacker_recall"] or 0) >= 0.5 * (ref["attacker_recall"] or 0)
                  and (d["pooled_window_recall"] or 0) >= 0.5 * (ref["pooled_window_recall"] or 0)
                  and (d["attacker_recall"] or 0) > 0)  # fmt: skip
        verdict[p] = {"budget_met": budget, "non_degenerate": nondeg, "passes": budget and nondeg}
    ok = [p for p in summ if verdict[p]["passes"]]
    sel = (max(ok, key=lambda p: (summ[p]["device"]["attacker_recall"] or 0,
                                  -summ[p]["sum_median_false_alerts_per_h"])) if ok else None)  # fmt: skip
    return {
        "per_policy": verdict,
        "selected": sel,
        "status": "development candidate only; no default change (FP_BUDGETS.md rule 4)",
    }


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    rows, skipped = {}, []
    for n in names:
        r = analyse(n)
        if r is None:
            skipped.append(n)
        else:
            rows[n] = r
        print(n, "skipped" if r is None else "ok", flush=True)
    summ = summarise(rows)
    res = {"rule": "docs/phase8e/FP_BUDGETS.md", "role": "development (no consumed capture)",
           "budgets_false_alerts_per_h": BUDGET, "skipped_too_few_windows": skipped,
           "summary": summ, "rule_outcome": apply_rule(summ), "captures": rows,
           "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for p, s in summ.items():
        print(p, json.dumps(s["device"]), res["rule_outcome"]["per_policy"][p])
        for pop, e in s["populations"].items():
            print("   ", pop, {k: e[k] for k in ("median_false_alerts_per_h",
                                                  "max_false_alerts_per_h", "pooled_window_recall",
                                                  "within_budget", "unreliable_thresholds")})  # fmt: skip
    print("selected:", res["rule_outcome"]["selected"])


if __name__ == "__main__":
    main()
