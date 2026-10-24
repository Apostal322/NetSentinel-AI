"""Phase 8d, Mission 2: why does good ranking not give attacker-level detection?
Operating-point comparison on DEVELOPMENT data (rule: docs/phase8d/DEVELOPMENT_LOG.md).

Per capture and policy: window PR-AUC, window recall, FPR, false alerts/h, attacker recall,
and the decomposition of the gap between ranking and detection:
* oracle: recall and attacker recall at the threshold that gives exactly 1% FPR on the
  capture's own benign evaluation windows (ranking quality only; not achievable in practice);
* threshold misplacement: realised FPR vs target, actual vs oracle recall;
* attacker heterogeneity: attack windows per attacker, share of the largest attacker;
* ranking-undetectable attackers: max attack-window score below the oracle 1% threshold.
A RETROSPECTIVE section explains the consumed ToN_IoT result (labelled; no choices).
Usage: uv run --extra torch python scripts/phase8d/operating_points.py
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score as ap

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "phase8c"))
sys.path.insert(0, str(HERE.parents[0] / "phase8b"))
import scorers as S  # noqa: E402, N812
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import agg, crossfit, private, robust_policies  # noqa: E402

from netsentinel.behavior.calibrate import calibrate_windows  # noqa: E402
from netsentinel.behavior.profile import conformal_threshold  # noqa: E402

DEV = Path("data/derived/phase8b")
TON = Path("data/derived/phase8c_external/toniot")
OUT = Path("reports/phase8d/operating_points.json")
T = 0.01
ORDER = ["A", "B", "C", "C2", "E_local", "E_source", "E_device", "E_c2"]


def lgbm_scores(model, cal, ev):
    sc = model.predict_proba(S._x(cal))[:, 1]
    se = model.predict_proba(S._x(ev))[:, 1]
    hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
    return sc, se, hold


def lgbm_policies(model, src_thr, cal, ev):
    sc, se, hold = lgbm_scores(model, cal, ev)
    t_loc, _ = conformal_threshold(sc[hold], T)
    out = {"E_local": (se / max(t_loc, 1e-12), se > t_loc),
           "E_source": (se / max(src_thr, 1e-12), se > src_thr)}  # fmt: skip
    kh = np.array(cal["key"].to_list(), dtype=object)[hold]
    ke = np.array(ev["key"].to_list(), dtype=object)
    td = np.full(len(se), t_loc)
    for k in set(ke):
        m = kh == k
        if m.sum() >= 100:
            td[ke == k] = conformal_threshold(sc[hold][m], T)[0]
    out["E_device"] = (se / np.maximum(td, 1e-12), se > td)
    ph = np.array([private(k) for k in kh])
    pe = np.array([private(k) for k in ke])
    tc = np.full(len(se), t_loc)
    for g in (True, False):
        if (ph == g).any():
            tc[pe == g] = conformal_threshold(sc[hold][ph == g], T)[0]
    out["E_c2"] = (se / np.maximum(tc, 1e-12), se > tc)
    reliable = int(hold.sum()) >= 100
    return out, reliable, se


def robust_reliable(cal) -> bool:
    lp = calibrate_windows({"device": cal}, 0, target_fpr=T, min_windows=30,
                           mode="vetted_benign", threshold_method="crossfit")["device"]  # fmt: skip
    warned = any("WITHOUT an own profile" in w for w in lp.warnings)
    return bool(lp.threshold_diag.get("reliable")) and not warned


def analyse(d: dict, model, src_thr) -> dict | None:
    cal, ev, tr = d["cal_clean"], d["eval_clean"], d["truth"]
    if cal.height < 60 or not ev.height:
        return None
    hours = d["meta"]["eval_hours"]
    attackers = set(d["meta"]["first_attack_ms"])
    e = with_truth(ev.select("key", "win"), tr)
    y = e["y"].to_numpy()
    keys = np.array(e["key"].to_list(), dtype=object)
    pol = dict(robust_policies(cal, ev))
    pol = {k: pol[k] for k in ("A", "B", "C", "C2")}
    lp, l_rel, raw_l = lgbm_policies(model, src_thr, cal, ev)
    pol.update(lp)
    prof, Zh, kh, oh = crossfit(cal)
    from netsentinel.behavior.profile import _zs

    raw_r = agg(_zs(prof, ev), "top2")
    r_rel = robust_reliable(cal)
    per_att = {a: int(((keys == a) & y).sum()) for a in attackers}
    per_att = {a: n for a, n in per_att.items() if n}
    out = {"benign_windows": int((~y).sum()), "attack_windows": int(y.sum()), "hours": hours,
           "attackers_with_attack_windows": len(per_att),
           "largest_attacker_share": max(per_att.values()) / y.sum() if y.sum() else None,
           "attack_windows_per_attacker": sorted(per_att.values(), reverse=True)[:10],
           "reliable": {"robust": r_rel, "lgbm": l_rel}, "policies": {}}  # fmt: skip
    for name, (norm, alert) in pol.items():
        m = {"fpr": float(alert[~y].mean()) if (~y).any() else None,
             "false_alerts_per_h": float((alert & ~y).sum() / hours) if hours else None,
             "window_recall": float(alert[y].mean()) if y.any() else None,
             "attackers_detected": sum(bool((alert & y & (keys == a)).any()) for a in per_att)}  # fmt: skip
        if 0 < y.sum() < len(y):
            m["pr_auc"] = float(ap(y.astype(int), norm))
        out["policies"][name] = m
    # oracle decomposition for the two score families
    for fam, raw in (("robust", raw_r), ("lgbm", raw_l)):
        if (~y).sum() >= 30 and y.any():
            t1 = float(np.quantile(raw[~y], 0.99))
            det = [a for a in per_att if (raw[(keys == a) & y] > t1).any()]
            out[f"oracle_{fam}"] = {"window_recall_at_1pct_fpr": float((raw[y] > t1).mean()),
                                    "attackers_detectable_at_1pct_fpr": len(det),
                                    "ranking_undetectable_attackers": len(per_att) - len(det)}  # fmt: skip
    return out


def summarise(rows: dict) -> dict:
    out = {}
    for p in ORDER:
        for abst in (False, True):
            name = p + ("+abst" if abst else "")
            fam = "robust" if p in ("A", "B", "C", "C2") else "lgbm"
            fprs, fah, det, n, cov = [], [], 0, 0, 0
            prs = []
            for r in rows.values():
                n += r["attackers_with_attack_windows"]
                if abst and not r["reliable"][fam]:
                    continue
                cov += 1
                m = r["policies"][p]
                det += m["attackers_detected"]
                if r["benign_windows"] >= 30:
                    fprs.append(m["fpr"])
                    fah.append(m["false_alerts_per_h"])
                if (
                    m.get("pr_auc") is not None
                    and r["attack_windows"] >= 5
                    and r["benign_windows"] >= 30
                ):
                    prs.append(m["pr_auc"])
            out[name] = {"attackers_detected": f"{det}/{n}", "attacker_recall": det / n if n else None,
                         "captures_covered": f"{cov}/{len(rows)}",
                         "max_fpr": max(fprs) if fprs else None,
                         "median_false_alerts_per_h": float(np.median(fah)) if fah else None,
                         "max_false_alerts_per_h": max(fah) if fah else None,
                         "mean_pr_auc": float(np.mean(prs)) if prs else None,
                         "within_budget": bool(fprs) and max(fprs) <= 0.03 and float(np.median(fah)) <= 1.0}  # fmt: skip
    return out


def select(summ: dict) -> str | None:
    names = [p + s for p in ORDER for s in ("", "+abst")]
    ok = [n for n in names if summ[n]["within_budget"]]
    return max(ok, key=lambda n: (summ[n]["attacker_recall"] or 0, -names.index(n))) if ok else None


def main() -> None:
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    data = {n: load(DEV / n) for n in names}

    def src(excl):
        return [{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"], "truth": data[o]["truth"]}
                for o in names if o != excl and data[o]["cal_clean"].height]  # fmt: skip

    dev = {}
    for n in names:
        model, src_thr = S.lgbm_fit(src(n), False)
        r = analyse(data[n], model, src_thr)
        if r:
            dev[n] = r
    summ = summarise(dev)
    res = {"rule": "docs/phase8d/DEVELOPMENT_LOG.md", "development": dev, "summary": summ,
           "selected": select(summ)}  # fmt: skip
    # RETROSPECTIVE explanation of the consumed ToN_IoT result (no choices)
    if (TON / "meta.json").exists():
        excl = {"CTU-IoT-Malware-Capture-49-1", "NF-UNSW-NB15-v3-dev"}
        keep = [o for o in names if o not in excl and data[o]["cal_clean"].height]
        srcs = [{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"], "truth": data[o]["truth"]}
                for o in keep]  # fmt: skip
        model, src_thr = S.lgbm_fit(srcs, False)
        d = load(TON)
        r = analyse(d, model, src_thr)
        ton_net = ipaddress.ip_network("192.168.159.0/24")
        att = list(d["meta"]["first_attack_ms"])
        tagged = [a for a in att if ipaddress.ip_address(a) in ton_net
                  and 30 <= int(a.split(".")[-1]) <= 39]  # fmt: skip
        r["label_structure"] = {"sources_with_attack_flows": len(att),
                                "of_which_documented_attacker_ips_192_168_159_30_39": len(tagged),
                                "other_sources_with_attack_labelled_flows": len(att) - len(tagged)}  # fmt: skip
        res["retrospective_toniot"] = r
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for k, v in summ.items():
        print(f"{k:14s} {v}")
    print("selected:", res["selected"])
    if "retrospective_toniot" in res:
        r = res["retrospective_toniot"]
        print("TON (retrospective):", {k: r[k] for k in ("attackers_with_attack_windows", "largest_attacker_share",
              "attack_windows_per_attacker", "label_structure", "oracle_robust", "oracle_lgbm")})  # fmt: skip


if __name__ == "__main__":
    main()
