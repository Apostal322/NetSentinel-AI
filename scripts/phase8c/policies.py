"""Phase 8c: decision-policy comparison on DEVELOPMENT data (rule: docs/phase8c/DEVELOPMENT_LOG.md).

All policies share the deployed device-level profile (per-device median/MAD with pooled
fallback, cross-fit held-out scores). They differ only in score aggregation and in how the
1%-FPR threshold is allocated:
  A  deployed: one conformal threshold over all held-out windows (top-2 |z|)
  B  per-device thresholds for devices with >= 100 own held-out windows, else group (C)
  C  Mondrian: separate thresholds for windows scored by an own profile vs the pooled fallback
  C2 Mondrian by address class: private/link-local vs external source addresses
  D1/D3/Dall  top-1 / top-3 / mean |z| aggregation, deployed threshold method
  E  LightGBM (leave-one-capture-out over development captures), local split-conformal
  F_or  C or E (each at 0.5%);  F_and  C and E (each at 1%)
The consumed Phase 8b captures are evaluated in a separate, RETROSPECTIVE section (LightGBM
trained on all development captures, as in Phase 8b); they are explanation, not validation.

Usage: uv run --extra torch python scripts/phase8c/policies.py -> reports/phase8c/policies.json
"""

from __future__ import annotations

import ipaddress
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
import scorers as S  # noqa: E402, N812
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402

from netsentinel.behavior.profile import (  # noqa: E402
    LevelProfile,
    _fit_stats,
    _zs,
    conformal_threshold,
)
from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("reports/phase8c/policies.json")
DEV = Path("data/derived/phase8b")
FRESH = Path("data/derived/phase8b_fresh")
RETRO = ["CTU-IoT-Malware-Capture-1-1", "CTU-IoT-Malware-Capture-60-1",
         "CTU-IoT-Malware-Capture-9-1"]  # fmt: skip
T = 0.01
POLICIES = ["A", "B", "C", "C2", "D1", "D3", "Dall", "E", "F_or", "F_and"]


def private(a: str) -> bool:
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local


def agg(Z: np.ndarray, kind: str) -> np.ndarray:  # noqa: N803
    a = np.sort(np.abs(Z), axis=1)[:, ::-1]
    if kind == "mean":
        return a.mean(axis=1)
    k = {"top1": 1, "top2": 2, "top3": 3}[kind]
    return a[:, :k].mean(axis=1)


def crossfit(cal: pl.DataFrame, folds: int = 5):
    """Deployed cross-fit: held-out Z matrices with keys and scope; final profile on all."""
    wins = np.sort(cal["win"].unique().to_numpy())
    Zs, keys, own = [], [], []
    for block in np.array_split(wins, folds):
        inside = pl.col("win").is_between(int(block[0]), int(block[-1]))
        train, test = cal.filter(~inside), cal.filter(inside)
        tmp = LevelProfile(level="device")
        tmp.keys, tmp.pooled, _, _ = _fit_stats(train, 30, "vetted_benign", 2)
        if tmp.pooled is not None and test.height:
            Zs.append(_zs(tmp, test))
            ks = test["key"].to_list()
            keys += ks
            own += [k in tmp.keys for k in ks]
    prof = LevelProfile(level="device")
    prof.keys, prof.pooled, _, _ = _fit_stats(cal, 30, "vetted_benign", 2)
    return prof, np.vstack(Zs), np.array(keys, dtype=object), np.array(own)


def thr(s: np.ndarray, t: float = T) -> float:
    return conformal_threshold(s, t)[0] if len(s) else math.inf


def robust_policies(cal: pl.DataFrame, ev: pl.DataFrame, target: float = T):
    """Returns {policy: (normalised score = score / applicable threshold, alert)}."""
    prof, Zh, kh, oh = crossfit(cal)
    Ze = _zs(prof, ev)
    ke = np.array(ev["key"].to_list(), dtype=object)
    oe = np.array([k in prof.keys for k in ke])
    pe = np.array([private(k) for k in ke])
    ph = np.array([private(k) for k in kh])
    out = {}
    for name, kind in (("A", "top2"), ("D1", "top1"), ("D3", "top3"), ("Dall", "mean")):
        sh, se = agg(Zh, kind), agg(Ze, kind)
        t = thr(sh, target)
        out[name] = (se / t, se > t)
    sh, se = agg(Zh, "top2"), agg(Ze, "top2")
    t_all = thr(sh, target)

    def mondrian(gh, ge):
        tt = np.full(len(se), t_all)
        for g in (True, False):
            if (gh == g).any():
                tt[ge == g] = thr(sh[gh == g], target)
        return tt

    tc = mondrian(oh, oe)
    out["C"] = (se / tc, se > tc)
    tc2 = mondrian(ph, pe)
    out["C2"] = (se / tc2, se > tc2)
    tb = tc.copy()
    for k in set(ke[oe]):
        m = kh == k
        if m.sum() >= 100:
            tb[ke == k] = thr(sh[m], target)
    out["B"] = (se / tb, se > tb)
    return out


def lgbm_policy(model, cal: pl.DataFrame, ev: pl.DataFrame, target: float = T):
    xe, xc = S._x(ev), S._x(cal)
    se = model.predict_proba(xe)[:, 1]
    hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
    t, _ = conformal_threshold(model.predict_proba(xc[hold])[:, 1], target)
    return se / max(t, 1e-12), se > t


def metrics(ev, tr, norm, alert, hours, first_attack) -> dict:
    from sklearn.metrics import average_precision_score

    d = with_truth(ev.select("key", "win", "window_end_ms"), tr).with_columns(
        pl.Series("alert", alert))  # fmt: skip
    y = d["y"].to_numpy()
    a = alert
    out = {"windows": len(y), "attack_windows": int(y.sum()), "benign_windows": int((~y).sum())}
    out["fpr"] = float(a[~y].mean()) if (~y).any() else None
    out["false_alerts_per_h"] = float((a & ~y).sum() / hours) if hours else None
    out["window_recall"] = float(a[y].mean()) if y.any() else None
    out["precision"] = float((a & y).sum() / a.sum()) if a.sum() else None
    if 0 < y.sum() < len(y) and norm is not None:
        out["pr_auc"] = float(average_precision_score(y.astype(int), norm))
    det, obs = 0, []
    first_win = {k: int(v) for k, v in d.filter(pl.col("y")).group_by("key")
                 .agg(pl.col("window_end_ms").min()).iter_rows()}  # fmt: skip
    for ent in first_attack:
        hit = d.filter((pl.col("key") == ent) & pl.col("alert") & pl.col("y"))
        if hit.height:
            det += 1
            if ent in first_win:
                obs.append((int(hit["window_end_ms"].min()) - first_win[ent]) / 1000)
    out["attackers"] = len(first_attack)
    out["attackers_detected"] = det
    out["observable_delays_s"] = obs
    return out


def evaluate(d: dict, model) -> dict:
    cal, ev, tr = d["cal_clean"], d["eval_clean"], d["truth"]
    hours, fa = d["meta"]["eval_hours"], d["meta"]["first_attack_ms"]
    if cal.height < 60 or not ev.height:
        return {"status": "too few windows"}
    rp = robust_policies(cal, ev)
    rp_half = robust_policies(cal, ev, T / 2)
    e_norm, e_alert = lgbm_policy(model, cal, ev)
    e_half_norm, e_half = lgbm_policy(model, cal, ev, T / 2)
    pol = dict(rp)
    pol["E"] = (e_norm, e_alert)
    pol["F_or"] = (np.maximum(rp_half["C"][0], e_half_norm), rp_half["C"][1] | e_half)
    pol["F_and"] = (np.minimum(rp["C"][0], e_norm), rp["C"][1] & e_alert)
    return {p: metrics(ev, tr, n, a, hours, fa) for p, (n, a) in pol.items()}


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [max(0.0, c - h), min(1.0, c + h)]


def summarise(rows: dict) -> dict:
    out = {}
    for p in POLICIES:
        ms = [r[p] for r in rows.values() if isinstance(r, dict) and p in r]
        ben = [m for m in ms if m["benign_windows"] >= 30]
        fprs = [m["fpr"] for m in ben]
        fah = [m["false_alerts_per_h"] for m in ben if m["false_alerts_per_h"] is not None]
        k = sum(m["attackers_detected"] for m in ms)
        n = sum(m["attackers"] for m in ms)
        elig = [m for m in ms if m.get("pr_auc") is not None and m["attack_windows"] >= 5
                and m["benign_windows"] >= 30]  # fmt: skip
        delays = [x for m in ms for x in m["observable_delays_s"]]
        wr = [m["window_recall"] for m in elig]
        out[p] = {"attackers_detected": f"{k}/{n}", "attacker_recall": k / n if n else None,
                  "attacker_recall_ci95": wilson(k, n),
                  "max_fpr": max(fprs) if fprs else None,
                  "median_fpr": float(np.median(fprs)) if fprs else None,
                  "median_false_alerts_per_h": float(np.median(fah)) if fah else None,
                  "max_false_alerts_per_h": max(fah) if fah else None,
                  "mean_window_recall": float(np.mean(wr)) if wr else None,
                  "mean_pr_auc": float(np.mean([m["pr_auc"] for m in elig])) if elig else None,
                  "median_observable_delay_s": float(np.median(delays)) if delays else None,
                  "within_budget": bool(fprs) and max(fprs) <= 0.03
                  and (float(np.median(fah)) if fah else 0) <= 1.0}  # fmt: skip
    return out


def select(summ: dict) -> str | None:
    order = {
        p: i for i, p in enumerate(["A", "B", "C", "C2", "D1", "D3", "Dall", "E", "F_or", "F_and"])
    }
    base = summ["A"]["mean_pr_auc"] or 0
    ok = [p for p, v in summ.items() if v["within_budget"]
          and (v["mean_pr_auc"] is None or v["mean_pr_auc"] >= base - 0.02)]  # fmt: skip
    if not ok:
        return None
    return max(ok, key=lambda p: (summ[p]["attacker_recall"] or 0, -order[p]))


def main() -> None:
    t0 = time.perf_counter()
    names = [n for n in dev_captures() if (DEV / n / "meta.json").exists()]
    data = {n: load(DEV / n) for n in names}

    def src(exclude):
        return [{"cal": data[o]["cal_clean"], "ev": data[o]["eval_clean"], "truth": data[o]["truth"]}
                for o in names if o != exclude and data[o]["cal_clean"].height]  # fmt: skip

    dev = {}
    for n in names:
        model, _ = S.lgbm_fit(src(n), False)
        dev[n] = evaluate(data[n], model)
        r = dev[n]
        if "A" in r:
            print(
                n, {p: (r[p]["attackers_detected"], round(r[p]["fpr"] or 0, 4)) for p in POLICIES}
            )
    summ = summarise(dev)
    chosen = select(summ)
    model_all, _ = S.lgbm_fit(src(None), False)
    retro = {}
    for n in RETRO:
        p = FRESH / n
        if (p / "meta.json").exists():
            retro[n] = evaluate(load(p), model_all)
    rsumm = summarise(retro)
    res = {"rule": "docs/phase8c/DEVELOPMENT_LOG.md section 2", "development": {"per_capture": dev,
           "summary": summ, "selected": chosen},
           "retrospective_consumed_captures": {"note": "explanation only, not validation",
                                               "per_capture": retro, "summary": rsumm},
           "meta": {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb()}}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for title, s in (("DEVELOPMENT", summ), ("RETROSPECTIVE (consumed)", rsumm)):
        print(f"== {title}")
        for p, v in s.items():
            print(f"  {p:6s} attackers={v['attackers_detected']:6s} recall_ci={v['attacker_recall_ci95']} "
                  f"maxFPR={v['max_fpr']} medFA/h={v['median_false_alerts_per_h']} maxFA/h={v['max_false_alerts_per_h']} "
                  f"wrec={v['mean_window_recall']} prauc={v['mean_pr_auc']} delay={v['median_observable_delay_s']} budget={v['within_budget']}")  # fmt: skip
    print("selected (development):", chosen, res["meta"])


if __name__ == "__main__":
    main()
