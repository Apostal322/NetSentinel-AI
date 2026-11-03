"""Phase 8o Experiment D analysis: the registered decisions of docs/phase8o/PREREGISTRATION.md
(H1, H1b, H2, C1), the descriptive H3/H4/H5 measures and the exploratory C4. No model is fitted.

Inputs:
- the per-member scores in data/derived/phase8o/experiment_d;
- the evaluation labels and entities of Phase 8n (`analyze_fragility.Labels`: Phase 8j B0
  windows);
- for C2 and C4, the saved P1x windows.

Output: reports/phase8o/experiment_d.json
Usage: python scripts/phase8o/analyze_d.py
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8n_analyze", ROOT / "scripts/phase8n/analyze_fragility.py"
)
AF = importlib.util.module_from_spec(_spec)
sys.modules["phase8n_analyze"] = AF
_spec.loader.exec_module(AF)

ED = ROOT / "data" / "derived" / "phase8o" / "experiment_d"
P1X = ROOT / "data" / "derived" / "phase8j" / "p1x"
OUT = ROOT / "reports" / "phase8o" / "experiment_d.json"
ALPHA = 0.01
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
STRONG = ("nfbot/all", "nfcic/2018-02-14", "nfcic/2018-02-16", "nfcic/2018-02-21",
          "nfton/all", "nfunsw/all")  # fmt: skip
LEVELS = (1, 20, 50)  # entity detected: >= 1 window, >= 20 %, >= 50 % of its attack windows
REPS = (6, 7, 8)
ARMS = {"F0": ("base", "stress"), "F1": ("base", "stress"), "F4": ("base", "stress"),
        "F2": ("base",), "F5": ("base",)}  # fmt: skip
KS = (1, 2, 3, 5)
FAMILY = {
    "nfcic/2018-02-14": "ssh_bruteforce",
    "nfcic/2018-02-16": "dos_hulk",
    "nfcic/2018-02-20": "ddos_loic_http",
    "nfcic/2018-02-21": "ddos_hoic",
    "nfcic/2018-02-22": "web_bruteforce/xss/sql_injection",
    "nfcic/2018-03-02": "bot",
    "nfunsw/all": "9 families",
    "nfton/all": "password/xss/backdoor/ransomware/mitm",
    "nfbot/all": "dos/ddos/theft",
}  # fmt: skip (Phase 8n compare_candidates.FAMILY)
HOUR_MS = 3_600_000
C4_MARGIN = 0.10  # exploratory


def k_of(n: int) -> int:
    return min(n, math.ceil((n + 1) * (1 - ALPHA)))


def t0_of(s_hold: np.ndarray) -> float:
    return float(np.sort(s_hold)[k_of(s_hold.size) - 1])


def entity_detected(frac: float, n_windows: int, level: int) -> bool:
    if level == 1:
        return frac * n_windows >= 1 - 1e-9
    return frac >= level / 100 - 1e-12


def metrics(lab, s_hold: np.ndarray, s_ev: np.ndarray, hours: float,
            assessed: np.ndarray | None = None, t0: float | None = None) -> dict:  # fmt: skip
    """Window and entity measures at T0. With `assessed`, unassessed windows never alert."""
    t0 = t0_of(s_hold) if t0 is None else t0
    alert = s_ev > t0
    if assessed is not None:
        alert &= assessed
    y, ben = lab.y, lab.benign
    q99 = float(np.quantile(s_ev[ben], 1 - ALPHA)) if ben.any() else math.inf
    frac = {e: float(alert[m].mean()) for e, m in lab.masks.items()}
    nwin = {e: int(m.sum()) for e, m in lab.masks.items()}
    rank_frac = {e: float((s_ev[m] > q99).mean()) for e, m in lab.masks.items()}
    margin = {e: float(np.median(s_ev[m]) - t0) for e, m in lab.masks.items()}
    delays = [float(lab.end[alert & m].min() - lab.end[m].min()) / 1000
              for e, m in lab.masks.items() if (alert & m).any()]  # fmt: skip
    fa = int((alert & ben).sum())
    return {"t0": t0, "fpr": float(alert[ben].mean()) if ben.any() else None,
            "false_alerts": fa, "false_alerts_per_h": fa / hours if hours else None,
            "window_recall": float(alert[y].mean()) if y.any() else None,
            "ranking_recall_at_benign_q99": float((s_ev[y] > q99).mean()) if y.any() else None,
            "auc": AF.auc(s_ev[y], s_ev[ben]), "entity_frac": frac, "entity_windows": nwin,
            "entity_rank_frac": rank_frac, "entity_margin": margin,
            "median_delay_s": float(np.median(delays)) if delays else None,
            "attack_windows_unassessed": int((y & ~assessed).sum()) if assessed is not None else 0,
            "windows_assessed_share": float(assessed.mean()) if assessed is not None else 1.0}  # fmt: skip


def summarise(per_fit: dict[tuple, dict[str, dict]]) -> dict:
    """per_fit: fit id -> domain -> metrics. Network means, macro, R/U/N per level, collapses."""
    nets = {}
    for net in NETWORKS:
        rows = [m for per in per_fit.values() for n, m in per.items() if n.startswith(net + "/")]

        def val(k: str, rows: list = rows) -> float | None:
            v = [m[k] for m in rows if m[k] is not None]
            return float(np.mean(v)) if v else None

        nets[net] = {"recall": val("window_recall"), "fa": val("false_alerts"), "fpr": val("fpr"),
                     "fa_per_h": val("false_alerts_per_h"), "auc": val("auc"),
                     "ranking_recall": val("ranking_recall_at_benign_q99"),
                     "delay_s": val("median_delay_s"),
                     "recall_min": min((m["window_recall"] for m in rows if m["window_recall"] is not None), default=None),
                     "recall_max": max((m["window_recall"] for m in rows if m["window_recall"] is not None), default=None)}  # fmt: skip
    rec = [v["recall"] for v in nets.values() if v["recall"] is not None]
    out = {"networks": nets, "macro_recall": float(np.mean(rec)),
           "worst_network_recall": float(np.min(rec)), "R": {}, "U": {}, "N": {}}  # fmt: skip
    domains = sorted({n for per in per_fit.values() for n in per})
    for lv in LEVELS:
        r = u = nn = 0
        for name in domains:
            ents = next(iter(per_fit.values()))[name]["entity_frac"]
            for e in ents:
                v = [entity_detected(per[name]["entity_frac"][e], per[name]["entity_windows"][e], lv)
                     for per in per_fit.values()]  # fmt: skip
                r, u, nn = r + all(v), u + (any(v) and not all(v)), nn + (not any(v))
        out["R"][lv], out["U"][lv], out["N"][lv] = r, u, nn
    out["collapses"] = sum(1 for per in per_fit.values() for n in STRONG
                           if n in per and (per[n]["window_recall"] or 0) < 0.2)  # fmt: skip
    out["fits"] = len(per_fit)
    out["per_domain"] = {}
    for name in domains:
        rec = [per[name]["window_recall"] for per in per_fit.values()]
        out["per_domain"][name] = {
            "family": FAMILY.get(name),
            "mean": float(np.mean(rec)),
            "min": float(np.min(rec)),
            "max": float(np.max(rec)),
            "fa_mean": float(np.mean([per[name]["false_alerts"] for per in per_fit.values()])),
            "fpr_mean": float(np.mean([per[name]["fpr"] for per in per_fit.values()])),
        }
    return out


# ---------------------------------------------------------------- registered decisions


def guardrails(c: dict, ref: dict) -> dict:
    g = {"recall_by_network": {n: c["networks"][n]["recall"] >= ref["networks"][n]["recall"] - 0.05
                               for n in NETWORKS},
         "fa_by_network": {n: c["networks"][n]["fa"] <= 1.10 * ref["networks"][n]["fa"] for n in NETWORKS},
         "R20": c["R"][20] >= ref["R"][20] - 2, "U20": c["U"][20] <= ref["U"][20] + 2,
         "collapses": c["collapses"] <= ref["collapses"]}  # fmt: skip
    g["all"] = bool(all(g["recall_by_network"].values()) and all(g["fa_by_network"].values())
                    and g["R20"] and g["U20"] and g["collapses"])  # fmt: skip
    return g


def decide_h1(f0: dict, f1: dict, f4: dict, r3_ok: bool) -> dict:
    """PREREGISTRATION section 4 (also H1b with base-only summaries)."""
    delta = float(np.mean([abs(f4["networks"][n]["recall"] - f0["networks"][n]["recall"])
                           for n in NETWORKS]))  # fmt: skip
    eps = max(abs(f4["networks"][n]["fa"] / f0["networks"][n]["fa"] - 1) for n in NETWORKS)
    res = {"noise_recall_delta": delta, "noise_fa_eps": eps, "r3_ok": r3_ok,
           "macro_recall_change": f1["macro_recall"] - f0["macro_recall"]}  # fmt: skip
    if not r3_ok or delta >= 0.05:
        return {**res, "verdict": "NOT EVALUABLE"}
    g = guardrails(f1, f0)
    path_r = res["macro_recall_change"] >= max(0.02, 2 * delta)
    cut = 1 - max(0.20, 2 * eps)
    fa_drop = {n: f1["networks"][n]["fa"] <= cut * f0["networks"][n]["fa"] for n in NETWORKS}
    path_f = sum(fa_drop.values()) >= 2 and res["macro_recall_change"] >= -0.01
    ok = g["all"] and (path_r or path_f)
    return {**res, "guardrails": g, "path_R": path_r, "path_F": path_f, "fa_drop_cut": cut,
            "fa_drop_by_network": fa_drop, "verdict": "SUPPORTED" if ok else "NOT SUPPORTED"}  # fmt: skip


def decide_h2(by_k: dict[int, dict]) -> dict:
    """PREREGISTRATION section 5."""
    d = {lv: by_k[1]["U"][lv] - by_k[5]["U"][lv] for lv in (1, 20)}
    informative = [lv for lv, v in d.items() if v >= 3]
    res = {"delta_U": d, "informative": informative}
    if not informative:
        return {**res, "selected_K": 5, "verdict": "NOT EVALUABLE"}
    checks = {}
    for k in (2, 3):
        c, ref = by_k[k], by_k[5]
        ck = {
            f"keeps_75pct_U{lv}": by_k[1]["U"][lv] - c["U"][lv] >= 0.75 * d[lv]
            for lv in informative
        }
        ck["R20"] = c["R"][20] >= ref["R"][20] - 1
        ck["collapses"] = c["collapses"] <= ref["collapses"]
        ck["recall"] = all(
            c["networks"][n]["recall"] >= ref["networks"][n]["recall"] - 0.02 for n in NETWORKS
        )
        ck["fa"] = all(c["networks"][n]["fa"] <= 1.10 * ref["networks"][n]["fa"] for n in NETWORKS)
        ck["preserves"] = bool(all(ck.values()))
        checks[k] = ck
    sel = next((k for k in (2, 3) if checks[k]["preserves"]), 5)
    return {**res, "checks": checks, "selected_K": sel,
            "verdict": f"K = {sel} preserves M2's benefit" if sel < 5 else "K = 5 retained"}  # fmt: skip


def decide_c1(t0: dict, c1: dict) -> dict:
    """PREREGISTRATION section 6."""
    closer = {n: abs(c1["networks"][n]["fpr"] - ALPHA) < abs(t0["networks"][n]["fpr"] - ALPHA)
              for n in NETWORKS}  # fmt: skip
    keep = {n: c1["networks"][n]["recall"] >= t0["networks"][n]["recall"] - 0.05
            for n in NETWORKS if t0["networks"][n]["fpr"] <= 2 * ALPHA}  # fmt: skip
    r20 = c1["R"][20] >= t0["R"][20] - 2
    ok = sum(closer.values()) >= 3 and all(keep.values()) and r20
    return {"fpr_closer_to_alpha": closer, "recall_kept_where_fpr_le_2alpha": keep, "R20": r20,
            "verdict": "SUPPORTED" if ok else "NOT SUPPORTED"}  # fmt: skip


# ---------------------------------------------------------------- data


def domains() -> list[str]:
    return sorted(
        p.name.split("__seed0")[0].replace("__", "/") for p in AF.B0_DIR.glob("*__seed0.npz")
    )


def hours_of(name: str) -> float:
    return float(np.load(AF.B0_DIR / f"{name.replace('/', '__')}__seed0.npz")["hours"])


def load(arm: str, regime: str, r: int, name: str) -> dict | None:
    f = ED / arm / regime / f"{name.replace('/', '__')}__r{r}.npz"
    return dict(np.load(f)) if f.exists() else None


def windows_context(name: str, lab) -> dict:
    """C2 (hold-out host-hour blocks) and C4 (trailing novelty) inputs, aligned to the labels."""
    net, dom = name.split("/")
    cal = pl.read_parquet(P1X / net / dom / "cal_p1x.parquet",
                          columns=["key", "win", "window_end_ms", "new_dst_frac"]).sort("win", "key")  # fmt: skip
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    hold = cal.filter(pl.col("win") >= lo + int(math.floor((hi - lo + 1) * 0.7)))
    blocks = hold.select("key", (pl.col("window_end_ms") // HOUR_MS)).unique().height
    z = np.load(AF.B0_DIR / f"{name.replace('/', '__')}__seed0.npz")
    order = pl.DataFrame({"key": z["ev_key"].astype(str), "win": z["ev_win"]})
    ev = pl.read_parquet(
        P1X / net / dom / "eval_p1x.parquet", columns=["key", "win", "new_dst_frac"]
    )
    ev = order.join(ev, on=["key", "win"], how="left", maintain_order="left")
    nov = (ev["new_dst_frac"].to_numpy() > 0).astype(float)
    end = lab.end
    # trailing share of novel windows that ENDED in the previous hour (strictly before this one)
    o = np.argsort(end, kind="stable")
    e_sorted, cum = end[o], np.concatenate([[0.0], np.cumsum(nov[o])])
    lo_i = np.searchsorted(e_sorted, end - HOUR_MS, side="left")
    hi_i = np.searchsorted(e_sorted, end, side="left")
    cnt = hi_i - lo_i
    trail = np.where(cnt > 0, (cum[hi_i] - cum[lo_i]) / np.maximum(cnt, 1), 0.0)
    hold_rate = float((hold["new_dst_frac"].to_numpy() > 0).mean())
    return {"blocks": blocks, "hold_novel_rate": hold_rate,
            "c4_assessed": trail <= hold_rate + C4_MARGIN}  # fmt: skip


def ens(z: dict, key: str, members: tuple[int, ...]) -> np.ndarray:
    return z[key][list(members)].mean(0)


def arm_fits(arm: str, labels: dict, members: tuple[int, ...], regimes=None,
             hold_key: str = "s_hold", ev_key: str = "s_ev", ctx: dict | None = None,
             gate: str | None = None) -> dict | None:  # fmt: skip
    per_fit = {}
    for regime in regimes or ARMS[arm]:
        for r in REPS:
            per = {}
            for name, lab in labels.items():
                z = load(arm, regime, r, name)
                if z is None:
                    return None
                assessed = None
                if gate == "C2" and ctx[name]["blocks"] < 1 / ALPHA:
                    assessed = np.zeros(lab.y.size, bool)
                elif gate == "C4":
                    assessed = ctx[name]["c4_assessed"]
                per[name] = metrics(lab, ens(z, hold_key, members), ens(z, ev_key, members),
                                    hours_of(name), assessed)  # fmt: skip
            per_fit[(regime, r)] = per
    return per_fit


def entity_table(per_fit: dict) -> dict:
    """H3: per entity, over the given fits."""
    out = {}
    first = next(iter(per_fit.values()))
    for name, m in first.items():
        for e in m["entity_frac"]:
            fr = [per[name]["entity_frac"][e] for per in per_fit.values()]
            rk = [per[name]["entity_rank_frac"][e] for per in per_fit.values()]
            mg = [per[name]["entity_margin"][e] for per in per_fit.values()]
            fail_thr = sum(1 for a, b in zip(fr, rk, strict=True) if a < 0.2 and b >= 0.5)
            fail_rank = sum(1 for a, b in zip(fr, rk, strict=True) if a < 0.2 and b < 0.2)
            out[f"{name}|{e}"] = {"windows": m["entity_windows"][e],
                                  "det_ge1": float(np.mean([entity_detected(f, m["entity_windows"][e], 1) for f in fr])),
                                  "det_ge20": float(np.mean([f >= 0.2 for f in fr])),
                                  "det_ge50": float(np.mean([f >= 0.5 for f in fr])),
                                  "recall_min": float(min(fr)), "recall_median": float(np.median(fr)),
                                  "margin_min": float(min(mg)), "margin_median": float(np.median(mg)),
                                  "failures_threshold": fail_thr, "failures_ranking": fail_rank}  # fmt: skip
    return out


def main() -> None:
    labels = {n: AF.Labels(n) for n in domains()}
    meta = {}
    for name in labels:
        net, dom = name.split("/")
        mf = ROOT / "data" / "derived" / "phase8o" / "aligned" / net / dom / "meta.json"
        meta[name] = json.loads(mf.read_text("utf-8")) if mf.exists() else None
    r3 = all(m is None or all(c["max_abs_diff"] == 0 and c["missing"] == 0
                              for k, c in m["checks"].items() if k.startswith(("f3", "f1_before", "c1_before")))
             for m in meta.values())  # fmt: skip
    all5 = tuple(range(5))
    res: dict = {"status": "REGISTERED DEVELOPMENT (Experiment D); consumed development networks",
                 "r3_feature_rebuild_exact": r3, "arms": {}}  # fmt: skip
    fits = {}
    for arm in ARMS:
        f = arm_fits(arm, labels, all5)
        if f is None:
            print(arm, "incomplete")
            continue
        fits[arm] = f
        res["arms"][arm] = summarise(f)
    if {"F0", "F1", "F4"} <= set(fits):
        res["H1"] = decide_h1(res["arms"]["F0"], res["arms"]["F1"], res["arms"]["F4"], r3)
    if {"F0", "F4", "F5"} <= set(fits):
        base = {
            a: summarise({k: v for k, v in fits[a].items() if k[0] == "base"}) for a in ("F0", "F4")
        }
        res["H1b"] = decide_h1(base["F0"], res["arms"]["F5"], base["F4"], True)
        res["F2_vs_F0_base"] = {"macro_recall_change": res["arms"]["F2"]["macro_recall"] - base["F0"]["macro_recall"],
                                "F0_base": base["F0"]} if "F2" in fits else None  # fmt: skip
    if "F0" in fits:
        by_k = {k: summarise(arm_fits("F0", labels, tuple(range(k)))) for k in KS}
        res["H2"] = {"by_K": by_k, "decision": decide_h2(by_k)}
        spread = {}
        for k in (1, 2, 3):
            subs = [
                summarise(arm_fits("F0", labels, c)) for c in itertools.combinations(range(5), k)
            ]
            spread[k] = {"subsets": len(subs),
                         "U1": [s["U"][1] for s in subs], "U20": [s["U"][20] for s in subs],
                         "macro_recall": [round(s["macro_recall"], 4) for s in subs]}  # fmt: skip
        res["H2"]["subset_spread_exploratory"] = spread
        ctx = {n: windows_context(n, labels[n]) for n in labels}
        cal = {"T0": res["arms"]["F0"], "C1": summarise(arm_fits("F0", labels, all5, hold_key="s_hold_c1")),
               "C3": summarise(arm_fits("F0", labels, all5, hold_key="s_hold_u", ev_key="s_ev_u")),
               "C2": summarise(arm_fits("F0", labels, all5, ctx=ctx, gate="C2")),
               "C4_exploratory": summarise(arm_fits("F0", labels, all5, ctx=ctx, gate="C4"))}  # fmt: skip
        cal_k1 = {
            "T0": by_k[1],
            "C1": summarise(arm_fits("F0", labels, (0,), hold_key="s_hold_c1")),
        }
        res["H4"] = {"K5": cal, "K1": cal_k1, "C1_decision": decide_c1(cal["T0"], cal["C1"]),
                     "C2_blocks": {n: c["blocks"] for n, c in ctx.items()},
                     "C4_assessed_share": {n: float(c["c4_assessed"].mean()) for n, c in ctx.items()},
                     "C4_hold_novel_rate": {n: c["hold_novel_rate"] for n, c in ctx.items()}}  # fmt: skip
        singles = {}
        for m in range(5):
            for fid, per in arm_fits("F0", labels, (m,)).items():
                singles[(*fid, m)] = per
        res["H3"] = {"single_member_fits": len(singles), "entities_single": entity_table(singles),
                     "entities_K5": entity_table(fits["F0"]),
                     "single_member_summary": summarise(singles)}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1, default=str).encode())
    for arm, s in res["arms"].items():
        print(arm, "macro", round(s["macro_recall"], 3), "R/U20", s["R"][20], s["U"][20], "U1", s["U"][1],
              "coll", s["collapses"], {n: (round(v["recall"], 3), round(v["fa"])) for n, v in s["networks"].items()})  # fmt: skip
    for k in ("H1", "H1b"):
        if k in res:
            print(k, res[k]["verdict"])
    if "H2" in res:
        print("H2", res["H2"]["decision"]["verdict"], "C1", res["H4"]["C1_decision"]["verdict"])


if __name__ == "__main__":
    main()
