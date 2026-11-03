"""Phase 8p Experiment E analysis: the registered decisions of docs/phase8p/PREREGISTRATION.md.
No model is fitted.

- Source-unit arms (S0 = Phase 8o F0; D2, S1, D2S, Sonly) and the D3 fusion: window and entity
  measures at T0. Entities split by the Stage 1 role audit (documented attackers primary).
- D1 / D1h on victim units: window recall, FPR, victim-host detection, attributed coverage of
  documented attackers.
- Complementarity of S0 and D1.
- H4 calibration scenarios C0-C3 on S0.

Output: reports/phase8p/experiment_e.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8p/analyze_e.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8o_analyze", ROOT / "scripts/phase8o/analyze_d.py"
)
AD = importlib.util.module_from_spec(_spec)
sys.modules["phase8o_analyze"] = AD
_spec.loader.exec_module(AD)
AF = AD.AF

EE = ROOT / "data" / "derived" / "phase8p" / "experiment_e"
F0 = ROOT / "data" / "derived" / "phase8o" / "experiment_d" / "F0"
P1X = ROOT / "data" / "derived" / "phase8j" / "p1x"
I8 = ROOT / "data" / "derived" / "phase8i"
C2 = ROOT / "data" / "derived" / "phase8p" / "c2"
VICTIM = ROOT / "data" / "derived" / "phase8p" / "victim"
CONTACTS = ROOT / "data" / "derived" / "phase8m" / "novelty"
ROLES = ROOT / "reports" / "phase8p" / "observability.json"
OUT = ROOT / "reports" / "phase8p" / "experiment_e.json"
ALPHA, HOUR_MS, W_MS = 0.01, 3_600_000, 30_000
NETWORKS, STRONG, LEVELS, REPS = AD.NETWORKS, AD.STRONG, (1, 20, 50), (6, 7, 8)
SOURCE_ARMS = {"S0": ("base", "stress"), "D2": ("base", "stress"), "S1": ("base", "stress"),
               "D2S": ("base", "stress"), "Sonly": ("base",)}  # fmt: skip
SIMPLICITY = ("D2", "S1", "D2S", "D3")


# ---------------------------------------------------------------- pure functions (tested)


def ecdf(ref: np.ndarray, x: np.ndarray) -> np.ndarray:
    """Share of `ref` values <= x."""
    r = np.sort(ref)
    return np.searchsorted(r, x, side="right") / r.size


def fuse(s_hold, v_hold, s_ev, v_ev) -> tuple[np.ndarray, np.ndarray]:
    """D3: max of the two branches' hold-out empirical CDFs (one shared score, one shared T0)."""
    return (np.maximum(ecdf(s_hold, s_hold), ecdf(v_hold, v_hold)),
            np.maximum(ecdf(s_hold, s_ev), ecdf(v_hold, v_ev)))  # fmt: skip


def host_balanced_t0(scores: np.ndarray, hosts: np.ndarray, alpha: float = ALPHA) -> float:
    """C3: the weighted (1 - alpha) quantile, each hold-out window weighted 1 / (its host's
    windows), so every host has the same total weight."""
    _, inv, cnt = np.unique(hosts, return_inverse=True, return_counts=True)
    w = 1.0 / cnt[inv]
    o = np.argsort(scores, kind="stable")
    cw = np.cumsum(w[o]) / w.sum()
    return float(scores[o][np.searchsorted(cw, 1 - alpha, side="left").clip(max=scores.size - 1)])


def decide(c: dict, ref: dict) -> dict:
    """PREREGISTRATION section 4: guardrails and improvement of candidate `c` against S0."""
    g = {"fa": {n: c["networks"][n]["fa"] <= 1.10 * ref["networks"][n]["fa"] for n in NETWORKS},
         "recall_doc": {n: c["networks"][n]["recall_doc"] >= ref["networks"][n]["recall_doc"] - 0.05 for n in NETWORKS},
         "collapses": c["collapses"] <= ref["collapses"],
         "U20_doc": c["doc"]["U"][20] <= ref["doc"]["U"][20] + 2}  # fmt: skip
    g_ok = (
        all(g["fa"].values()) and all(g["recall_doc"].values()) and g["collapses"] and g["U20_doc"]
    )
    gain_r = c["doc"]["R"][20] - ref["doc"]["R"][20]
    gain_m = c["macro_recall_doc"] - ref["macro_recall_doc"]
    imp = {
        "a_R20_doc_gain": gain_r,
        "a": gain_r >= 3,
        "b_macro_doc_gain": gain_m,
        "b": gain_m >= 0.03,
    }
    return {"guardrails": g, "guardrails_ok": bool(g_ok), "improvement": imp,
            "pass": bool(g_ok and (imp["a"] or imp["b"]))}  # fmt: skip


def verdicts(dec: dict, sonly_macro: float | None, s1_macro: float | None) -> dict:
    h2_ctrl = sonly_macro is not None and s1_macro is not None and sonly_macro < 0.5 * s1_macro
    out = {"H1": "SUPPORTED" if dec.get("D2", {}).get("pass") else "NOT SUPPORTED",
           "H2": "SUPPORTED" if dec.get("S1", {}).get("pass") and h2_ctrl else "NOT SUPPORTED",
           "H2_shortcut_control_ok": bool(h2_ctrl),
           "H3": "SUPPORTED" if dec.get("D3", {}).get("pass") else "NOT SUPPORTED"}  # fmt: skip
    eligible = [x for x in SIMPLICITY if dec.get(x, {}).get("pass") and (x != "S1" or h2_ctrl)]
    out["selected"] = (
        max(eligible, key=lambda x: (dec[x]["R20_doc"], -SIMPLICITY.index(x))) if eligible else None
    )
    out["model_candidate"] = "DEVELOPMENT GO" if eligible else "DEVELOPMENT NO-GO"
    return out


# ---------------------------------------------------------------- measures


def doc_sets(labels: dict) -> dict[str, set[str]]:
    roles = json.loads(ROLES.read_text("utf-8"))["roles"]
    out: dict[str, set[str]] = {n: set() for n in labels}
    for ek, r in roles.items():
        dom, src = ek.split("|")
        if r == "documented_attacker" and dom in out:
            out[dom].add(src)
    return out


def measure(lab, doc: set[str], s_hold, s_ev, hours, t0=None) -> dict:
    m = AD.metrics(lab, s_hold, s_ev, hours, t0=t0)
    yd = lab.y & np.isin(lab.key, np.array(sorted(doc), dtype=str))
    alert = s_ev > m["t0"]
    m["recall_doc"] = float(alert[yd].mean()) if yd.any() else None
    m["doc"] = sorted(doc & set(m["entity_frac"]))
    return m


def summarise(per_fit: dict) -> dict:
    s = AD.summarise(per_fit)
    first = next(iter(per_fit.values()))
    for net in NETWORKS:
        v = [m["recall_doc"] for per in per_fit.values() for n, m in per.items()
             if n.startswith(net + "/") and m["recall_doc"] is not None]  # fmt: skip
        s["networks"][net]["recall_doc"] = float(np.mean(v)) if v else None
    s["macro_recall_doc"] = float(np.mean([s["networks"][n]["recall_doc"] for n in NETWORKS
                                           if s["networks"][n]["recall_doc"] is not None]))  # fmt: skip
    s["doc"] = {"R": {}, "U": {}, "N": {}, "entities": 0}
    det_all20 = {}
    for lv in LEVELS:
        r = u = nn = 0
        for name, m in first.items():
            for e in m["doc"]:
                v = [AD.entity_detected(per[name]["entity_frac"][e], per[name]["entity_windows"][e], lv)
                     for per in per_fit.values()]  # fmt: skip
                r, u, nn = r + all(v), u + (any(v) and not all(v)), nn + (not any(v))
                if lv == 20:
                    det_all20[f"{name}|{e}"] = bool(all(v))
        s["doc"]["R"][lv], s["doc"]["U"][lv], s["doc"]["N"][lv] = r, u, nn
    s["doc"]["entities"] = len(det_all20)
    s["doc_detected_all_fits_20"] = det_all20
    return s


def labels_all() -> dict:
    return {n: AF.Labels(n) for n in AD.domains()}


def arm_fits(
    arm: str, labels: dict, docs: dict, regimes, src_dir=EE, keys=("s_hold", "s_ev")
) -> dict | None:
    per_fit = {}
    for regime in regimes:
        for r in REPS:
            per = {}
            for name, lab in labels.items():
                f = (
                    src_dir / arm / regime / f"{name.replace('/', '__')}__r{r}.npz"
                    if arm
                    else src_dir / regime / f"{name.replace('/', '__')}__r{r}.npz"
                )
                if not f.exists():
                    return None
                z = np.load(f)
                per[name] = measure(
                    lab, docs[name], z[keys[0]].mean(0), z[keys[1]].mean(0), AD.hours_of(name)
                )
            per_fit[(regime, r)] = per
    return per_fit


def hold_keys(name: str, path: Path) -> pl.DataFrame:
    cal = pl.read_parquet(path, columns=["key", "win", "window_end_ms"]).sort("win", "key")
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    return cal.filter(pl.col("win") >= lo + int(math.floor((hi - lo + 1) * 0.7)))


def v_for_source_windows(name: str, vw_idx: pl.DataFrame, v_score: np.ndarray,
                         rows: pl.DataFrame) -> tuple[np.ndarray, int]:  # fmt: skip
    """D3: max D1 score over the responders each source window (key, win) contacted."""
    net, dom = name.split("/")
    c = (
        pl.scan_parquet(str(CONTACTS / net / dom / "contacts_p1x" / "*.parquet"))
        .select("win", "src", "dst")
        .collect()
    )
    vs = vw_idx.select("dst", "win").with_columns(pl.Series("v", v_score))
    m = c.join(vs, on=["dst", "win"], how="left").group_by("src", "win").agg(pl.col("v").max())
    j = rows.select("key", "win").join(
        m.rename({"src": "key"}), on=["key", "win"], how="left", maintain_order="left"
    )
    return j["v"].fill_null(0.0).to_numpy(), int(j["v"].null_count())


def victim_measures(
    name: str, idx: pl.DataFrame, s: np.ndarray, doc: set[str], contacts: pl.DataFrame
) -> dict:
    cal = idx.with_row_index("i").filter((pl.col("period") == "cal") & ~pl.col("noisy"))
    lo, hi = int(cal["win"].min()), int(cal["win"].max())
    hold = cal.filter(
        (pl.col("win") >= lo + int(math.floor((hi - lo + 1) * 0.7))) & (pl.col("attack_flows") == 0)
    )
    ev = idx.with_row_index("i").filter((pl.col("period") == "eval") & ~pl.col("noisy"))
    sh, se = s[hold["i"].to_numpy()], s[ev["i"].to_numpy()]
    t0 = AD.t0_of(sh)
    alert = se > t0
    att = ev["attack_flows"].to_numpy()
    y_any, y_maj, ben = att > 0, att / np.maximum(ev["flows"].to_numpy(), 1) >= 0.5, att == 0
    alerted = ev.filter(pl.Series(alert)).select("dst", "win")
    vic = (
        ev.filter(pl.Series(y_any))
        .with_columns(pl.Series("a", alert[y_any]))
        .group_by("dst")
        .agg(pl.col("a").mean())
    )
    # evaluation-period attack contacts of documented attackers; covered = one falls in an alerted VW
    cov = (contacts.filter(pl.col("src").is_in(sorted(doc)))
           .join(ev.select("dst", "win"), on=["dst", "win"], how="semi")
           .join(alerted.with_columns(pl.lit(True).alias("hit")), on=["dst", "win"], how="left"))  # fmt: skip
    covered = cov.group_by("src").agg(pl.col("hit").any())
    return {"t0": t0, "hold_windows": int(sh.size),
            "recall_any": float(alert[y_any].mean()) if y_any.any() else None,
            "recall_majority": float(alert[y_maj].mean()) if y_maj.any() else None,
            "fpr": float(alert[ben].mean()) if ben.any() else None, "false_alerts": int((alert & ben).sum()),
            "mixed_positive_share": float((att[y_any] < ev["flows"].to_numpy()[y_any]).mean()) if y_any.any() else None,
            "victims": vic.height, "victims_ge1": int((vic["a"] > 0).sum()), "victims_ge20": int((vic["a"] >= 0.2).sum()),
            "doc_attackers_covered": {k: bool(v) for k, v in covered.fill_null(False).iter_rows()},
            "auc": AF.auc(se[y_any], se[ben])}  # fmt: skip


def main() -> None:
    labels = labels_all()
    docs = doc_sets(labels)
    res: dict = {
        "status": "REGISTERED DEVELOPMENT (Experiment E); consumed development networks",
        "arms": {},
    }
    fits = {"S0": arm_fits(None, labels, docs, ("base", "stress"), src_dir=F0)}
    for arm, regs in SOURCE_ARMS.items():
        if arm == "S0":
            continue
        fits[arm] = arm_fits(arm, labels, docs, regs)
    # R1: S0 base refits reproduce Phase 8o F0
    runs = json.loads((ROOT / "reports" / "phase8p" / "experiment_e_runs.json").read_text("utf-8"))[
        "runs"
    ]
    r1 = [v["R1_max_abs_diff_vs_phase8o_F0"] for v in runs.get("S0/base", {}).values()]
    res["R1_max_abs_diff"] = max(r1) if r1 else None
    res["R1_ok"] = bool(r1) and max(r1) == 0.0 and len(r1) == 27
    # D1 / D3
    vidx = {
        n: pl.read_parquet(EE / "_vw_index" / f"{n.replace('/', '__')}.parquet") for n in labels
    }
    acon = {
        n: pl.read_parquet(VICTIM / n.split("/")[0] / n.split("/")[1] / "attacker_contacts.parquet")
        for n in labels
    }
    d1 = {}
    comp = {}
    for arm, regs in (("D1", ("base", "stress")), ("D1h", ("base",))):
        per_fit = {}
        for regime in regs:
            for r in REPS:
                per = {}
                for name in labels:
                    f = EE / arm / regime / f"{name.replace('/', '__')}__r{r}.npz"
                    if not f.exists():
                        per = None
                        break
                    per[name] = np.load(f)["s_vw"].mean(0)
                if per is None:
                    break
                per_fit[(regime, r)] = per
        d1[arm] = per_fit
    vm = {}
    for arm, per_fit in d1.items():
        rows = {}
        for (regime, r), per in per_fit.items():
            rows[f"{regime}_r{r}"] = {
                n: victim_measures(n, vidx[n], per[n], docs[n], acon[n]) for n in labels
            }
        vm[arm] = rows
    res["victim_units"] = vm
    if d1.get("D1") and fits["S0"]:
        per_fit3, cors, jac = {}, [], []
        for (regime, r), per in d1["D1"].items():
            per3 = {}
            for name, lab in labels.items():
                net, dom = name.split("/")
                z = np.load(F0 / regime / f"{name.replace('/', '__')}__r{r}.npz")
                s_hold, s_ev = z["s_hold"].mean(0), z["s_ev"].mean(0)
                hk = hold_keys(name, P1X / net / dom / "cal_p1x.parquet")
                zz = np.load(AF.B0_DIR / f"{name.replace('/', '__')}__seed0.npz")
                evk = pl.DataFrame({"key": zz["ev_key"].astype(str), "win": zz["ev_win"]})
                v_hold, miss_h = v_for_source_windows(name, vidx[name], per[name], hk)
                v_ev, miss_e = v_for_source_windows(name, vidx[name], per[name], evk)
                f_hold, f_ev = fuse(s_hold, v_hold, s_ev, v_ev)
                per3[name] = measure(lab, docs[name], f_hold, f_ev, AD.hours_of(name))
                per3[name]["v_missing"] = miss_h + miss_e
                yd = lab.y & np.isin(lab.key, np.array(sorted(docs[name]), dtype=str))
                if yd.sum() > 2:
                    from scipy.stats import spearmanr

                    cors.append({"fit": f"{regime}_r{r}", "domain": name,
                                 "spearman_s_v_doc_attack": float(spearmanr(s_ev[yd], v_ev[yd]).statistic)})  # fmt: skip
                a0 = (s_ev > AD.t0_of(s_hold)) & lab.benign
                a3 = (f_ev > per3[name]["t0"]) & lab.benign
                jac.append({"fit": f"{regime}_r{r}", "domain": name, "fa_S0": int(a0.sum()), "fa_D3": int(a3.sum()),
                            "fa_both": int((a0 & a3).sum())})  # fmt: skip
            per_fit3[(regime, r)] = per3
        fits["D3"] = per_fit3
        comp = {"spearman": cors, "false_alert_overlap": jac}
    res["complementarity"] = comp
    summ = {a: summarise(f) for a, f in fits.items() if f}
    for a, s in summ.items():
        s.pop("per_domain", None)
        res["arms"][a] = s
    dec = {}
    for x in ("D2", "S1", "D2S", "D3"):
        if x in summ:
            dec[x] = decide(summ[x], summ["S0"])
            dec[x]["R20_doc"] = summ[x]["doc"]["R"][20]
    res["decisions"] = dec
    res["verdicts"] = verdicts(
        dec,
        summ.get("Sonly", {}).get("macro_recall_doc"),
        summ.get("S1", {}).get("macro_recall_doc"),
    )
    if not res["R1_ok"]:
        res["verdicts"]["model_candidate"] = "NOT EVALUABLE (R1 failed)"
    # entity bootstrap of the R20_doc difference
    rng = np.random.default_rng(8)
    boot = {}
    for x in dec:
        a, b = summ[x]["doc_detected_all_fits_20"], summ["S0"]["doc_detected_all_fits_20"]
        ks = sorted(a)
        d = np.array([int(a[k]) - int(b[k]) for k in ks])
        bs = [d[rng.integers(0, d.size, d.size)].sum() for _ in range(2000)]
        boot[x] = {
            "diff": int(d.sum()),
            "ci95": [float(np.quantile(bs, 0.025)), float(np.quantile(bs, 0.975))],
        }
    res["entity_bootstrap_R20_doc_diff"] = boot
    # paired per-fit macro recall_doc differences
    res["paired_macro_doc_diff"] = {x: [float(np.mean([m["recall_doc"] for n, m in fits[x][k].items() if m["recall_doc"] is not None])
                                              - np.mean([m["recall_doc"] for n, m in fits["S0"][k].items() if m["recall_doc"] is not None]))
                                        for k in fits[x]] for x in dec}  # fmt: skip
    res["H4"] = calibration(labels, docs)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1, default=str).encode())
    for a, s in res["arms"].items():
        print(a, "macro_doc", round(s["macro_recall_doc"], 3), "R/U20 doc", s["doc"]["R"][20], s["doc"]["U"][20],
              "coll", s["collapses"], {n: (round(v["recall_doc"] or 0, 3), round(v["fa"])) for n, v in s["networks"].items()})  # fmt: skip
    print(res["verdicts"], res["H4"].get("decision"))


def calibration(labels: dict, docs: dict) -> dict:
    out: dict = {"scenarios": {}}
    sc = {"C0": (F0, ("base", "stress"), ("s_hold", "s_ev")), "C1": (F0, ("base", "stress"), ("s_hold_u", "s_ev_u")),
          "C2": (EE / "S0", ("base",), ("s_hold_c2", "s_ev_c2"))}  # fmt: skip
    per_sc = {}
    for c, (d, regs, keys) in sc.items():
        f = arm_fits(None, labels, docs, regs, src_dir=d, keys=keys)
        if f is not None:
            per_sc[c] = f
    # C3: host-balanced threshold on the unlabelled hold-out
    f3 = {}
    for regime in ("base", "stress"):
        for r in REPS:
            per = {}
            for name, lab in labels.items():
                net, dom = name.split("/")
                z = np.load(F0 / regime / f"{name.replace('/', '__')}__r{r}.npz")
                hk = hold_keys(name, I8 / net / dom / "cal_unlabelled.parquet")
                sh = z["s_hold_u"].mean(0)
                if hk.height != sh.size:
                    raise RuntimeError(f"{name}: unlabelled hold-out keys do not match the scores")
                t0 = host_balanced_t0(sh, hk["key"].to_numpy().astype(str))
                per[name] = measure(
                    lab, docs[name], sh, z["s_ev_u"].mean(0), AD.hours_of(name), t0=t0
                )
            f3[(regime, r)] = per
    per_sc["C3"] = f3
    for c, f in per_sc.items():
        s = summarise(f)
        s.pop("per_domain", None)
        out["scenarios"][c] = {"fits": len(f), "macro_recall_doc": s["macro_recall_doc"], "R20_doc": s["doc"]["R"][20],
                               "networks": {n: {k: s["networks"][n][k] for k in ("recall_doc", "recall", "fpr", "fa", "fa_per_h")}
                                            for n in NETWORKS}}  # fmt: skip
    # hold-out evidence per scenario
    ev_info = {}
    for name in labels:
        net, dom = name.split("/")
        info = {}
        for c, path in (("C0", P1X / net / dom / "cal_p1x.parquet"), ("C1", I8 / net / dom / "cal_unlabelled.parquet"),
                        ("C2", C2 / net / dom / "cal_p1x.parquet")):  # fmt: skip
            if not path.exists():
                continue
            hk = hold_keys(name, path)
            cnt = hk.group_by("key").len()["len"].to_numpy()
            info[c] = {"hold_windows": hk.height, "hosts": int(cnt.size), "top_host_share": round(float(cnt.max() / cnt.sum()), 4),
                       "host_hour_blocks": hk.select("key", (pl.col("window_end_ms") // HOUR_MS)).unique().height}  # fmt: skip
        mid = json.loads((I8 / net / dom / "meta.json").read_text("utf-8"))
        info["calibration_age_h_at_eval_midpoint"] = round(mid.get("eval_hours", 0) / 2, 2)
        c2m = C2 / net / dom / "meta.json"
        if c2m.exists():
            info["C2_known_attackers"] = {
                k: v
                for k, v in json.loads(c2m.read_text("utf-8")).items()
                if k != "unlabelled_attackers"
            }
        ev_info[name] = info
    out["holdout_evidence"] = ev_info
    if {"C0", "C3"} <= set(out["scenarios"]):
        c0, c3 = out["scenarios"]["C0"], out["scenarios"]["C3"]
        ok_r = c3["macro_recall_doc"] >= 0.75 * c0["macro_recall_doc"]
        ok_f = {n: c3["networks"][n]["fpr"] <= c0["networks"][n]["fpr"] + 0.01 for n in NETWORKS}
        out["decision"] = {"recall_kept": ok_r, "fpr_ok": ok_f,
                           "H4": "SUPPORTED" if ok_r and all(ok_f.values()) else "NOT SUPPORTED"}  # fmt: skip
    return out


if __name__ == "__main__":
    main()
