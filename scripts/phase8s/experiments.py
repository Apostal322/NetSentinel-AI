"""Phase 8s registered experiments A-E (docs/phase8s/PREREGISTRATION.md). Saved scores only
(Phase 8o F0 = the frozen M2 construction, 6 fits, K = 5); no model is fitted.

**Information boundary.** A design sees only the unlabelled `Pool` (hosts, window counts, times,
UDP share, destination ports, unlabelled scores). Labels live only in `Reviewer` (simulated
review; ORACLE-SIMULATED from the calibration labels, or, for Experiment E, the audited
evaluation categories of the first half of the evaluation period) and in the metrics.

**Experiments** (all on unlabelled-memory scores; thresholds applied to `s_ev_u`):
- A/B/C: designs × budgets k ∈ {10, 30, 100} expected host reviews × estimators C0/C1/C3,
  perfect reviewer R0, 20 draws.
- D: k = 30, reviewers R1 (p_inc 0.10, e_fb 0.10, e_fm 0.02) and R2 (MNAR: p_inc 0.40 for hosts
  above the 90th activity percentile, else 0.10; e_fb 0.25, e_fm 0.02).
- E: temporal, PPS + C1, k = 30, R0, evaluated on the second half of the evaluation period.

References per fit: U (unlabelled T0), T (oracle benign hold-out T0, unlabelled memory),
P (full oracle, P1x scores).

Outputs (atomic; an existing output is never overwritten):
- reports/phase8s/experiments<tag>.json (aggregates, decisions, provenance);
- data/derived/phase8s/review_log<tag>.npz (candidate IDs, inclusion probabilities and review
  outcomes of the primary cell).
Usage: python scripts/run_capped.py -- <python> scripts/phase8s/experiments.py [--draws 20]
       [--domains a,b] [--tag _x] [--only ABCD|E]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import math
import os
import subprocess
import sys
import time
import zlib
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AB = _load("phase8r_ab", "scripts/phase8r/experiment_ab.py")
AC = _load("phase8s_ac", "scripts/phase8s/active_calibration.py")
FG, BM = AB.FG, AB.BM
OUT = ROOT / "reports" / "phase8s"
LOGS = ROOT / "data" / "derived" / "phase8s"
FITS = AB.FITS
BUDGETS = (10, 30, 100)
PRIMARY = {"design": "pps", "k": 30, "estimator": "C1", "reviewer": "R0"}
BASELINE = {"design": "random_host", "k": 30, "estimator": "C0", "reviewer": "R0"}
REVIEWERS = {"R0": {}, "R1": {"p_inc": 0.10, "e_fb": 0.10, "e_fm": 0.02},
             "R2": {"p_inc": 0.10, "p_inc_heavy": 0.40, "e_fb": 0.25, "e_fm": 0.02}}  # fmt: skip
ESTIMATORS = ("C0", "C1", "C3")
DELAY_MS = 3_600_000
KS_STALE = 0.10


def rng_for(*parts) -> np.random.Generator:
    return np.random.default_rng([zlib.crc32(str(p).encode()) for p in parts])


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    if path.exists():
        raise FileExistsError(f"{path} exists; completed results are never overwritten")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".partial")
    tmp.write_bytes(data)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------- data
class Pool:
    """Label-free view of a population of windows grouped by host (what a design may see)."""

    def __init__(self, key: np.ndarray, end_ms: np.ndarray, udp: np.ndarray, ports: np.ndarray,
                 scores: np.ndarray) -> None:  # fmt: skip
        self.uniq, self.inv, self.n_h = np.unique(key, return_inverse=True, return_counts=True)
        self.end_ms, self.scores = end_ms, scores
        self.hour = end_ms // AC.HOUR_MS
        self.udp, self.ports = udp, ports
        thr = np.quantile(scores, 0.95)
        self.tail_h = np.bincount(
            self.inv, weights=(scores >= thr).astype(float), minlength=self.uniq.size
        )
        med_u = AC_group_median(self.inv, udp, self.uniq.size)
        med_p = AC_group_median(self.inv, ports, self.uniq.size)
        q90 = AC_group_quantile(self.inv, scores, self.uniq.size, 0.9)
        hours = np.unique(np.stack([self.inv, self.hour]), axis=1)
        active = np.bincount(hours[0], minlength=self.uniq.size)
        self.features = np.column_stack([np.log1p(self.n_h), active, med_u, med_p, q90])


def AC_group_median(inv: np.ndarray, x: np.ndarray, n: int) -> np.ndarray:  # noqa: N802
    return AC_group_quantile(inv, x, n, 0.5)


def AC_group_quantile(inv: np.ndarray, x: np.ndarray, n: int, q: float) -> np.ndarray:  # noqa: N802
    o = np.lexsort((x, inv))
    cnt = np.bincount(inv, minlength=n)
    starts = np.r_[0, np.cumsum(cnt)[:-1]]
    idx = starts + np.floor(q * (cnt - 1)).astype(int)
    return x[o][idx]


def load(name: str) -> dict:
    d = AB.load(name)  # Phase 8r loader: hold-out frame, metadata, audit categories, entities
    a = pl.read_parquet(
        BM.AUDIT / f"{name.replace('/', '__')}.parquet", columns=["key", "win", "category"]
    )
    d["ev_win"] = a["win"].to_numpy()
    d["ev_mal_cat"] = ~np.isin(a["category"].to_numpy().astype(str), BM.BENIGN)
    net, dom = name.split("/")
    ev = pl.read_parquet(FG.CD.I8 / net / dom / "eval_unlabelled.parquet",
                         columns=["key", "win", "window_end_ms", "udp_share", "dst_ports"])  # fmt: skip
    j = a.select("key", "win").join(ev, on=["key", "win"], how="left", maintain_order="left")
    if j["window_end_ms"].null_count():
        raise RuntimeError(f"{name}: evaluation windows missing metadata")
    d["ev_end"] = j["window_end_ms"].to_numpy()
    d["ev_udp"] = j["udp_share"].to_numpy().astype(float)
    d["ev_ports"] = j["dst_ports"].to_numpy().astype(float)
    d["inputs"] = [BM.AUDIT / f"{name.replace('/', '__')}.parquet", FG.CD.I8 / net / dom / "cal_unlabelled.parquet",
                   FG.CD.I8 / net / dom / "cal_truth.parquet", FG.CD.I8 / net / dom / "eval_unlabelled.parquet"]  # fmt: skip
    return d


# ----------------------------------------------------------------------------- metrics
class Evaluator(AB.Evaluator):
    """Phase 8r window/entity metrics plus workload diagnostics on a window subset."""

    def __init__(self, d: dict, s_ev: np.ndarray, mask: np.ndarray | None = None) -> None:
        m = np.ones(s_ev.size, bool) if mask is None else mask
        sub = dict(d)
        sub["pos"], sub["neg"] = d["pos"] & m, d["neg"] & m
        sub["ents"] = [(e, em & m) for e, em in d["ents"] if (em & m).sum() >= 5]
        sub["cat"] = np.where(m, d["cat"], "__masked__")
        sub["hours"] = d["hours"] if mask is None else d["hours"] * m.mean()
        super().__init__(sub, s_ev)
        neg = sub["neg"]
        self.neg_s, self.neg_key = s_ev[neg], d["key"][neg]
        end = d["ev_end"][neg]
        self.host_hours = max(
            1,
            np.unique(
                np.char.add(self.neg_key.astype(str), "|" + (end // AC.HOUR_MS).astype(str))
            ).size,
        )

    def full(self, t: float | None) -> dict:
        if t is None:
            return {"abstain": True}
        m = self(t)
        fa = self.neg_s > t
        n_fa = int(fa.sum())
        top = 0.0
        if n_fa:
            _, c = np.unique(self.neg_key[fa], return_counts=True)
            top = float(c.max() / n_fa)
        n_ent = len(self.ents)
        det20 = m["r20"]
        missed = sum(self.above(e, t) == 0 for e in self.ents)
        r50 = sum(self.above(e, t) >= 0.5 * e.size - 1e-9 for e in self.ents)
        m.update({"abstain": False, "fa_per_host_hour": n_fa / self.host_hours, "top_host_fa_share": top,
                  "entities": n_ent, "r50": r50, "missed_entirely": missed,
                  "fa_per_detected_entity": n_fa / det20 if det20 else None})  # fmt: skip
        return m


def calibration_error(s_hold: np.ndarray, benign: np.ndarray, t: float | None) -> float | None:
    """Exceedance of the threshold on the benign hold-out population, minus α (oracle metric)."""
    if t is None:
        return None
    return float((s_hold[benign] > t).mean() - AC.ALPHA)


# ----------------------------------------------------------------------------- one cell
def design_pi(design: str, pool: Pool, k: float) -> np.ndarray | None:
    if design == "random_host":
        return AC.pi_random_host(pool.n_h, k)
    if design == "random_window":
        return AC.pi_random_window(pool.n_h, k)
    if design == "pps":
        return AC.pi_pps(pool.n_h, k)
    if design == "stratified":
        return AC.pi_stratified(pool.n_h, k)
    if design == "tail":
        return AC.pi_tail(pool.n_h, pool.tail_h, k)
    return None  # diversity: deterministic, no design weights


def acquire(
    design: str, pool: Pool, k: float, reviewer: AC.Reviewer, rng: np.random.Generator
) -> dict:
    """Select (label-free), review (simulated), and return the trusted windows with weights."""
    pi = design_pi(design, pool, k)
    window_mask = None
    if design == "diversity":
        sel = AC.select_diverse(pool.features, int(round(k)))
    elif design == "random_window":
        p = AC.window_rate(pool.n_h, k)
        window_mask = rng.random(pool.inv.size) < p
        sel = np.unique(pool.inv[window_mask])
    else:
        sel = AC.poisson_draw(pi, rng)
    out = reviewer.review(sel, rng) if sel.size else np.array([], dtype=int)
    benign = sel[out == AC.BENIGN]
    trusted = np.isin(pool.inv, benign)
    c0_mask = trusted & window_mask if window_mask is not None else trusted
    return {"sel": sel, "out": out, "pi": pi, "trusted": trusted, "c0_mask": c0_mask,
            "malicious_found": int((out == AC.MALICIOUS).sum()), "inconclusive": int((out == AC.INCONCLUSIVE).sum()),
            "benign_verified": int(benign.size)}  # fmt: skip


def estimate(acq: dict, pool: Pool, rng: np.random.Generator) -> dict:
    s, inv = pool.scores, pool.inv
    th: dict = {"C0": None, "C1": None, "C3": None}
    if acq["c0_mask"].any():
        th["C0"] = AC.conformal_t0(s[acq["c0_mask"]])
    diag: dict = {"kish_neff": 0.0, "cluster_neff": 0.0, "weight_cv": None, "tail_hosts": 0}
    tr = acq["trusted"]
    if acq["pi"] is not None and tr.any():
        w = 1.0 / acq["pi"][inv[tr]]
        th["C1"] = AC.hajek(s[tr], w)
        th["C3"] = AC.conservative(s[tr], w, inv[tr], rng, b=100)
        hosts = np.unique(inv[tr])
        diag.update({"kish_neff": AC.kish_neff(w), "cluster_neff": AC.cluster_neff(1 / acq["pi"][hosts], pool.n_h[hosts]),
                     "weight_cv": float(w.std() / w.mean()), **AC.tail_support(s[tr], w, inv[tr], th["C1"])})  # fmt: skip
    return {"th": th, "diag": diag}


def acquisition_stats(acq: dict, pool: Pool, attacker_window: np.ndarray, cost: float) -> dict:
    tr = acq["trusted"]
    w = (
        1.0 / acq["pi"][pool.inv[tr]]
        if acq["pi"] is not None and tr.any()
        else np.ones(int(tr.sum()))
    )
    contam = float((w * attacker_window[tr]).sum() / w.sum()) if tr.any() else None
    prof = (pool.udp > 0.5).astype(int) * 3 + np.digitize(pool.ports, [1.5, 5.5])
    return {"reviews": int(acq["sel"].size), "benign_verified": acq["benign_verified"],
            "malicious_found": acq["malicious_found"], "inconclusive": acq["inconclusive"],
            "review_success": acq["benign_verified"] / acq["sel"].size if acq["sel"].size else None,
            "cost": cost, "trusted_windows": int(tr.sum()), "c0_windows": int(acq["c0_mask"].sum()),
            "trusted_hours": int(np.unique(pool.hour[tr]).size), "service_profiles": int(np.unique(prof[tr]).size),
            "trusted_contamination": contam}  # fmt: skip


# ----------------------------------------------------------------------------- experiments
def run_abcd(names: list[str], data: dict, draws: int, log: dict) -> dict:
    rows: list[dict] = []
    refs: list[dict] = []
    for name in names:
        d = data[name]
        t_dom = time.perf_counter()
        attacker_window = d["is_att"]
        benign = ~attacker_window
        for regime, r in FITS:
            fk = f"{regime}_r{r}"
            z = FG.scores(name, regime, r)
            s = z["s_hold_u"]
            pool = Pool(d["hu_key"], d["hu_end"], d["udp"], d["ports"], s)
            if not np.array_equal(pool.uniq, d["meta"]["uniq"]):
                raise RuntimeError("host order differs from the Phase 8r metadata")
            ev, ev_p = Evaluator(d, z["s_ev_u"]), Evaluator(d, z["s_ev"])
            t_u, t_t = AC.conformal_t0(s), AC.conformal_t0(s[benign]) if benign.any() else math.inf
            for ref, (e, t, sh, bn) in {"U": (ev, t_u, s, benign), "T": (ev, t_t, s, benign),
                                         "P": (ev_p, AC.conformal_t0(z["s_hold"]), None, None)}.items():  # fmt: skip
                refs.append({"domain": name, "fit": fk, "ref": ref, "draw": 0, "t": t,
                             "cal_error": calibration_error(sh, bn, t) if sh is not None else None, **e.full(t)})  # fmt: skip
            cells = [(dsg, k, "R0") for dsg in AC.DESIGNS for k in BUDGETS]
            cells += [(dsg, 30, rv) for dsg in AC.DESIGNS for rv in ("R1", "R2")]
            heavy = float(np.quantile(pool.n_h, 0.9))
            for dsg, k, rv in cells:
                for dr in range(1 if dsg == "diversity" and rv == "R0" else draws):
                    rng = rng_for(name, fk, dsg, k, rv, dr)
                    reviewer = AC.Reviewer(d["mal_host"], pool.n_h, heavy_n=heavy, **REVIEWERS[rv])
                    acq = acquire(dsg, pool, k, reviewer, rng)
                    est = estimate(acq, pool, rng_for(name, fk, dsg, k, rv, dr, "boot"))
                    stats = acquisition_stats(acq, pool, attacker_window, reviewer.cost)
                    for e in ESTIMATORS:
                        if dsg == "diversity" and e != "C0":
                            continue
                        t = est["th"][e]
                        rows.append({"domain": name, "fit": fk, "design": dsg, "k": k, "reviewer": rv, "estimator": e,
                                     "draw": dr, "t": t, "t_bias": None if t is None else t - t_t,
                                     "cal_error": calibration_error(s, benign, t), **est["diag"], **stats, **ev.full(t)})  # fmt: skip
                    if (dsg, k, rv) == (PRIMARY["design"], PRIMARY["k"], PRIMARY["reviewer"]):
                        log.setdefault("primary", []).append({"domain": name, "fit": fk, "draw": dr,
                                                              "hosts": pool.uniq[acq["sel"]].tolist(),
                                                              "pi": acq["pi"][acq["sel"]].tolist(),
                                                              "outcomes": acq["out"].tolist()})  # fmt: skip
        print(name, "ABCD", round(time.perf_counter() - t_dom, 1), "s", flush=True)
    return {"rows": rows, "refs": refs}


def run_e(names: list[str], data: dict, draws: int) -> list[dict]:
    """Temporal: every cell is evaluated on the second half of the evaluation period."""
    rows = []
    k = PRIMARY["k"]
    for name in names:
        d = data[name]
        win = d["ev_win"]
        mid_win = int(np.median(np.unique(win)))
        second = win >= mid_win
        end_mid = (
            int(d["ev_end"][win == mid_win].min())
            if (win == mid_win).any()
            else int(np.median(d["ev_end"]))
        )
        first = (win < mid_win) & (
            d["ev_end"] <= end_mid - DELAY_MS
        )  # reviewable before the switch
        hold_recent = d["hu_end"] >= np.median(d["hu_end"])
        for regime, r in FITS:
            fk = f"{regime}_r{r}"
            z = FG.scores(name, regime, r)
            s, sev = z["s_hold_u"], z["s_ev_u"]
            ev2 = Evaluator(d, sev, second)
            ref_t = AC.conformal_t0(s[~d["is_att"]])
            pools = {
                "E0_historical": (Pool(d["hu_key"], d["hu_end"], d["udp"], d["ports"], s), d["is_att"]),
                "E1_recent_half": (Pool(d["hu_key"][hold_recent], d["hu_end"][hold_recent], d["udp"][hold_recent],
                                        d["ports"][hold_recent], s[hold_recent]), d["is_att"][hold_recent]),
                "E2_refresh": (Pool(d["key"][first], d["ev_end"][first], d["ev_udp"][first], d["ev_ports"][first],
                                    sev[first]), d["ev_mal_cat"][first]),
            }  # fmt: skip
            ks = None
            if first.any():
                a, b = np.sort(s), np.sort(sev[first])
                grid = np.r_[a, b]
                ks = float(np.abs(np.searchsorted(a, grid, side="right") / a.size
                                  - np.searchsorted(b, grid, side="right") / b.size).max())  # fmt: skip
            for cell, (pool, att) in pools.items():
                if pool.uniq.size == 0:
                    rows.append(
                        {"domain": name, "fit": fk, "cell": cell, "draw": 0, "abstain": True}
                    )
                    continue
                mal_host = (
                    np.bincount(pool.inv, weights=att.astype(float), minlength=pool.uniq.size) > 0
                )
                for dr in range(draws):
                    rng = rng_for(name, fk, "E", cell, dr)
                    reviewer = AC.Reviewer(mal_host, pool.n_h)
                    acq = acquire(PRIMARY["design"], pool, k, reviewer, rng)
                    est = estimate(acq, pool, rng_for(name, fk, "E", cell, dr, "boot"))
                    t = est["th"]["C1"]
                    rows.append({"domain": name, "fit": fk, "cell": cell, "draw": dr, "t": t, "ks_drift": ks,
                                 **ev2.full(t)})  # fmt: skip
                    if cell == "E0_historical":
                        stale = ks is not None and ks > KS_STALE
                        rows.append({"domain": name, "fit": fk, "cell": "E3_abstain_if_stale", "draw": dr, "t": t,
                                     "ks_drift": ks, **ev2.full(None if stale else t)})  # fmt: skip
            rows.append(
                {
                    "domain": name,
                    "fit": fk,
                    "cell": "T_reference",
                    "draw": 0,
                    "t": ref_t,
                    **ev2.full(ref_t),
                }
            )
        print(name, "E done", flush=True)
    return rows


# ----------------------------------------------------------------------------- aggregation
def net_of(name: str) -> str:
    return name.split("/")[0]


def summarise(df: pl.DataFrame, by: list[str]) -> dict:
    """Per network: means over domains within a fit-draw, then over fit-draws; abstention rate;
    p10/p90 over draws. Abstained rows count as no alerts (recall 0, FPR 0)."""
    df = df.with_columns(
        pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net"),
        pl.col("recall").fill_null(0.0).fill_nan(None),
        pl.col("fpr").fill_null(0.0),
    )  # fmt: skip  (S-1: NaN = no positives, excluded)
    out: dict = {}
    for keyv, g in df.group_by(by, maintain_order=True):
        nets = {}
        for net, gn in g.group_by("net", maintain_order=True):
            per = gn.group_by("fit", "draw").agg(pl.col("recall").mean(), pl.col("fpr").mean(),
                                                  pl.col("abstain").mean().alias("abst"),
                                                  pl.col("cal_error").abs().median().alias("abs_cal_err") if "cal_error" in gn.columns else pl.lit(None).alias("abs_cal_err"),
                                                  pl.col("r20").sum().alias("r20"))  # fmt: skip
            per_draw = per.group_by("draw").agg(pl.col("recall").mean(), pl.col("fpr").mean())
            nets[net[0]] = {"recall": float(per["recall"].mean()), "fpr": float(per["fpr"].mean()),
                            "fpr_p90": float(per_draw["fpr"].quantile(0.9)), "recall_p10": float(per_draw["recall"].quantile(0.1)),
                            "abstention": float(per["abst"].mean()),
                            "median_abs_cal_error": None if per["abs_cal_err"].null_count() == per.height else float(per["abs_cal_err"].median())}  # fmt: skip
        r20 = g.group_by("fit", "draw").agg(pl.col("r20").fill_null(0).sum())["r20"].mean()
        out["|".join(map(str, keyv))] = {"networks": nets, "macro_recall": float(np.mean([v["recall"] for v in nets.values()])),
                                          "mean_R20": float(r20)}  # fmt: skip
    return out


def decide(rows: pl.DataFrame, refs: pl.DataFrame, e_rows: pl.DataFrame | None) -> dict:
    """The registered decision rules (PREREGISTRATION § 8)."""

    def cell(design, k, est, rv):
        return rows.filter((pl.col("design") == design) & (pl.col("k") == k) & (pl.col("estimator") == est)
                           & (pl.col("reviewer") == rv))  # fmt: skip

    def per_net_abs_err(g):
        g = g.with_columns(pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net"),
                           pl.col("cal_error").abs().fill_null(float("inf")).alias("e"))  # fmt: skip
        return {n[0]: float(x["e"].median()) for n, x in g.group_by("net")}

    sref = summarise(refs, ["ref"])
    U, T = sref["U"], sref["T"]
    prim = summarise(cell("pps", 30, "C1", "R0"), ["design"])["pps"]
    base = cell("random_host", 30, "C0", "R0")
    e_p, e_b = per_net_abs_err(cell("pps", 30, "C1", "R0")), per_net_abs_err(base)
    nets = sorted(e_p)
    better = {n: e_p[n] < e_b[n] for n in nets}
    macro_p = float(np.mean([min(e_p[n], 1.0) for n in nets]))
    macro_b = float(np.mean([min(e_b[n], 1.0) for n in nets]))
    h1 = {"median_abs_cal_error_primary": e_p, "median_abs_cal_error_baseline": e_b, "better": better,
          "macro_primary": macro_p, "macro_baseline": macro_b,
          "verdict": "SUPPORTED" if sum(better.values()) >= 3 and macro_p <= 0.5 * macro_b else "NOT SUPPORTED"}  # fmt: skip
    crit = {"i_gain": prim["macro_recall"] - U["macro_recall"] >= 0.10,
            "ii_fpr": all(prim["networks"][n]["fpr"] <= T["networks"][n]["fpr"] + 0.02 for n in prim["networks"]),
            "iii_fpr_p90": all(prim["networks"][n]["fpr_p90"] <= T["networks"][n]["fpr"] + 0.05 for n in prim["networks"]),
            "iv_abstention": all(prim["networks"][n]["abstention"] <= 0.25 for n in prim["networks"])}  # fmt: skip
    hc = {"criteria": crit, "verdict": "SUPPORTED" if all(crit.values()) else "NOT SUPPORTED"}
    r20_gain = prim["mean_R20"] - U["mean_R20"]
    hd = {"R20_gain_over_U": r20_gain,
          "verdict": "DEVELOPMENT GO" if hc["verdict"] == "SUPPORTED" and r20_gain >= 5 else "DEVELOPMENT NO-GO"}  # fmt: skip
    # H2: does the Kish effective size track calibration error better than the verified-host count?
    r0 = rows.filter(
        (pl.col("reviewer") == "R0")
        & (pl.col("estimator") == "C1")
        & pl.col("cal_error").is_not_null()
    )
    r0 = r0.with_columns(pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net"))
    h2 = {}
    for n, g in r0.group_by("net"):
        e = g["cal_error"].abs().rank().to_numpy()
        rho_n = float(np.corrcoef(e, g["kish_neff"].rank().to_numpy())[0, 1])
        rho_h = float(np.corrcoef(e, g["benign_verified"].rank().to_numpy())[0, 1])
        h2[n[0]] = {
            "spearman_neff": rho_n,
            "spearman_hosts": rho_h,
            "neff_stronger": abs(rho_n) > abs(rho_h),
        }
    h2v = "SUPPORTED" if sum(v["neff_stronger"] for v in h2.values()) >= 3 else "NOT SUPPORTED"
    # H3: weighting (C1 vs C0) under PPS, paired on (domain, fit, draw)
    pp = (
        cell("pps", 30, "C1", "R0")
        .select("domain", "fit", "draw", pl.col("cal_error").alias("c1"))
        .join(
            cell("pps", 30, "C0", "R0").select(
                "domain", "fit", "draw", pl.col("cal_error").alias("c0")
            ),
            on=["domain", "fit", "draw"],
        )
    )
    pp = pp.drop_nulls().with_columns((pl.col("c1").abs() - pl.col("c0").abs()).alias("d"),
                                       pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net"))  # fmt: skip
    h3 = {n[0]: float(g["d"].median()) for n, g in pp.group_by("net")}
    h3v = "SUPPORTED" if sum(v < 0 for v in h3.values()) >= 3 else "NOT SUPPORTED"
    # H4: imperfect reviewer R1, primary design
    r1 = cell("pps", 30, "C1", "R1").with_columns(
        pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net")
    )
    contam = {
        n[0]: float(g["trusted_contamination"].fill_null(0).median()) for n, g in r1.group_by("net")
    }
    s1 = summarise(cell("pps", 30, "C1", "R1"), ["design"])["pps"]
    fpr_ok = all(s1["networks"][n]["fpr"] <= T["networks"][n]["fpr"] + 0.02 for n in s1["networks"])
    h4 = {"median_trusted_contamination": contam, "fpr_criterion_ii": fpr_ok,
          "verdict": "SUPPORTED" if all(v <= 0.01 for v in contam.values()) and fpr_ok else "NOT SUPPORTED"}  # fmt: skip
    h5 = None
    if e_rows is not None and e_rows.height:
        er = e_rows.with_columns(pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net"),
                                 (pl.col("fpr").fill_null(0) - AC.ALPHA).abs().alias("dev"))  # fmt: skip
        dev = {
            c[0]: {n[0]: float(g["dev"].median()) for n, g in gc.group_by("net")}
            for c, gc in er.group_by("cell")
        }
        imp = {n: dev["E2_refresh"][n] < dev["E0_historical"][n] for n in dev["E0_historical"]}
        h5 = {"median_abs_fpr_minus_alpha": dev, "E2_better": imp,
              "verdict": "SUPPORTED" if sum(imp.values()) >= 3 else "NOT SUPPORTED"}  # fmt: skip
    return {"H1_representative_sampling": h1, "H_calibration": hc, "H_detection": hd,
            "H2_two_dimensional_budget": {"per_network": h2, "verdict": h2v},
            "H3_weighting": {"median_paired_abs_error_C1_minus_C0": h3, "verdict": h3v},
            "H4_reviewer_error": h4, "H5_temporal": h5}  # fmt: skip


def provenance(names: list[str], data: dict, args: argparse.Namespace) -> dict:
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()
    )
    reg = json.loads((ROOT / "reports/phase8o/experiment_d_scores_sha256.json").read_text("utf-8"))
    scores = {}
    for name in names:
        for regime, r in FITS:
            rel = (
                f"data/derived/phase8o/experiment_d/F0/{regime}/{name.replace('/', '__')}__r{r}.npz"
            )
            h = sha256(ROOT / rel)
            # Amendment S-2 (after review): fail closed; a score file missing from the Phase 8o
            # registry is an error, not a pass (none was missing in the registered run).
            if reg.get(rel) != h:
                raise RuntimeError(
                    f"{rel}: frozen score hash missing from, or differs from, Phase 8o"
                )
            scores[rel] = h
    inputs = {
        str(p.relative_to(ROOT)): sha256(p) for n in names for p in data[n]["inputs"] if p.exists()
    }
    from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: PLC0415

    return {"git_sha": sha, "dirty_tree": dirty, "frozen_scores_sha256": scores, "inputs_sha256": inputs,
            "feature_schema_sha256": hashlib.sha256(json.dumps(list(WINDOW_FEATURES)).encode()).hexdigest(),
            "split": "Phase 8i time split; hold-out = last 30 % of calibration slots", "args": vars(args),
            "label_audit": BM.LA.AUDIT_VERSION}  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--draws", type=int, default=20)
    ap.add_argument("--domains")
    ap.add_argument("--tag", default="")
    ap.add_argument("--only", choices=("ABCD", "E"))
    args = ap.parse_args()
    from netsentinel.resources import peak_rss_mb  # noqa: PLC0415

    t0 = time.perf_counter()
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    if args.domains:
        names = [n for n in names if n in args.domains.split(",")]
    data = {n: load(n) for n in names}
    prov = provenance(names, data, args)
    log: dict = {}
    res: dict = {
        "status": "Phase 8s registered experiments (saved scores; ORACLE-SIMULATED review)",
        "provenance": prov,
    }
    rows = refs = e_rows = None
    if args.only in (None, "ABCD"):
        out = run_abcd(names, data, args.draws, log)
        rows, refs = (
            pl.DataFrame(out["rows"], infer_schema_length=None),
            pl.DataFrame(out["refs"], infer_schema_length=None),
        )
        res["references"] = summarise(refs, ["ref"])
        res["cells"] = summarise(rows, ["design", "k", "reviewer", "estimator"])
        acq_cols = ["reviews", "benign_verified", "malicious_found", "inconclusive", "review_success", "cost",
                    "trusted_windows", "trusted_hours", "service_profiles", "trusted_contamination", "kish_neff",
                    "cluster_neff", "weight_cv", "tail_hosts", "t_bias", "fa_per_host_hour", "top_host_fa_share",
                    "fa_per_detected_entity", "missed_entirely", "r50"]  # fmt: skip
        acq = rows.with_columns(pl.col("domain").map_elements(net_of, return_dtype=pl.Utf8).alias("net")).group_by(
            "design", "k", "reviewer", "estimator", "net", maintain_order=True).agg(
            [pl.col(c).cast(pl.Float64, strict=False).median().alias(c) for c in acq_cols])  # fmt: skip
        res["acquisition_medians"] = acq.to_dicts()
    if args.only in (None, "E"):
        e_rows = pl.DataFrame(run_e(names, data, args.draws), infer_schema_length=None)
        res["temporal"] = summarise(
            e_rows.with_columns(pl.lit(None, dtype=pl.Float64).alias("cal_error")), ["cell"]
        )
        res["temporal_ks_drift"] = {n: float(g["ks_drift"].drop_nulls().mean()) for n, g in
                                    e_rows.filter(pl.col("ks_drift").is_not_null()).group_by("domain") for n in [n[0]]}  # fmt: skip
    if rows is not None:
        res["decisions"] = decide(rows, refs, e_rows)
    res["runtime_s"] = time.perf_counter() - t0
    res["peak_rss_mb"] = peak_rss_mb()
    body = json.dumps(res, indent=1, default=float).encode()
    res_hash = hashlib.sha256(body).hexdigest()
    atomic_write(OUT / f"experiments{args.tag}.json", body)
    atomic_write(OUT / f"experiments{args.tag}.sha256", res_hash.encode())
    if log:
        buf = io.BytesIO()
        np.savez_compressed(buf, primary=np.array(json.dumps(log["primary"])))
        atomic_write(LOGS / f"review_log{args.tag}.npz", buf.getvalue())
    if rows is not None:
        buf = io.BytesIO()
        rows.write_parquet(buf)
        atomic_write(LOGS / f"rows{args.tag}.parquet", buf.getvalue())
    if e_rows is not None:
        buf = io.BytesIO()
        e_rows.write_parquet(buf)
        atomic_write(LOGS / f"temporal_rows{args.tag}.parquet", buf.getvalue())
    print("done", round(res["runtime_s"], 1), "s; peak", res["peak_rss_mb"], "MiB", flush=True)


if __name__ == "__main__":
    main()
