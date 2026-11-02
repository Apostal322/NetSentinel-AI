"""Phase 8j development comparison [E]: M0, M0x, M1-M4 under P1x, leave-one-network-out, and
the registered selection rule (docs/phase8j/PREREGISTRATION.md sections 4-7;
CALIBRATION_RELIABILITY_METHODOLOGY.md sections 4-5).

Units: nfcic (6 day-domains, equal weights), nfunsw, nfton, nfbot. Seeds 0-2 (dev_scores.py).
- Episodes: each domain's P1x hold-out is re-drawn (hosts H' in {5,10,20,50,200} x 5 draws plus
  the full hold-out; then the last 3 h / 12 h / all), duplicates dropped. Every evaluation
  block with >= 30 verified-benign windows gives one row: label-free features and the overrun
  label (exact one-sided binomial test of FPR <= 2 alpha, p < 0.05; amendment A1) at T0 and at
  M3's threshold. --overrun-null alpha reruns everything with the original null (FPR <= alpha)
  as a sensitivity analysis.
- M2 / M4: L2 logistic regression (C = 1, standardised, class-balanced, equal unit weights).
  tau: the largest tau whose covered overrun rate on the training units' out-of-fold
  predictions (pooled, equal unit weights) is <= 10%; else the tau minimising it subject to
  >= 50% coverage (flagged).
- Held-out evaluation uses the FULL hold-out of each held-out domain and every evaluation
  block; criteria (a)-(e) as registered, with a host-cluster bootstrap for the FPR bound and a
  random-abstention control for (d).
- Selection: S = the method of M1, M2, M4 meeting (a) and (b) on the most held-out units (ties:
  lower overrun, then higher coverage); go only if S meets them on >= 2 of 4 units.
- The final M2 / M4 models and tau are refitted on all 4 units (same procedure) and saved.

Output: reports/phase8j/dev/compare.json, reports/phase8j/dev/final_models.json
Usage: uv run python scripts/run_capped.py -- uv run python scripts/phase8j/dev_compare.py
"""

from __future__ import annotations

import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8i"))
import threshold_stats as TS  # noqa: E402, N812
from calibration_audit import eff_n, grouped_exceedance, icc, sessions  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

ALPHA = 0.01
SEEDS = (0, 1, 2)
UNITS = ("nfcic", "nfunsw", "nfton", "nfbot")
DEV = Path("data/derived/phase8j/dev")
OUT = Path("reports/phase8j/dev")
HOST_SUBSETS = (5, 10, 20, 50, 200)
DRAWS = 5
RECENCY_H = (
    None,
    3.0,
    12.0,
)  # untruncated first, so the full hold-out is never dropped as a duplicate
MIN_BENIGN = 30
OVERRUN_NULL = 2 * ALPHA  # amendment A1 (PREREGISTRATION section 11); --overrun-null alpha: ALPHA
HOUR = 3.6e6
B_BOOT, B_RA = 1000, 1000
FEATURES = ("log_n", "log_hosts", "log_eff_hosts", "top_share", "log_sess_neff", "log_m3_neff",
            "pac_l", "tie", "grouped", "oof_ucb", "hours", "shift_med", "shift_q75", "unseen")  # fmt: skip


# ----------------------------------------------------------------------------- calibration
def calib(s: np.ndarray, key: np.ndarray, win: np.ndarray, end: np.ndarray,
          rng: np.random.Generator) -> dict:  # fmt: skip
    """Label-free statistics of one calibration hold-out (rows in any order)."""
    o = np.lexsort((win, key))
    s, key, win, end = s[o], key[o], win[o], end[o]
    n = len(s)
    uniq, m = np.unique(key, return_counts=True)
    srt = np.sort(s)
    t0 = float(srt[TS.k_of(n) - 1])
    sid = sessions(pl.DataFrame({"key": key, "win": win}))
    rho_s = icc(s, sid)
    sess_neff = eff_n(np.unique(sid, return_counts=True)[1].astype(float), rho_s)
    m3_neff = TS.neff_m3(s, key) if len(uniq) >= 2 else float("nan")
    ne = int(math.floor(m3_neff)) if math.isfinite(m3_neff) else 0
    t_m3 = TS.pac_threshold(s, m3_neff) if len(uniq) >= 10 else None
    return {"n": n, "hosts": len(uniq), "eff_hosts": float(m.sum() ** 2 / np.sum(m.astype(float) ** 2)),
            "top_share": float(m.max() / n), "sess_neff": sess_neff, "m3_neff": m3_neff,
            "pac_l": TS.pac_exceedances(ne) if ne >= 1 else 0, "tie": float(np.mean(s == t0)),
            "grouped": grouped_exceedance(s, key).get("exceedance", float("nan")),
            "oof_ucb": TS.cluster_ucb(TS.out_of_fold_exceedance(s, key), key, rng),
            "t0": t0, "t_m3": t_m3, "hold_end": float(end.max()),
            "med": float(np.median(s)), "q75": float(np.quantile(s, 0.75)), "hostset": uniq}  # fmt: skip


def m1_network_pass(c: dict) -> bool:
    """Phase 8i checks 1-3 as proposed (session n_eff >= 199; effective hosts >= 10 and top host
    <= 25%; host-grouped exceedance <= 2 alpha)."""
    return bool(math.isfinite(c["sess_neff"]) and c["sess_neff"] >= 199
                and c["eff_hosts"] >= 10 and c["top_share"] <= 0.25
                and math.isfinite(c["grouped"]) and c["grouped"] <= 2 * ALPHA)  # fmt: skip


# ----------------------------------------------------------------------------- blocks
class Domain:
    """One domain x seed: evaluation windows, 1 h blocks and per-block score summaries."""

    def __init__(self, path: Path):
        z = np.load(path, allow_pickle=False)
        self.cal = {k[4:]: z[k] for k in z.files if k.startswith("cal_")}
        self.ev = {k[3:]: z[k] for k in z.files if k.startswith("ev_")}
        self.attackers = [str(a) for a in z["attackers"]]
        self.network = str(z["network"])
        end = self.ev["end"]
        start = end.min()
        self.blk = ((end - start) // HOUR).astype(int)
        self.nb = int(self.blk.max()) + 1
        self.blk_start = start + np.arange(self.nb) * HOUR
        self.win_per_blk = np.bincount(self.blk, minlength=self.nb)
        ben = self.ev["benign"]
        self.ben_per_blk = np.bincount(self.blk[ben], minlength=self.nb)
        order = np.argsort(self.blk, kind="stable")
        parts = np.split(self.ev["s"][order], np.cumsum(self.win_per_blk)[:-1])
        self.med_b = np.array([np.median(p) if len(p) else np.nan for p in parts])
        self.q75_b = np.array([np.quantile(p, 0.75) if len(p) else np.nan for p in parts])

    def overrun(self, thr: float) -> np.ndarray:
        """Per block: significantly above OVERRUN_NULL (exact one-sided binomial p < 0.05); NaN if the
        block has fewer than MIN_BENIGN verified-benign windows."""
        from scipy.stats import binom

        ben = self.ev["benign"]
        x = np.bincount(self.blk[ben], weights=(self.ev["s"][ben] > thr).astype(float),
                        minlength=self.nb)  # fmt: skip
        p = binom.sf(x - 1, self.ben_per_blk, OVERRUN_NULL)
        return np.where(self.ben_per_blk >= MIN_BENIGN, (p < 0.05).astype(float), np.nan)

    def features(self, c: dict) -> np.ndarray:
        unseen = np.bincount(self.blk, weights=(~np.isin(self.ev["key"], c["hostset"])).astype(float),
                             minlength=self.nb) / np.maximum(self.win_per_blk, 1)  # fmt: skip
        cal = [math.log(c["n"]), math.log(c["hosts"]), math.log(c["eff_hosts"]), c["top_share"],
               math.log1p(np.nan_to_num(c["sess_neff"])), math.log1p(np.nan_to_num(c["m3_neff"])),
               c["pac_l"], c["tie"], np.nan_to_num(c["grouped"], nan=1.0), c["oof_ucb"]]  # fmt: skip
        blk = np.column_stack([(self.blk_start - c["hold_end"]) / HOUR,
                               np.nan_to_num(self.med_b - c["med"]),
                               np.nan_to_num(self.q75_b - c["q75"]), unseen])  # fmt: skip
        return np.column_stack([np.tile(cal, (self.nb, 1)), blk])


def variants(d: Domain, rng: np.random.Generator) -> list[tuple[bool, np.ndarray]]:
    """(is_full, hold-out row indices) for every distinct calibration variant."""
    hold = np.flatnonzero(d.cal["hold"])
    uniq = np.unique(d.cal["key"][hold])
    sets = [None] + [rng.choice(uniq, h, replace=False) for h in HOST_SUBSETS if h < len(uniq)
                     for _ in range(DRAWS)]  # fmt: skip
    out, seen = [], set()
    for hs in sets:
        idx = hold if hs is None else hold[np.isin(d.cal["key"][hold], hs)]
        for rec in RECENCY_H:
            sub = (
                idx
                if rec is None
                else idx[d.cal["end"][idx] >= d.cal["end"][idx].max() - rec * HOUR]
            )
            sig = (len(sub), hash(sub.tobytes()))
            if len(sub) < 20 or sig in seen:
                continue
            seen.add(sig)
            out.append((hs is None and rec is None, sub))
    return out


# ----------------------------------------------------------------------------- learning
def fit(x: np.ndarray, y: np.ndarray, w: np.ndarray):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    if y.min() == y.max():
        return float(y[0])  # one class only: a constant prediction
    m = make_pipeline(StandardScaler(), LogisticRegression(C=1.0, class_weight="balanced",
                                                           max_iter=2000))  # fmt: skip
    return m.fit(x, y, logisticregression__sample_weight=w)


def predict(m, x: np.ndarray) -> np.ndarray:
    return np.full(len(x), m) if isinstance(m, float) else m.predict_proba(x)[:, 1]


def unit_weights(units: np.ndarray) -> np.ndarray:
    u, inv, cnt = np.unique(units, return_inverse=True, return_counts=True)
    return 1.0 / cnt[inv]


def choose_tau(rows: dict, train: list[str], target: str) -> dict:
    """Nested out-of-fold tau on the training units (registered rule)."""
    p = {}
    for t in train:
        rest = [u for u in train if u != t]
        tr = np.isin(rows["unit"], rest) & np.isfinite(rows[target])
        te = (rows["unit"] == t) & np.isfinite(rows[target])
        if not te.any():
            continue
        m = (
            fit(rows["x"][tr], rows[target][tr], unit_weights(rows["unit"][tr]))
            if tr.any()
            else 0.0
        )
        p[t] = (predict(m, rows["x"][te]), rows[target][te])
    grid = np.unique(np.r_[np.quantile(np.concatenate([v[0] for v in p.values()]),
                                       np.linspace(0, 1, 201)), 1.0])[::-1]  # fmt: skip

    def score(tau):
        cov = [float(np.mean(pp <= tau)) for pp, _ in p.values()]
        ov = [float(np.mean(yy[pp <= tau])) for pp, yy in p.values() if (pp <= tau).any()]
        return (float(np.mean(ov)) if ov else float("nan")), float(np.mean(cov))

    for tau in grid:  # descending: least abstention first
        ov, cov = score(tau)
        if math.isfinite(ov) and ov <= 0.10:
            return {"tau": float(tau), "oof_overrun": ov, "oof_coverage": cov, "flag": False}
    best = None
    for tau in grid:
        ov, cov = score(tau)
        if cov >= 0.5 and math.isfinite(ov) and (best is None or ov < best[1]):
            best = (tau, ov, cov)
    if best is None:
        ov, cov = score(1.0)
        return {"tau": 1.0, "oof_overrun": ov, "oof_coverage": cov, "flag": True}
    return {"tau": float(best[0]), "oof_overrun": best[1], "oof_coverage": best[2], "flag": True}


# ----------------------------------------------------------------------------- evaluation
def domain_metrics(d: Domain, thr: float, covered_blk: np.ndarray) -> dict:
    ev = d.ev
    cov = covered_blk[d.blk]
    alert = (ev["s"] > thr) & cov
    y, ben, key = ev["y"], ev["benign"], ev["key"]
    over = d.overrun(thr)
    scored = np.isfinite(over) & covered_blk
    det, delays, eligible = 0, [], 0
    for a in d.attackers:
        m = y & (key == a)
        if m.sum() < 5:
            continue
        eligible += 1
        if (alert & m).any():
            det += 1
            delays.append(float((ev["end"][alert & m].min() - ev["end"][m].min()) / 1000))
    bk = key[ben & cov]
    _, inv = np.unique(bk, return_inverse=True)
    return {"fp": int(alert[ben].sum()), "benign_cov": int((ben & cov).sum()),
            "fpr": float(alert[ben].sum() / (ben & cov).sum()) if (ben & cov).any() else None,
            "host_fp": np.bincount(inv, alert[ben & cov].astype(float)) if len(bk) else None,
            "host_n": np.bincount(inv).astype(float) if len(bk) else None,
            "block_cov": float(covered_blk[d.win_per_blk > 0].mean()),
            "attack_cov": float(cov[y].mean()) if y.any() else None,
            "benign_win_cov": float(cov[ben].mean()) if ben.any() else None,
            "recall_cov": float(alert[y & cov].mean()) if (y & cov).any() else None,
            "recall_all": float(alert[y].mean()) if y.any() else None,
            "entity_recall": det / eligible if eligible else None,
            "median_delay_s": float(np.median(delays)) if delays else None,
            "overrun_rate": float(over[scored].mean()) if scored.any() else None,
            "scored_blocks": int(scored.sum()), "over": over, "covered": covered_blk}  # fmt: skip


def mean_or_none(v):
    v = [x for x in v if x is not None]
    return float(np.mean(v)) if v else None


def fpr_ucb(per: list[dict], rng: np.random.Generator) -> float | None:
    """95th percentile of the unit FPR (mean over domains) when each domain's verified-benign
    hosts are resampled with replacement (host-cluster bootstrap)."""
    draws = []
    for m in per:
        if m["host_n"] is None:
            continue
        h = len(m["host_n"])
        w = rng.multinomial(h, np.full(h, 1 / h), size=B_BOOT).astype(float)
        draws.append((w @ m["host_fp"]) / np.maximum(w @ m["host_n"], 1))
    return float(np.quantile(np.mean(draws, axis=0), 0.95)) if draws else None


def ra_pvalue(per: list[dict], rng: np.random.Generator) -> float:
    """Random abstention at the method's total block coverage, pooled over the unit's domains,
    scored at the method's threshold (T0 where M3 abstains);
    p = (1 + #{RA overrun <= method overrun}) / (B + 1); ties count against the method."""
    over = np.concatenate([m["over"] for m in per])
    cov = np.concatenate([m["covered"] for m in per])
    k = int(cov.sum())
    s_sc = cov & np.isfinite(over)
    if k == 0 or not s_sc.any():
        return 1.0
    s_rate = float(over[s_sc].mean())
    hits = 0
    for _ in range(B_RA):
        c = np.zeros(len(cov), dtype=bool)
        c[rng.choice(len(cov), k, replace=False)] = True
        sc = c & np.isfinite(over)
        if sc.any() and float(over[sc].mean()) <= s_rate:
            hits += 1
    return (1 + hits) / (B_RA + 1)


def summarize_unit(per_seed: list[list[dict]], ucbs: list, ps: list) -> dict:
    keys = ("fpr", "block_cov", "attack_cov", "benign_win_cov", "recall_cov", "recall_all",
            "entity_recall", "median_delay_s", "overrun_rate")  # fmt: skip
    seed_means = [{k: mean_or_none([m[k] for m in per]) for k in keys} for per in per_seed]
    out = {k: mean_or_none([s[k] for s in seed_means]) for k in keys}
    out["fpr_seeds"] = [s["fpr"] for s in seed_means]
    out["fpr_ucb"] = mean_or_none(ucbs)
    out["ra_p_median"] = float(np.median(ps)) if ps else None
    a = out["fpr"] is not None and out["fpr"] <= 0.02 and out["fpr_ucb"] is not None \
        and out["fpr_ucb"] <= 0.03  # fmt: skip
    b = all(
        out[k] is not None and out[k] >= 0.5 for k in ("block_cov", "attack_cov", "benign_win_cov")
    )
    out["criteria"] = {
        "a_budget": bool(a), "b_coverage": bool(b),
        "c_sensitivity": bool(out["entity_recall"] is not None and out["entity_recall"] >= 0.5),
        "d_beats_random": bool(out["ra_p_median"] is not None and out["ra_p_median"] < 0.05),
        "e_no_attack_abstention": bool(out["attack_cov"] is not None and out["benign_win_cov"]
                                       and out["attack_cov"] >= 0.8 * out["benign_win_cov"])}  # fmt: skip
    return out


# ----------------------------------------------------------------------------- main
def main() -> None:
    import argparse

    global OVERRUN_NULL
    ap = argparse.ArgumentParser()
    ap.add_argument("--overrun-null", choices=("2alpha", "alpha"), default="2alpha")
    a = ap.parse_args()
    OVERRUN_NULL = ALPHA if a.overrun_null == "alpha" else 2 * ALPHA
    tag = "" if a.overrun_null == "2alpha" else "_null_alpha"
    t_start = time.perf_counter()
    names = sorted({p.name.split("__seed")[0] for p in DEV.glob("*__seed*.npz")})
    unit_of = {n: n.split("__")[0] for n in names}
    rows = {k: [] for k in ("x", "over_t0", "over_m3", "unit")}
    full: dict[tuple, tuple] = {}  # (name, seed) -> (Domain, calib of the full hold-out)
    for seed in SEEDS:
        for i, name in enumerate(names):
            d = Domain(DEV / f"{name}__seed{seed}.npz")
            rng = np.random.default_rng(10_000 * seed + i)
            for is_full, idx in variants(d, rng):
                c = calib(
                    d.cal["s"][idx], d.cal["key"][idx], d.cal["win"][idx], d.cal["end"][idx], rng
                )
                x = d.features(c)
                o0 = d.overrun(c["t0"])
                o3 = d.overrun(c["t_m3"]) if c["t_m3"] is not None else np.full(d.nb, np.nan)
                keep = np.isfinite(o0)
                rows["x"].append(x[keep])
                rows["over_t0"].append(o0[keep])
                rows["over_m3"].append(o3[keep])
                rows["unit"].append(np.full(keep.sum(), unit_of[name]))
                if is_full:
                    full[(name, seed)] = (d, c, x)
            print(f"seed {seed} {name}: {time.perf_counter() - t_start:.0f} s", flush=True)
    rows = {k: np.concatenate(v) for k, v in rows.items()}
    res = {"episodes": {u: int((rows["unit"] == u).sum()) for u in UNITS},
           "overrun_base_rate_t0": {u: float(np.mean(rows["over_t0"][rows["unit"] == u])) for u in UNITS},
           "units": {}, "tau": {}}  # fmt: skip
    rng = np.random.default_rng(2026)
    methods = ("M0", "M0x", "M1", "M2", "M3", "M4")
    for u in UNITS:
        train = [t for t in UNITS if t != u]
        models = {}
        for meth, target in (("M2", "over_t0"), ("M4", "over_m3")):
            tr = np.isin(rows["unit"], train) & np.isfinite(rows[target])
            models[meth] = (fit(rows["x"][tr], rows[target][tr], unit_weights(rows["unit"][tr])),
                            choose_tau(rows, train, target))  # fmt: skip
            res["tau"].setdefault(meth, {})[u] = models[meth][1]
        res["units"][u] = {}
        for meth in methods:
            per_seed, ucbs, ps = [], [], []
            for seed in SEEDS:
                per = []
                for name in names:
                    if unit_of[name] != u:
                        continue
                    d, c, x = full[(name, seed)]
                    allb = np.ones(d.nb, dtype=bool)
                    if meth == "M0":
                        thr, cov = c["t0"], allb
                    elif meth == "M0x":
                        thr, cov = float(np.sort(d.cal["s"])[TS.k_of(len(d.cal["s"])) - 1]), allb
                    elif meth == "M1":
                        thr = c["t0"]
                        fresh = (d.blk_start - c["hold_end"]) / HOUR <= 24
                        cov = fresh if m1_network_pass(c) else np.zeros(d.nb, dtype=bool)
                    elif meth == "M2":
                        m, t = models["M2"]
                        thr, cov = c["t0"], predict(m, x) <= t["tau"]
                    elif meth == "M3":
                        thr = c["t_m3"] if c["t_m3"] is not None else c["t0"]
                        cov = allb if c["t_m3"] is not None else np.zeros(d.nb, dtype=bool)
                    else:  # M4
                        m, t = models["M4"]
                        thr = c["t_m3"] if c["t_m3"] is not None else c["t0"]
                        cov = (predict(m, x) <= t["tau"]) if c["t_m3"] is not None \
                            else np.zeros(d.nb, dtype=bool)  # fmt: skip
                    per.append(domain_metrics(d, thr, cov))
                per_seed.append(per)
                ucbs.append(fpr_ucb(per, rng))
                ps.append(ra_pvalue(per, rng))
            res["units"][u][meth] = summarize_unit(per_seed, ucbs, ps)
            s = res["units"][u][meth]
            print(u, meth, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in s.items()
                            if k in ("fpr", "fpr_ucb", "block_cov", "attack_cov", "recall_cov",
                                     "overrun_rate")}, s["criteria"], flush=True)  # fmt: skip
    # J2 (descriptive on development): M1's network checks vs the M0 FPR, per domain (seed 0)
    res["m1_checks_seed0"] = {
        name: {"pass": m1_network_pass(full[(name, 0)][1]),
               "m0_fpr": domain_metrics(full[(name, 0)][0], full[(name, 0)][1]["t0"],
                                        np.ones(full[(name, 0)][0].nb, dtype=bool))["fpr"],
               **{k: full[(name, 0)][1][k] for k in ("n", "hosts", "eff_hosts", "top_share",
                                                     "sess_neff", "m3_neff", "pac_l", "tie",
                                                     "grouped")}} for name in names}  # fmt: skip
    # selection rule (section 7)
    cand = {}
    for meth in ("M1", "M2", "M4"):
        ok = [u for u in UNITS if res["units"][u][meth]["criteria"]["a_budget"]
              and res["units"][u][meth]["criteria"]["b_coverage"]]  # fmt: skip
        ov = mean_or_none([res["units"][u][meth]["overrun_rate"] for u in UNITS])
        cv = mean_or_none([res["units"][u][meth]["block_cov"] for u in UNITS])
        cand[meth] = {
            "units_meeting_a_and_b": ok,
            "count": len(ok),
            "mean_overrun": ov,
            "mean_block_cov": cv,
        }
    best = sorted(cand, key=lambda k: (-cand[k]["count"],
                                       cand[k]["mean_overrun"] if cand[k]["mean_overrun"] is not None else 9,
                                       -(cand[k]["mean_block_cov"] or 0)))[0]  # fmt: skip
    res["selection"] = {"candidates": cand, "S": best, "go": cand[best]["count"] >= 2}
    # final models on all 4 units (saved whatever the go/no-go)
    final = {}
    for meth, target in (("M2", "over_t0"), ("M4", "over_m3")):
        tr = np.isfinite(rows[target])
        m = fit(rows["x"][tr], rows[target][tr], unit_weights(rows["unit"][tr]))
        tau = choose_tau(rows, list(UNITS), target)
        if isinstance(m, float):
            final[meth] = {"constant": m, "tau": tau}
        else:
            sc, lr = m.named_steps["standardscaler"], m.named_steps["logisticregression"]
            final[meth] = {"features": FEATURES, "mean": sc.mean_.tolist(), "scale": sc.scale_.tolist(),
                           "coef": lr.coef_[0].tolist(), "intercept": float(lr.intercept_[0]), "tau": tau}  # fmt: skip
    res["seconds"] = round(time.perf_counter() - t_start, 1)
    res["peak_rss_mb"] = peak_rss_mb()
    OUT.mkdir(parents=True, exist_ok=True)
    res["overrun_null"] = OVERRUN_NULL
    (OUT / f"final_models{tag}.json").write_text(json.dumps(final, indent=1), "utf-8")
    (OUT / f"compare{tag}.json").write_text(json.dumps(res, indent=1, default=float), "utf-8")
    print(json.dumps(res["selection"], indent=1), flush=True)


if __name__ == "__main__":
    main()
