"""Phase 8l DEDALE analysis (docs/phase8l/DEDALE_PREREGISTRATION.md sections 3-7).

Two modes, each refused unless docs/phase8l/DEDALE_FREEZE.md is committed with the
pre-registration's SHA-256, and each run once (an existing report stops it):

  --n8     score the CALIBRATION windows with the three frozen source models; T0 and M2 per seed
           on the eligible hold-out; N8 = the smallest per-seed `neff_m3` of hold-out scores
           >= 590. Writes reports/phase8l/dedale_n8.json. No evaluation data exists yet.
  --final  after Stage B and dedale_eval_build.py: score the evaluation windows, then H1-H3,
           detection, sensitivity analyses. Writes reports/phase8l/dedale_final.json.

Statistics are pure functions below (unit-tested in tests/unit/test_phase8l_dedale_analysis.py).
Usage: uv run python scripts/run_capped.py -- <abs python> scripts/phase8l/dedale_analysis.py --n8
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPORTS = ROOT / "reports" / "phase8l"
N8_REPORT = REPORTS / "dedale_n8.json"
FINAL_REPORT = REPORTS / "dedale_final.json"

ALPHA = 0.01
BUDGET = 2 * ALPHA
UPPER_MAX = 0.03
NEFF_MIN = 590
N9_HOSTS, N9_HOST_WINDOWS, N9_WINDOWS = 15, 20, 2000
PERIOD_MIN, DAY_MIN = 200, 30
B, RNG_SEED, CHUNK = 10_000, 81202, 500
SEEDS = (0, 1, 2)
W_MS = 30_000
BOUNDARY_MS = int(datetime(2025, 1, 6, tzinfo=UTC).timestamp() * 1000)
POST_MS = int(datetime(2025, 1, 14, tzinfo=UTC).timestamp() * 1000)
END_MS = int(datetime(2025, 1, 20, tzinfo=UTC).timestamp() * 1000)
# compromise times: first labelled event of each client (labelling script, UTC)
COMPROMISE_MS = {
    "172.16.1.3": int(datetime(2025, 1, 6, 10, 0, 13, tzinfo=UTC).timestamp() * 1000),  # client 2
    "172.16.1.2": int(datetime(2025, 1, 8, 15, 10, 2, tzinfo=UTC).timestamp() * 1000),  # client 1
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _stats():
    """(Phase 8i common, Phase 8j threshold_stats). threshold_stats imports calibration_audit,
    which does `import common`: bind that name to the Phase 8i module first."""
    c = _load("common_8i", ROOT / "scripts/phase8i/common.py")
    sys.modules.setdefault("common", c)
    sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
    ts = _load("phase8j_threshold_stats", ROOT / "scripts/phase8j/threshold_stats.py")
    return c, ts


# ----------------------------------------------------------------------------- thresholds
def t0(z: np.ndarray, k_of) -> float:
    """Plain conformal T0: the order statistic at rank k = ceil((n + 1)(1 - alpha))."""
    return float(np.sort(z)[k_of(len(z)) - 1])


def host_order(host: np.ndarray, win: np.ndarray) -> np.ndarray:
    """Row order by host, then time (what lag-1 and the ICC in `neff_m3` expect)."""
    return np.lexsort((win, host))


# ----------------------------------------------------------------------------- FPR and bounds
def boot_bounds(a: np.ndarray, host: np.ndarray, rng: np.random.Generator) -> tuple[float, float]:
    """One-sided 95% percentile bounds of the pooled rate sum(a)/n under a host-cluster
    bootstrap (hosts resampled with replacement, B draws in chunks)."""
    uniq, inv = np.unique(host, return_inverse=True)
    s, n = np.bincount(inv, a), np.bincount(inv).astype(float)
    out = []
    for lo in range(0, B, CHUNK):
        idx = rng.integers(0, len(uniq), size=(min(CHUNK, B - lo), len(uniq)))
        out.append(s[idx].sum(1) / n[idx].sum(1))
    r = np.concatenate(out)
    return float(np.quantile(r, 0.05)), float(np.quantile(r, 0.95))


def cp_bounds(rate: float, n_eff: float) -> tuple[float, float]:
    """One-sided 95% Clopper-Pearson bounds at x = rate * n_eff (continuous in x)."""
    from scipy.stats import beta

    if not (math.isfinite(n_eff) and n_eff > 0):
        return 0.0, 1.0
    x = rate * n_eff
    lo = float(beta.ppf(0.05, x, n_eff - x + 1)) if x > 0 else 0.0
    hi = float(beta.ppf(0.95, x + 1, n_eff - x)) if x < n_eff else 1.0
    return lo, hi


def fpr_summary(a: np.ndarray, host: np.ndarray, win: np.ndarray, neff_fn, seed: int) -> dict:
    """Pooled FPR of seed-mean alert indicators `a`, its two bound pairs and the less
    favourable pair (larger upper, smaller lower)."""
    if a.size == 0:
        return {"n": 0}
    o = host_order(host, win)
    a, host, win = a[o], host[o], win[o]
    rate = float(a.mean())
    n_eff = float(neff_fn(a, host)) if len(np.unique(host)) >= 2 else float("nan")
    b_lo, b_hi = boot_bounds(a, host, np.random.default_rng(seed))
    c_lo, c_hi = cp_bounds(rate, n_eff)
    return {"n": int(a.size), "hosts": int(len(np.unique(host))), "fpr": rate, "n_eff": n_eff,
            "boot": [b_lo, b_hi], "cp": [c_lo, c_hi], "lower": min(b_lo, c_lo),
            "upper": max(b_hi, c_hi)}  # fmt: skip


def three_state(s: dict) -> str:
    if s.get("n", 0) == 0:
        return "INDETERMINATE"
    if s["fpr"] <= BUDGET and s["upper"] <= UPPER_MAX:
        return "HOLDS"
    if s["lower"] > BUDGET:
        return "FAILS"
    return "INCONCLUSIVE"


def h1_outcome(s: dict, n9: bool) -> str:
    """H1 with N9: when the counts are too small, only FAILS is reportable."""
    if n9:
        return "FAILS" if s.get("n", 0) and s["lower"] > BUDGET else "NOT EVALUABLE"
    return three_state(s)


# ----------------------------------------------------------------------------- drift
def holm(p: list[float]) -> list[float]:
    order = np.argsort(p)
    adj, run = np.empty(len(p)), 0.0
    for i, j in enumerate(order):
        run = max(run, min(1.0, (len(p) - i) * p[j]))
        adj[j] = run
    return adj.tolist()


def overrun_p(rate: float, n: int, deff: float) -> float:
    """Exact binomial P(X >= x | n_eff, 2 alpha) at n_eff = n / deff (one-sided overrun)."""
    from scipy.stats import binom

    n_eff = max(1, round(n / deff))
    x = round(rate * n_eff)
    return float(binom.sf(x - 1, n_eff, BUDGET)) if x > 0 else 1.0


def logistic_slope(y: np.ndarray, t: np.ndarray, g: np.ndarray, iters: int = 50) -> dict:
    """Logit(P(alert)) = b0 + b1 t, fractional y in [0, 1], IRLS; cluster-robust (CR0) SE of b1
    with clusters g."""
    x = np.column_stack([np.ones_like(t, dtype=float), t.astype(float)])
    b = np.zeros(2)
    for _ in range(iters):
        mu = 1 / (1 + np.exp(-(x @ b)))
        w = np.clip(mu * (1 - mu), 1e-12, None)
        step = np.linalg.solve(x.T @ (x * w[:, None]), x.T @ (y - mu))
        b += step
        if np.max(np.abs(step)) < 1e-10:
            break
    mu = 1 / (1 + np.exp(-(x @ b)))
    bread = np.linalg.inv(x.T @ (x * (mu * (1 - mu))[:, None]))
    _, inv = np.unique(g, return_inverse=True)
    u = np.zeros((inv.max() + 1, 2))
    np.add.at(u, inv, x * (y - mu)[:, None])
    v = bread @ (u.T @ u) @ bread
    se = float(math.sqrt(max(v[1, 1], 0.0)))
    return {
        "slope_per_day": float(b[1]),
        "se": se,
        "z": float(b[1] / se) if se > 0 else float("nan"),
    }


# ----------------------------------------------------------------------------- detection
def wilson(x: float, n: int, z: float = 1.959964) -> list[float]:
    if n == 0:
        return [float("nan"), float("nan")]
    p = x / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [c - h, c + h]


def entity_detection(wins: pl.DataFrame, alerts: np.ndarray, entity: str, comp_ms: int) -> dict:
    """Per seed: detected (any alerted label 1 window), delay from the first label 1 window to
    the first alerted one, and from compromise to the first alert on any of its windows.
    `wins` holds host, window_end_ms, y1 aligned with `alerts` (n_windows x n_seeds, 0/1)."""
    m = (wins["host"] == entity).to_numpy()
    y1 = wins["y1"].to_numpy() & m
    end = wins["window_end_ms"].to_numpy()
    out = []
    for k in range(alerts.shape[1]):
        al = alerts[:, k] > 0
        first = end[y1].min() if y1.any() else None
        hit = end[y1 & al]
        after = end[m & al & (end >= comp_ms)]
        out.append({"label1_windows": int(y1.sum()), "detected": bool(hit.size),
                    "delay_first_label1_h": (float(hit.min() - first) / 3.6e6 if hit.size else None),
                    "delay_any_after_compromise_h": (float(after.min() - comp_ms) / 3.6e6
                                                     if after.size else None)})  # fmt: skip
    return {"per_seed": out, "detected_seeds": sum(o["detected"] for o in out)}


# ----------------------------------------------------------------------------- data helpers
def attribute_hosts(
    keys: pl.Series, end_ms: pl.Series, leases: pl.DataFrame, internal
) -> pl.Series:
    """Host of each window: for internal addresses, the MAC of the address's latest DHCP lease
    at or before the window end (else its first later lease); other sources keep the address."""
    df = pl.DataFrame({"key": keys, "t": end_ms}).with_row_index("i")
    lz = (leases.filter(pl.col("assigned_addr").map_elements(internal, return_dtype=pl.Boolean))
          .select(pl.col("assigned_addr").alias("key"),
                  (pl.col("ts").cast(pl.Float64) * 1000).cast(pl.Int64).alias("t"), "mac")
          .sort("t"))  # fmt: skip
    if lz.height == 0:
        return keys
    d = df.sort("t")
    back = d.join_asof(lz, on="t", by="key", strategy="backward")
    fwd = d.join_asof(lz, on="t", by="key", strategy="forward").select(
        "i", pl.col("mac").alias("m2")
    )
    j = back.join(fwd, on="i").sort("i")
    return j.select(pl.coalesce("mac", "m2", "key")).to_series().alias("host")


def score(c, models: list, df: pl.DataFrame) -> np.ndarray:
    x = c.S._x(df)
    return np.column_stack([m.predict(x) for m in models])


def load_models(rep: dict) -> list:
    import hashlib

    import lightgbm as lgb

    out = []
    for seed in SEEDS:
        info = rep["models"][str(seed)]
        p = ROOT / info["file"].replace("\\", "/")
        if hashlib.sha256(p.read_bytes()).hexdigest() != info["sha256"]:
            raise SystemExit(f"N7: model seed {seed} hash mismatch")
        out.append(lgb.Booster(model_file=str(p)))
    return out


def population(stage_a: dict) -> dict:
    """Primary eligible addresses, clients 3-4 and the excluded set, from the Stage A report."""
    prim = stage_a["hosts"]["primary"]
    return {"eligible": sorted(r["addr"] for r in prim if r["status"] == "eligible"),
            "clients_3_4": sorted(r["addr"] for r in prim if r["status"] == "clients_3_4"),
            "excluded_internal": sorted(r["addr"] for r in prim if r["status"] == "excluded")}  # fmt: skip


# ----------------------------------------------------------------------------- modes
def _guard(report: Path) -> None:
    f = _load("phase8l_dedale_fetch", HERE / "dedale_fetch.py")
    if not f.freeze_ok():
        raise SystemExit(
            "refused: DEDALE_FREEZE.md is not committed with the pre-registration hash"
        )
    if report.exists():
        raise SystemExit(f"refused: {report.name} exists (each mode runs once)")


def a_internal(a):
    import ipaddress

    def f(x: str) -> bool:
        try:
            return ipaddress.ip_address(x) in a.CLIENTS
        except ValueError:
            return False

    return f


def holdout_stats(ts, z: np.ndarray, host: np.ndarray, win: np.ndarray) -> dict:
    o = host_order(host, win)
    z, host = z[o], host[o]
    n_eff = float(ts.neff_m3(z, host))
    t_m2 = ts.pac_threshold(z, n_eff) if len(np.unique(host)) >= 10 else None
    return {"n": int(z.size), "t0": t0(z, ts.k_of), "neff_m3": n_eff,
            "m2": (None if t_m2 is None else float(t_m2))}  # fmt: skip


def run_n8() -> None:
    _guard(N8_REPORT)
    t_start = time.perf_counter()
    c, ts = _stats()
    a = _load("phase8l_dedale_stage_a", HERE / "dedale_stage_a.py")
    stage_a = json.loads((REPORTS / "dedale_stage_a.json").read_text("utf-8"))
    models = load_models(json.loads((REPORTS / "dedale_source_models.json").read_text("utf-8")))
    cal = pl.read_parquet(a.DERIVED / "cal_p1x.parquet")
    cal = cal.with_columns(attribute_hosts(cal["key"], cal["window_end_ms"], _cal_leases(a),
                                           a_internal(a)))  # fmt: skip
    cut = stage_a["windows"]["split_cut_win"]
    pop = population(stage_a)
    s = score(c, models, cal)
    np.save(a.DERIVED / "cal_scores.npy", s)
    elig_hosts = set(_hosts_of(cal, pop["eligible"]))
    hold = ((cal["win"] >= cut) & cal["host"].is_in(sorted(elig_hosts))).to_numpy()
    host, win = cal["host"].to_numpy()[hold], cal["win"].to_numpy()[hold]
    per = {str(k): holdout_stats(ts, s[hold, i], host, win) for i, k in enumerate(SEEDS)}
    worst = min(v["neff_m3"] for v in per.values())
    rep = {"holdout_windows": int(hold.sum()), "hosts": len(elig_hosts), "per_seed": per,
           "min_neff_m3": worst, "deff": float(np.mean([v["n"] / v["neff_m3"] for v in per.values()])),
           "outcome": "PASS" if worst >= NEFF_MIN else "NOT EVALUABLE",
           "seconds": round(time.perf_counter() - t_start, 1)}  # fmt: skip
    N8_REPORT.write_text(json.dumps(rep, indent=1), "utf-8")
    print(json.dumps(rep, indent=1))


def _cal_leases(a) -> pl.DataFrame:
    man = json.loads(a.MANIFEST.read_text("utf-8"))["stages"]["A"]["members"]
    rows = []
    for m in man:
        if m["name"].endswith("dhcp.log"):
            rows += a.dhcp_leases(a.RAW / f"D{m['day']:02d}_{m['date']}_dhcp.log.gz")
    return pl.DataFrame(rows)


def _hosts_of(frame: pl.DataFrame, addrs: list[str]) -> list[str]:
    """Hosts (MACs or addresses) that the windows of these addresses are attributed to."""
    return frame.filter(pl.col("key").is_in(addrs))["host"].unique().to_list()


def run_final() -> None:
    _guard(FINAL_REPORT)
    n8 = json.loads(N8_REPORT.read_text("utf-8"))
    if n8["outcome"] != "PASS":
        raise SystemExit("refused: N8 did not pass")
    t_start = time.perf_counter()
    c, ts = _stats()
    a = _load("phase8l_dedale_stage_a", HERE / "dedale_stage_a.py")
    stage_a = json.loads((REPORTS / "dedale_stage_a.json").read_text("utf-8"))
    build = json.loads((REPORTS / "dedale_eval_build.json").read_text("utf-8"))
    models = load_models(json.loads((REPORTS / "dedale_source_models.json").read_text("utf-8")))
    leases = pl.read_parquet(a.DERIVED / "leases.parquet")
    internal = a_internal(a)
    pop = population(stage_a)

    cal = pl.read_parquet(a.DERIVED / "cal_p1x.parquet")
    cal = cal.with_columns(attribute_hosts(cal["key"], cal["window_end_ms"], leases, internal))
    s_cal = np.load(a.DERIVED / "cal_scores.npy")
    cut = stage_a["windows"]["split_cut_win"]
    ev = pl.read_parquet(a.DERIVED / "eval_p1x.parquet")
    ev = ev.with_columns(attribute_hosts(ev["key"], ev["window_end_ms"], leases, internal))
    truth = pl.read_parquet(a.DERIVED / "eval_truth.parquet")
    ev = ev.join(truth, on=["key", "win"], how="left").with_columns(
        pl.col("y1").fill_null(False), pl.col("y2").fill_null(False)
    )
    s_ev = score(c, models, ev)

    # excluded hosts: everything that ever held an excluded internal address, any day
    excl_hosts = set(_hosts_of(ev, pop["excluded_internal"])) | set(
        _hosts_of(cal, pop["excluded_internal"])
    )
    elig = set(_hosts_of(cal, pop["eligible"])) - excl_hosts
    c34 = set(_hosts_of(cal, pop["clients_3_4"])) - excl_hosts

    def thresholds(hold_mask: np.ndarray) -> list[float]:
        return [t0(s_cal[hold_mask, i], ts.k_of) for i in range(len(SEEDS))]

    hold_primary = ((cal["win"] >= cut) & cal["host"].is_in(sorted(elig))).to_numpy()
    thr = thresholds(hold_primary)
    for i, k in enumerate(SEEDS):
        if abs(thr[i] - n8["per_seed"][str(k)]["t0"]) > 0:
            raise SystemExit("T0 differs from the N8 report")
    alerts = (s_ev > np.array(thr)[None, :]).astype(float)
    a_mean = alerts.mean(1)
    host = ev["host"].to_numpy()
    win = ev["win"].to_numpy()
    end = ev["window_end_ms"].to_numpy()
    y1, y2 = ev["y1"].to_numpy(), ev["y2"].to_numpy()
    clean = ~(y1 | y2)

    def summary(mask: np.ndarray, aa: np.ndarray = a_mean, seed: int = RNG_SEED) -> dict:
        return fpr_summary(aa[mask], host[mask], win[mask], ts.neff_m3, seed)

    vb = np.isin(host, sorted(elig)) & clean
    per_host = pl.DataFrame({"h": host[np.isin(host, sorted(elig))]}).group_by("h").len()
    n9 = bool((per_host["len"] >= N9_HOST_WINDOWS).sum() < N9_HOSTS or vb.sum() < N9_WINDOWS)
    h1 = summary(vb)
    rep: dict = {"n8": n8, "thresholds_t0": thr, "N9_triggered": n9,
                 "label2_only_windows_excluded": int((np.isin(host, sorted(elig)) & y2 & ~y1).sum()),
                 "H1": {**h1, "outcome": h1_outcome(h1, n9),
                        "per_seed_fpr": [float(alerts[vb, i].mean()) for i in range(len(SEEDS))],
                        "host_macro_fpr": float(pl.DataFrame({"h": host[vb], "a": a_mean[vb]})
                                                .group_by("h").agg(pl.col("a").mean())["a"].mean())}}  # fmt: skip
    periods = {"attack": (BOUNDARY_MS, POST_MS), "post_attack": (POST_MS, END_MS)}
    rep["H2"] = {}
    for name, (lo, hi) in periods.items():
        m = vb & (end >= lo) & (end < hi)
        sm = summary(m)
        rep["H2"][name] = {
            **sm,
            "outcome": three_state(sm) if m.sum() >= PERIOD_MIN else "INDETERMINATE",
        }

    # H3 drift (descriptive)
    day = (end - BOUNDARY_MS) // 86_400_000
    deff = n8["deff"]
    daily = []
    for d in np.unique(day[vb]):
        m = vb & (day == d)
        if m.sum() >= DAY_MIN:
            r = float(a_mean[m].mean())
            daily.append({"day": int(d) + 15, "n": int(m.sum()), "fpr": r,
                          "p_overrun": overrun_p(r, int(m.sum()), deff)})  # fmt: skip
    for row, p in zip(daily, holm([r["p_overrun"] for r in daily]), strict=True):
        row["p_holm"] = p
    rep["H3"] = {"daily": daily, "trend": logistic_slope(a_mean[vb], day[vb], host[vb])}

    # secondary threshold M2
    m2 = [n8["per_seed"][str(k)]["m2"] for k in SEEDS]
    if all(v is not None for v in m2):
        am2 = (s_ev > np.array(m2)[None, :]).astype(float).mean(1)
        rep["M2"] = {"thresholds": m2, **summary(vb, am2)}
    else:
        rep["M2"] = {"thresholds": m2, "note": "M2 abstains for at least one seed"}

    # sensitivity analyses
    sens = {}
    hours = (cal["window_end_ms"].to_numpy() - 1) // 3_600_000
    act = np.unique(hours[cal["host"].is_in(sorted(elig)).to_numpy()])
    last = act[len(act) - int(math.floor(0.3 * len(act))) :]
    hold_act = cal["host"].is_in(sorted(elig)).to_numpy() & np.isin(hours, last)
    thr_act = thresholds(hold_act)
    sens["active_hours_holdout"] = {"thresholds": thr_act, "holdout_windows": int(hold_act.sum()),
                                    **summary(vb, (s_ev > np.array(thr_act)[None, :]).mean(1))}  # fmt: skip
    pop34 = elig | c34
    hold34 = ((cal["win"] >= cut) & cal["host"].is_in(sorted(pop34))).to_numpy()
    thr34 = thresholds(hold34)
    vb34 = np.isin(host, sorted(pop34)) & clean
    sens["clients_3_4_included"] = {"thresholds": thr34,
                                    **summary(vb34, (s_ev > np.array(thr34)[None, :]).mean(1))}  # fmt: skip
    outside = set(build.get("label_addresses_outside_script", []))
    drop = set(_hosts_of(ev, sorted(outside))) if outside else set()
    sens["label_sanity_dropped"] = {"addresses": sorted(outside),
                                    **(summary(vb & ~np.isin(host, sorted(drop))) if drop else {"same_as_primary": True})}  # fmt: skip
    excluded_addr = set(a.ALWAYS_EXCLUDED) | set(a.COMPROMISED)
    per = cal.group_by("key").agg(pl.len().alias("n"), (pl.col("win") >= cut).sum().alias("h"))
    sec_keys = [r[0] for r in per.iter_rows() if not internal(r[0]) and r[0] not in excluded_addr
                and r[1] >= a.MIN_CAL and r[2] >= a.MIN_HOLD]  # fmt: skip
    sec = np.isin(ev["key"].to_numpy(), sec_keys) & clean
    sens["secondary_population"] = {"sources": sorted(sec_keys), **summary(sec)}
    rep["sensitivity"] = sens

    # detection (descriptive)
    att = y1
    steps = ev["steps"].to_list()
    by_step: dict[str, list] = {}
    for i in np.flatnonzero(att):
        for st in steps[i] or []:
            by_step.setdefault(st, []).append(a_mean[i])
    rep["detection"] = {
        "attack_windows": int(att.sum()),
        "window_recall": float(a_mean[att].mean()) if att.any() else None,
        "window_recall_wilson_ignores_dependence": wilson(float(a_mean[att].sum()), int(att.sum())),
        "by_step": {k: {"windows": len(v), "recall": float(np.mean(v))} for k, v in sorted(by_step.items())},
        "entities": {},
    }  # fmt: skip
    wins = pl.DataFrame({"host": host, "window_end_ms": end, "y1": y1})
    for addr, comp in COMPROMISE_MS.items():
        hs = _hosts_of(ev, [addr])
        ent = hs[0] if hs else addr
        rep["detection"]["entities"][addr] = entity_detection(wins, alerts, ent, comp)
    fa = vb & (a_mean > 0)
    hh = pl.DataFrame({"h": host[vb], "hr": end[vb] // 3_600_000}).unique().height
    newdst = ev["new_dst_frac"].fill_null(0).to_numpy() > 0
    excl_int = np.isin(host, sorted(excl_hosts)) & ~y1 & ~y2
    rep["alert_burden"] = {
        "false_alerts_per_benign_host_hour": float(a_mean[vb].sum() / hh) if hh else None,
        "false_alerts_per_day": {str(int(d) + 15): float(a_mean[vb & (day == d)].sum())
                                 for d in np.unique(day[vb])},
        "share_of_false_alerts_with_new_dst": float(a_mean[fa & newdst].sum() / a_mean[fa].sum())
        if fa.any() else None,
        "alerts_on_label0_windows_of_excluded_hosts": float(a_mean[excl_int].sum()),
    }  # fmt: skip
    rep["seconds"] = round(time.perf_counter() - t_start, 1)
    FINAL_REPORT.write_text(json.dumps(rep, indent=1, default=str), "utf-8")
    print(
        json.dumps(
            {"H1": rep["H1"]["outcome"], "H2": {k: v["outcome"] for k, v in rep["H2"].items()}}
        )
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--n8", action="store_true")
    g.add_argument("--final", action="store_true")
    a = ap.parse_args()
    run_n8() if a.n8 else run_final()


if __name__ == "__main__":
    main()
