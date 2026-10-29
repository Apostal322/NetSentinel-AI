"""Phase 8h [E]: leave-one-domain-out evaluation (docs/phase8h/PREREGISTRATION.md, A1).

For every held-out domain of a telemetry family (Zeek, NetFlow), the supervised scorers are
trained on the OTHER domains of the same family; the robust baseline is fitted on the held-out
domain's own calibration windows. Everything is scored on identical device windows.

Scorers
  B-rz   product robust baseline (calibrate_windows, top-2 |z|), fitted on the first 70% of the
         target's clean calibration windows; the last 30% is the threshold hold-out. The
         deployed cross-fit threshold (fitted on all calibration windows) is also reported.
  B-lr   logistic regression on locally standardised features (clipped to +-10)
  B-raw  LightGBM on the 12 raw features (Phase 8b settings)
  B-loc  LightGBM on locally standardised features
  N-dis  LightGBM on the locally standardised features kept by domain-invariance screening
Thresholds (alpha = 1%): T0 split-conformal on the hold-out; T1 90% moving-block-bootstrap
upper bound (blocks of 20 window slots); T2 own-profile / pooled populations; T3 T1 with
abstention when the bootstrap 90% interval is wider than 50% of T0.
Fusion: F-or (B-loc or B-rz, each at alpha / 2), F-and (both at alpha).

Output: reports/phase8h/lodo/<family>__<domain>.json (one per held-out domain).
Usage: uv run python scripts/phase8h/lodo.py [--family netflow|zeek] [--domains a,b]
       [--seeds 0,1,2] [--h2-only]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from itertools import combinations
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
import scorers as S  # noqa: E402, N812

from netsentinel.behavior.profile import conformal_threshold  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

FEATS = S.FEATS
ALPHA = 0.01
CAP = 200_000  # training windows per source domain (pre-registration section 8)
BLOCK = 20  # window slots per bootstrap block (10 min)
N_BOOT = 1000
OUT = Path("reports/phase8h/lodo")
PRIMARY = {"netflow": ["nfcic_2018-02-14", "nfcic_2018-02-16", "nfcic_2018-02-20",
                       "nfcic_2018-02-21", "nfcic_2018-03-02", "NF-UNSW-NB15-v3-dev"],
           "zeek": ["CTU-IoT-Malware-Capture-3-1", "CTU-IoT-Malware-Capture-34-1",
                    "CTU-IoT-Malware-Capture-8-1"]}  # fmt: skip
SECONDARY = {"netflow": ["nfcic_2018-02-22"], "zeek": []}


# ----------------------------------------------------------------------------- data
def _load(d: Path) -> dict:
    ev = pl.read_parquet(d / "eval_clean.parquet").sort("win", "key")
    tr = pl.read_parquet(d / "truth.parquet").select("key", "win", "y")
    ev = ev.join(tr, on=["key", "win"], how="left").with_columns(pl.col("y").fill_null(False))
    noisy = d / "noisy.parquet"
    if noisy.exists():
        nz = pl.read_parquet(noisy).with_columns(pl.lit(True).alias("noisy"))
        ev = ev.join(nz, on=["key", "win"], how="left")
    ev = ev.with_columns(pl.col("noisy").fill_null(False) if "noisy" in ev.columns
                         else pl.lit(False).alias("noisy"))  # fmt: skip
    ev = ev.with_columns((pl.col("y") & ~pl.col("noisy")).alias("y"))
    attackers = set(ev.filter(pl.col("y"))["key"].unique().to_list())
    ev = ev.with_columns(
        (~pl.col("key").is_in(list(attackers)) & ~pl.col("noisy")).alias("benign"))  # fmt: skip
    meta = json.loads((d / "meta.json").read_text("utf-8"))
    cal = pl.read_parquet(d / "cal_clean.parquet").sort("win", "key")
    return {"cal": cal, "ev": ev, "attackers": attackers, "hours": meta.get("eval_hours") or 0.0,
            "first_attack": {k: v for k, v in (meta.get("first_attack_ms") or {}).items()
                             if k in attackers}}  # fmt: skip


def domains(family: str) -> dict[str, dict]:
    out = {}
    if family == "netflow":
        for d in sorted(Path("data/derived/phase8h/nf_cic").iterdir()):
            out[f"nfcic_{d.name}"] = _load(d)
        out["NF-UNSW-NB15-v3-dev"] = _load(Path("data/derived/phase8b/NF-UNSW-NB15-v3-dev"))
    else:
        for d in sorted(Path("data/derived/phase8b").iterdir()):
            if d.name != "NF-UNSW-NB15-v3-dev":
                out[d.name] = _load(d)
    return {k: v for k, v in out.items() if v["cal"].height >= 60 and v["ev"].height >= 60}


def attack_eligible(d: dict) -> bool:
    if not d["attackers"]:
        return False
    per = d["ev"].filter(pl.col("y")).group_by("key").len()
    return bool((per["len"] >= 5).any())


# ----------------------------------------------------------------------------- features
def clip_local(sc, x: np.ndarray) -> np.ndarray:
    return np.clip(sc.transform(x), -10, 10)


def screen(sources: dict[str, dict], rng_seed: int = 0) -> tuple[list[int], list[float]]:
    """Domain-invariance screening on source BENIGN calibration windows only."""
    from scipy.stats import wasserstein_distance

    rng = np.random.default_rng(rng_seed)
    zs = []
    for d in sources.values():
        x = S._x(d["cal"])
        z = clip_local(S.local_scaler(d["cal"]), x)
        if len(z) > 5000:
            z = z[rng.choice(len(z), 5000, replace=False)]
        zs.append(z)
    inst = []
    for f in range(len(FEATS)):
        ds = [wasserstein_distance(a[:, f], b[:, f]) for a, b in combinations(zs, 2)]
        inst.append(float(np.median(ds)) if ds else 0.0)
    cut = float(np.median(inst))
    return [f for f, v in enumerate(inst) if v <= cut], inst


def train_matrix(d: dict, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(raw X, local X, y) of a source domain: clean calibration (benign) + evaluation."""
    ev = d["ev"].filter(~pl.col("noisy"))
    x = np.vstack([S._x(d["cal"]), S._x(ev)])
    y = np.concatenate([np.zeros(d["cal"].height), ev["y"].to_numpy()]).astype(int)
    if len(y) > CAP:
        rng = np.random.default_rng(seed)
        pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
        pos = rng.choice(pos, min(len(pos), CAP // 2), replace=False)
        neg = rng.choice(neg, min(len(neg), CAP - len(pos)), replace=False)
        idx = np.sort(np.concatenate([pos, neg]))
        x, y = x[idx], y[idx]
    return x, clip_local(S.local_scaler(d["cal"]), x), y


def fit_models(sources: dict[str, dict], seed: int, keep: list[int]) -> dict:
    import lightgbm as lgb
    from sklearn.linear_model import LogisticRegression

    xr, xl, ys, ws = [], [], [], []
    for d in sources.values():
        a, b, y = train_matrix(d, seed)
        xr.append(a)
        xl.append(b)
        ys.append(y)
        ws.append(np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
    Xr, Xl, y, w = np.vstack(xr), np.vstack(xl), np.concatenate(ys), np.concatenate(ws)  # noqa: N806
    w = w * len(y)

    def lgbm(X):  # noqa: N803
        m = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15,
                               min_child_samples=20, subsample=0.8, subsample_freq=1,
                               colsample_bytree=0.8, random_state=seed, n_jobs=2, verbose=-1)  # fmt: skip
        return m.fit(X, y, sample_weight=w)

    t0 = time.perf_counter()
    models = {"B-raw": (lgbm(Xr), "raw", None), "B-loc": (lgbm(Xl), "loc", None),
              "N-dis": (lgbm(Xl[:, keep]), "loc", keep)}  # fmt: skip
    lr = LogisticRegression(C=1.0, max_iter=2000).fit(Xl, y, sample_weight=w)
    models["B-lr"] = (lr, "loc", None)
    models["_fit_s"] = time.perf_counter() - t0
    models["_train_rows"] = len(y)
    return models


def score_target(models: dict, tgt: dict) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    sc = S.local_scaler(tgt["cal"])
    xe, xc = S._x(tgt["ev"]), S._x(tgt["cal"])
    out = {}
    for name, (m, kind, keep) in ((k, v) for k, v in models.items() if not k.startswith("_")):
        ae, ac = (xe, xc) if kind == "raw" else (clip_local(sc, xe), clip_local(sc, xc))
        if keep is not None:
            ae, ac = ae[:, keep], ac[:, keep]
        out[name] = (m.predict_proba(ae)[:, 1], m.predict_proba(ac)[:, 1])
    return out


def robust_baseline(tgt: dict) -> dict:
    """B-rz fitted on the first 70% of calibration; scores of the hold-out and evaluation."""
    cal = tgt["cal"]
    cut = S.split_cut(cal)
    fit, hold = cal.filter(pl.col("win") < cut), cal.filter(pl.col("win") >= cut)
    # scored separately: the window holding the calibration/evaluation midpoint exists in both
    # (same key and win), so one joined call would duplicate it; the fit is deterministic
    s_hold, _ = S.product(fit, hold)
    s_ev, _ = S.product(fit, tgt["ev"])
    s_dep, thr_dep = S.product(cal, tgt["ev"])  # deployed: cross-fit on all calibration
    assert len(s_hold) == hold.height and len(s_ev) == tgt["ev"].height
    return {"ev": s_ev, "cal": s_hold, "deployed": (s_dep, thr_dep)}


# ----------------------------------------------------------------------------- thresholds
def hold_mask(tgt: dict) -> np.ndarray:
    return (tgt["cal"]["win"] >= S.split_cut(tgt["cal"])).to_numpy()


def boot_thresholds(scores: np.ndarray, slots: np.ndarray, alpha: float, seed: int = 0):
    uniq = np.unique(slots)
    if len(uniq) < 2 * BLOCK or len(scores) == 0:
        return None
    rng = np.random.default_rng(seed)
    pos = np.searchsorted(uniq, slots)
    order = np.argsort(pos, kind="stable")
    bounds = np.searchsorted(pos[order], np.arange(len(uniq) + 1))
    nb = math.ceil(len(uniq) / BLOCK)
    out = np.empty(N_BOOT)
    for b in range(N_BOOT):
        starts = rng.integers(0, len(uniq) - BLOCK + 1, nb)
        idx = np.concatenate([order[bounds[s] : bounds[s + BLOCK]] for s in starts])
        out[b] = conformal_threshold(scores[idx], alpha)[0]
    return out


def thresholds(s_hold: np.ndarray, slots: np.ndarray, own_hold: np.ndarray,
               alpha: float = ALPHA) -> dict:  # fmt: skip
    t0, rel = conformal_threshold(s_hold, alpha)
    bt = boot_thresholds(s_hold, slots, alpha)
    out = {"T0": t0, "T0_reliable": rel, "n_hold": len(s_hold)}
    if bt is None:
        out.update(T1=t0, T3_abstain=True, boot_width=None)
    else:
        q05, q90, q95 = np.quantile(bt, [0.05, 0.90, 0.95])
        # registered T1 = the bootstrap 90% bound itself (amendment A3: an unregistered floor at
        # T0 was removed; it made T1 >= T0 by construction)
        out.update(T1=float(q90), T1_floored_at_T0=float(max(q90, t0)),
                   boot_width=float(q95 - q05),
                   T3_abstain=bool(t0 > 0 and (q95 - q05) > 0.5 * t0))  # fmt: skip
    pops = {}
    for name, m in (("own", own_hold), ("pooled", ~own_hold)):
        pops[name] = conformal_threshold(s_hold[m], alpha)[0] if m.sum() >= 30 else t0
    out["T2"] = pops
    return out


# ----------------------------------------------------------------------------- metrics
def metrics(tgt: dict, s: np.ndarray, alert: np.ndarray) -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score

    ev = tgt["ev"]
    y, ben = ev["y"].to_numpy(), ev["benign"].to_numpy()
    keys = ev["key"].to_numpy()
    out = {"fpr": float(alert[ben].mean()) if ben.any() else None,
           "false_alerts_per_h": float(alert[ben].sum() / tgt["hours"]) if tgt["hours"] else None,
           "window_recall": float(alert[y].mean()) if y.any() else None}  # fmt: skip
    if y.any() and ben.any():
        lab = np.concatenate([np.ones(y.sum()), np.zeros(ben.sum())])
        sc = np.concatenate([s[y], s[ben]])
        out["pr_auc"] = float(average_precision_score(lab, sc))
        out["roc_auc"] = float(roc_auc_score(lab, sc))
        t_or = np.quantile(s[ben], 1 - ALPHA)
        hit = s > t_or
        out["oracle_recall_at_fpr1"] = float(hit[y].mean())
        ents = sorted(tgt["attackers"])
        out["oracle_entity_macro_recall"] = float(np.mean(
            [hit[y & (keys == e)].mean() for e in ents if (y & (keys == e)).any()]))  # fmt: skip
        out["oracle_entities_detected"] = int(sum((hit & y & (keys == e)).any() for e in ents))
    if tgt["attackers"]:
        end = ev["window_end_ms"].to_numpy()
        det, delays = 0, []
        for e in tgt["attackers"]:
            m = y & (keys == e)
            if (alert & m).any():
                det += 1
                delays.append((end[alert & m].min() - end[m].min()) / 1000)
        out["entities"] = len(tgt["attackers"])
        out["entities_detected"] = det
        out["entity_recall"] = det / len(tgt["attackers"])
        out["median_delay_s"] = float(np.median(delays)) if delays else None
    return out


def own_mask(tgt: dict, frame: pl.DataFrame) -> np.ndarray:
    counts = tgt["cal"].group_by("key").len()
    own = set(counts.filter(pl.col("len") >= 30)["key"].to_list())
    return frame["key"].is_in(list(own)).to_numpy()


def operating(tgt: dict, s_ev: np.ndarray, s_cal: np.ndarray) -> dict:
    hm = hold_mask(tgt)
    hold = tgt["cal"].filter(pl.Series(hm))
    th = thresholds(s_cal[hm], hold["win"].to_numpy(), own_mask(tgt, hold))
    own_ev = own_mask(tgt, tgt["ev"])
    t2 = np.where(own_ev, th["T2"]["own"], th["T2"]["pooled"])
    res = {"thresholds": th}
    for name, a in (("T0", s_ev > th["T0"]), ("T1", s_ev > th["T1"]), ("T2", s_ev > t2)):
        res[name] = metrics(tgt, s_ev, a)
    res["T3"] = {"abstain": th["T3_abstain"], **({} if th["T3_abstain"] else res["T1"])}
    return res


def fusion(tgt: dict, a: tuple, b: tuple) -> dict:
    hm = hold_mask(tgt)
    ta = conformal_threshold(a[1][hm], ALPHA / 2)[0]
    tb = conformal_threshold(b[1][hm], ALPHA / 2)[0]
    ta1 = conformal_threshold(a[1][hm], ALPHA)[0]
    tb1 = conformal_threshold(b[1][hm], ALPHA)[0]
    aa, ab = a[0] > ta, b[0] > tb
    keys, y = tgt["ev"]["key"].to_numpy(), tgt["ev"]["y"].to_numpy()
    only_a = sum(bool((aa & y & (keys == e)).any() and not (ab & y & (keys == e)).any())
                 for e in tgt["attackers"])  # fmt: skip
    only_b = sum(bool((ab & y & (keys == e)).any() and not (aa & y & (keys == e)).any())
                 for e in tgt["attackers"])  # fmt: skip
    rank = np.maximum(a[0] / max(ta, 1e-12), b[0] / max(tb, 1e-12))
    return {"F-or": metrics(tgt, rank, aa | ab),
            "F-and": metrics(tgt, np.minimum(a[0] / max(ta1, 1e-12), b[0] / max(tb1, 1e-12)),
                             (a[0] > ta1) & (b[0] > tb1)),
            "entities_only_A_at_half_alpha": only_a, "entities_only_B_at_half_alpha": only_b}  # fmt: skip


def mean_dict(ds: list[dict]):
    """Average numeric leaves of equally shaped dicts (seeds)."""
    if not ds:
        return None
    if isinstance(ds[0], dict):
        return {k: mean_dict([d.get(k) for d in ds]) for k in ds[0]}
    vals = [d for d in ds if isinstance(d, (int, float)) and not isinstance(d, bool)]
    if len(vals) == len(ds):
        return float(np.mean(vals))
    return ds[0]


# ----------------------------------------------------------------------------- fold
def run_fold(family: str, name: str, doms: dict, seeds: list[int], h2_only: bool) -> dict:
    t0 = time.perf_counter()
    tgt = doms[name]
    out = {"family": family, "domain": name, "eval_windows": tgt["ev"].height,
           "benign_windows": int(tgt["ev"]["benign"].sum()),
           "attack_windows": int(tgt["ev"]["y"].sum()), "attackers": len(tgt["attackers"]),
           "attack_eligible": attack_eligible(tgt), "eval_hours": tgt["hours"],
           "role": "primary" if name in PRIMARY[family] else
                   "secondary" if name in SECONDARY[family] else "benign_unit"}  # fmt: skip
    rz = robust_baseline(tgt)
    out["B-rz"] = operating(tgt, rz["ev"], np.concatenate([np.full(int((~hold_mask(tgt)).sum()),
                                                                   np.nan), rz["cal"]]))  # fmt: skip
    s_dep, thr_dep = rz["deployed"]
    out["B-rz"]["deployed_crossfit"] = {"threshold": thr_dep,
                                        **metrics(tgt, s_dep, s_dep > thr_dep)}  # fmt: skip
    if h2_only or out["role"] == "benign_unit":
        out["seconds"] = time.perf_counter() - t0
        return out
    sources = {k: v for k, v in doms.items() if k != name}
    keep, inst = screen(sources)
    out["screening"] = {"kept": [FEATS[i] for i in keep],
                        "instability": dict(zip(FEATS, inst, strict=True))}  # fmt: skip
    per_seed = []
    for seed in seeds:
        models = fit_models(sources, seed, keep)
        sc = score_target(models, tgt)
        r = {"fit_s": models["_fit_s"], "train_rows": models["_train_rows"]}
        for m, (se, scal) in sc.items():
            r[m] = operating(tgt, se, scal)
        cal_rz = np.concatenate([np.full(int((~hold_mask(tgt)).sum()), np.nan), rz["cal"]])
        r["fusion"] = fusion(tgt, sc["B-loc"], (rz["ev"], cal_rz))
        per_seed.append(r)
    out["seeds"] = seeds
    out["supervised"] = mean_dict(per_seed)
    out["per_seed"] = per_seed
    out["seconds"] = time.perf_counter() - t0
    return out


def main() -> None:
    global CAP, OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", choices=("netflow", "zeek"), action="append")
    ap.add_argument("--domains")
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--h2-only", action="store_true")
    ap.add_argument("--cap", type=int, default=CAP, help="smoke runs only; default = registered")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    CAP, OUT = a.cap, Path(a.out)
    seeds = [int(s) for s in a.seeds.split(",")]
    OUT.mkdir(parents=True, exist_ok=True)
    for family in a.family or ("netflow", "zeek"):
        doms = domains(family)
        names = a.domains.split(",") if a.domains else list(doms)
        for name in (n for n in names if n in doms):
            r = run_fold(family, name, doms, seeds, a.h2_only)
            r["peak_rss_mb"] = peak_rss_mb()
            (OUT / f"{family}__{name}.json").write_text(json.dumps(r, indent=1, default=str),
                                                        "utf-8")  # fmt: skip
            print(
                family,
                name,
                r["role"],
                f"{r['seconds']:.0f}s",
                f"rss {r['peak_rss_mb']:.0f} MB",
                flush=True,
            )


if __name__ == "__main__":
    main()
