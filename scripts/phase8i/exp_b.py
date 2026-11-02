"""Phase 8i Experiment B (I2): does an unsupervised shift score mark one-hour evaluation blocks
whose false-alert rate overruns the budget? (docs/phase8i/PREREGISTRATION.md section 5)

Detector: the deployed robust baseline B-rz (fit = first 70% of the benign calibration slots,
T0 threshold on the last 30%). Secondary: the Experiment A source model (A1, seed 0) on the
cross-network units, read from its saved scores.
Units: one-hour evaluation blocks (after the first evaluation hour) with >= 30 benign windows,
in every domain with >= 60 benign evaluation windows: the NetFlow development networks and
the Phase 8h Zeek units (IoT-23 and CTU-Normal, data/derived/phase8b).
Outcome: block benign FPR > 2%. Scores (no labels): S_score, S_feat, S_cal, S_n.

Output: reports/phase8i/exp_b/blocks.json (one row per block) and summary.json
Usage: uv run python scripts/phase8i/exp_b.py [--confirm]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("reports/phase8i/exp_b")
MIN_BENIGN_BLOCK = 30
SCORES = ("S_score", "S_feat", "S_cal", "S_n")


def ks(a: np.ndarray, b: np.ndarray) -> float:
    from scipy.stats import ks_2samp

    return float(ks_2samp(a, b).statistic) if len(a) and len(b) else float("nan")


def median_feature_ks(sc, a: pl.DataFrame, b: pl.DataFrame) -> float:
    xa, xb = C.L.clip_local(sc, C.S._x(a)), C.L.clip_local(sc, C.S._x(b))
    return float(np.nanmedian([ks(xa[:, f], xb[:, f]) for f in range(xa.shape[1])]))


def domain_blocks(name: str, d: dict, s_ev: np.ndarray, s_hold: np.ndarray, thr: float,
                  detector: str) -> list[dict]:  # fmt: skip
    C.prepare(d)
    ev, hold, btrain = d["ev"], d["_hold"], d["_btrain"]
    sc = C.S.local_scaler(btrain)
    s_cal = median_feature_ks(sc, btrain, hold)
    end = ev["window_end_ms"].to_numpy()
    blk = C.blocks(end, int(end.min()) + 3_600_000)
    ben, y = ev["benign"].to_numpy(), ev["y"].to_numpy()
    alert = s_ev > thr
    rows = []
    for b in np.unique(blk[blk >= 0]):
        m = blk == b
        if (m & ben).sum() < MIN_BENIGN_BLOCK:
            continue
        fpr = float(alert[m & ben].mean())
        rows.append({"domain": name, "network": d["network"], "detector": detector,
                     "block": int(b), "benign": int((m & ben).sum()), "attack": int((m & y).sum()),
                     "attack_alerts": int((m & y & alert).sum()), "fpr": fpr,
                     "overrun": fpr > 2 * C.ALPHA, "n_hold": hold.height,
                     "S_score": ks(s_hold, s_ev[m]),
                     "S_feat": median_feature_ks(sc, hold, ev.filter(pl.Series(m))),
                     "S_cal": s_cal, "S_n": 1.0 / max(hold.height, 1)})  # fmt: skip
    return rows


def domains(confirm: bool, net: str = "nfbot") -> dict[str, dict]:
    if confirm:
        return C.load_network(net)
    out = {k: v for n in C.DEV_NETWORKS for k, v in C.load_network(n).items()}
    for d in sorted(Path("data/derived/phase8b").iterdir()):
        if d.name != "NF-UNSW-NB15-v3-dev" and (d / "meta.json").exists():
            dom = C.load_domain(d, "zeek")
            if dom["cal"].height >= 60 and dom["ev"].height >= 60:
                out[f"zeek/{d.name}"] = dom
    return {k: v for k, v in out.items() if int(v["ev"]["benign"].sum()) >= 60}


def boot_auc(rows: list[dict], score: str, n_boot: int = 1000, seed: int = 0):
    """Domain-level bootstrap of the pooled block AUC (blocks within a domain correlate)."""
    doms = sorted({r["domain"] for r in rows})
    by = {d: [r for r in rows if r["domain"] == d] for d in doms}
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n_boot):
        pick = [r for d in rng.choice(doms, len(doms)) for r in by[d]]
        a = C.auc(np.array([r[score] for r in pick]), np.array([r["overrun"] for r in pick]))
        if a is not None:
            vals.append(a)
    return [float(np.quantile(vals, 0.025)), float(np.quantile(vals, 0.975))] if vals else None


def summarize(rows: list[dict]) -> dict:
    if not rows:
        return {"blocks": 0}
    ov = np.array([r["overrun"] for r in rows])
    out = {"blocks": len(rows), "domains": len({r["domain"] for r in rows}),
           "overrun_rate": float(ov.mean()), "scores": {}}  # fmt: skip
    for s in SCORES:
        v = np.array([r[s] for r in rows], dtype=float)
        out["scores"][s] = {"auc": C.auc(v, ov), "auc_ci_domain_boot": boot_auc(rows, s),
                            "risk_coverage": C.risk_coverage(v, ov)}  # fmt: skip
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tau", type=float, help="confirmatory: the S_score cut fixed on development")
    C.confirm_args(ap)
    a = ap.parse_args()
    out = Path(a.out) if a.out else OUT
    C.confirm_guard(a)
    t0 = time.perf_counter()
    rows = []
    for name, d in domains(a.confirm, a.stand_in or "nfbot").items():
        C.prepare(d)
        s_hold, _ = C.S.product(d["_btrain"], d["_hold"])
        s_ev, _ = C.S.product(d["_btrain"], d["ev"])
        thr, _ = C.t0(s_hold)
        rows += domain_blocks(name, d, s_ev, s_hold, thr, "B-rz")
        npz = Path("reports/phase8i/exp_a") / f"{name.replace('/', '__')}__seed0_A1.npz"
        if npz.exists() and not a.confirm:
            z = np.load(npz)
            rows += domain_blocks(name, d, z["s_ev"], z["s_hold"], C.t0(z["s_hold"])[0], "A1")
        print(name, sum(r["domain"] == name for r in rows), flush=True)
    rz = [r for r in rows if r["detector"] == "B-rz"]
    summary = {"B-rz": summarize(rz), "A1": summarize([r for r in rows if r["detector"] == "A1"])}
    if not a.confirm and rz:
        v = np.array([r["S_score"] for r in rz])
        summary["tau_S_score_60pct"] = float(np.quantile(v, 0.6))
    if a.confirm and a.tau is not None and rz:
        v = np.array([r["S_score"] for r in rz])
        ov = np.array([r["overrun"] for r in rz])
        cov = v <= a.tau
        att = np.array([r["attack"] for r in rz])
        summary["confirm"] = {"tau": a.tau, "coverage": float(cov.mean()),
                              "exceedance_covered": float(ov[cov].mean()) if cov.any() else None,
                              "exceedance_all": float(ov.mean()),
                              "attack_share_abstained": float(att[~cov].sum() / max(att.sum(), 1))}  # fmt: skip
    C.dump(out / "blocks.json", rows)
    C.dump(out / "summary.json", {**summary, "seconds": time.perf_counter() - t0,
                                  "peak_rss_mb": peak_rss_mb()})  # fmt: skip


if __name__ == "__main__":
    main()
