"""Phase 8i audit, POST-HOC [E]: how representative is each domain's benign calibration?

Fits nothing and chooses nothing: it reads the saved windows and the saved A1 scores
(reports/phase8i/**/<domain>__seed<k>_A1.npz) of every development domain and of N4
(NF-BoT-IoT-v3, consumed; its verdicts are fixed in reports/phase8i/confirm/verdicts.json).

Calibration side (no evaluation labels):
  hosts, sessions (a host's windows with gaps <= 30 min), largest host share, effective
  number of hosts (sum m)^2 / sum m^2, intra-session correlation of the A1 score and the
  effective sample size n / (1 + (m_w - 1) rho), the i.i.d. conformal FPR interval at the
  T0 rank (Beta(n + 1 - k, k)), and the host-grouped cross-conformal exceedance: T0 from the
  other hosts' hold-out windows, exceedance on the held-out hosts' windows (<= 10 host folds).
Evaluation side (uses the labels, so post-hoc; N4's are already consumed):
  realised A1 FPR (3 seeds), Kolmogorov-Smirnov distance of benign evaluation vs hold-out
  scores, false alerts of the top host, evaluation benign windows from hosts / days absent
  from calibration, hours between the hold-out and the evaluation benign windows.

Output: reports/phase8i/calibration_audit.json
Usage: uv run python scripts/phase8i/calibration_audit.py
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812

GAP_WINDOWS = 60  # 30 min of 30 s windows ends a session
FOLDS = 10
SCORES = {"nfbot": Path("reports/phase8i/confirm/exp_a")}
DEFAULT_SCORES = Path("reports/phase8i/exp_a")


def sessions(df: pl.DataFrame) -> np.ndarray:
    """Session id of each row (rows of one host split at gaps > GAP_WINDOWS)."""
    s = df.with_row_index("i").sort("key", "win").with_columns(
        ((pl.col("key") != pl.col("key").shift()) | (pl.col("win").diff() > GAP_WINDOWS))
        .fill_null(True).cum_sum().alias("sid"))  # fmt: skip
    return s.sort("i")["sid"].to_numpy()


def icc(x: np.ndarray, g: np.ndarray) -> float:
    """One-way random-effects intraclass correlation of x within groups g (clipped at 0)."""
    _, inv, m = np.unique(g, return_inverse=True, return_counts=True)
    k, n = len(m), len(x)
    if k < 2 or n <= k:
        return float("nan")
    means = np.bincount(inv, x) / m
    msb = float(np.sum(m * (means - x.mean()) ** 2) / (k - 1))
    msw = float(np.sum((x - means[inv]) ** 2) / (n - k))
    m0 = (n - np.sum(m**2) / n) / (k - 1)
    return max(0.0, (msb - msw) / (msb + (m0 - 1) * msw)) if msb + msw > 0 else 0.0


def eff_n(m: np.ndarray, rho: float) -> float:
    n = m.sum()
    return float(n / (1 + (np.sum(m**2) / n - 1) * rho)) if not math.isnan(rho) else float("nan")


def grouped_exceedance(s: np.ndarray, hosts: np.ndarray) -> dict:
    """T0 from the other host folds, exceedance on each held-out fold."""
    uniq, cnt = np.unique(hosts, return_counts=True)
    if len(uniq) < 2:
        return {"folds": 0}
    order = uniq[np.argsort(-cnt, kind="stable")]
    fold_of = {h: i % min(FOLDS, len(uniq)) for i, h in enumerate(order)}
    f = np.array([fold_of[h] for h in hosts])
    rows = []
    for k in np.unique(f):
        thr, ok = C.t0(s[f != k])
        rows.append((int((f == k).sum()), float((s[f == k] > thr).mean()), ok))
    w = np.array([r[0] for r in rows])
    e = np.array([r[1] for r in rows])
    return {"folds": len(rows), "exceedance": float(np.sum(w * e) / w.sum()),
            "max_fold_exceedance": float(e.max()),
            "all_folds_reliable": all(r[2] for r in rows)}  # fmt: skip


def iid_interval(n: int, alpha: float = C.ALPHA) -> dict:
    from scipy.stats import beta

    k = math.ceil((n + 1) * (1 - alpha))
    if k > n:
        return {"k": k, "note": "unreliable (k > n)"}
    a, b = n + 1 - k, k
    return {"k": k, "mean": a / (a + b), "p025": float(beta.ppf(0.025, a, b)),
            "p975": float(beta.ppf(0.975, a, b))}  # fmt: skip


def ks(a: np.ndarray, b: np.ndarray) -> float:
    from scipy.stats import ks_2samp

    return float(ks_2samp(a, b).statistic) if len(a) and len(b) else float("nan")


def audit(name: str, d: dict) -> dict | None:
    net, dom = name.split("/")
    base = SCORES.get(net, DEFAULT_SCORES) / f"{net}__{dom}"
    seeds = [np.load(f"{base}__seed{k}_A1.npz") for k in range(3)
             if Path(f"{base}__seed{k}_A1.npz").exists()]  # fmt: skip
    if not seeds:
        return None
    d = C.prepare(d)
    hold, btrain, ev = d["_hold"], d["_btrain"], d["ev"]
    assert len(seeds[0]["s_hold"]) == hold.height and len(seeds[0]["s_ev"]) == ev.height
    hosts = hold["key"].to_numpy()
    sid = sessions(hold)
    m_host = hold.group_by("key").len()["len"].to_numpy()
    m_sess = np.unique(sid, return_counts=True)[1]
    s0 = seeds[0]["s_hold"]
    rho_s, rho_h = icc(s0, sid), icc(s0, hosts)
    ben = ev.filter(pl.col("benign"))
    bmask = ev["benign"].to_numpy()
    day = 86_400_000
    cal_days = set((pl.concat([btrain, hold])["window_end_ms"] // day).to_list())
    fp = []
    for z in seeds:
        thr, _ = C.t0(z["s_hold"])
        alert = z["s_ev"][bmask] > thr
        per = ben.with_columns(pl.Series("a", alert)).group_by("key").agg(pl.col("a").sum())
        fp.append({"fpr": float(alert.mean()), "false_alerts": int(alert.sum()),
                   "top_host_share": float(per["a"].max() / alert.sum()) if alert.sum() else None,
                   "hosts_with_false_alerts": int((per["a"] > 0).sum())})  # fmt: skip
    return {
        "calibration": {
            "btrain_windows": btrain.height, "hold_windows": hold.height,
            "btrain_hosts": btrain["key"].n_unique(), "hold_hosts": len(m_host),
            "hold_sessions": len(m_sess), "largest_host_share": float(m_host.max() / m_host.sum()),
            "effective_hosts": float(m_host.sum() ** 2 / np.sum(m_host**2)),
            "icc_session": rho_s, "icc_host": rho_h,
            "n_eff_session": eff_n(m_sess, rho_s), "n_eff_host": eff_n(m_host, rho_h),
            "iid_conformal_fpr": iid_interval(hold.height),
            "host_grouped_exceedance": grouped_exceedance(s0, hosts),
            "hold_days": len(set((hold["window_end_ms"] // day).to_list())),
        },
        "evaluation_posthoc": {
            "benign_windows": ben.height, "benign_hosts": ben["key"].n_unique(),
            "a1_by_seed": fp, "a1_fpr_mean": float(np.mean([f["fpr"] for f in fp])),
            "ks_benign_vs_hold_seed0": ks(seeds[0]["s_ev"][bmask], s0),
            "benign_windows_from_hosts_not_in_hold": float(
                (~ben["key"].is_in(hold["key"].unique().to_list())).mean()) if ben.height else None,
            "benign_windows_on_days_without_calibration": float(
                (~(ben["window_end_ms"] // day).is_in(list(cal_days))).mean()) if ben.height else None,
            "hours_hold_end_to_first_benign_eval": float(
                (ben["window_end_ms"].min() - hold["window_end_ms"].max()) / 3.6e6) if ben.height else None,
            "benign_eval_span_hours": float(
                (ben["window_end_ms"].max() - ben["window_end_ms"].min()) / 3.6e6) if ben.height else None,
        },
    }  # fmt: skip


def main() -> None:
    out = {"label": "[E post-hoc audit] calibration representativeness; fits nothing, changes no verdict",
           "domains": {}}  # fmt: skip
    for net in ("nfcic", "nfunsw", "nfton", "nfbot"):
        for name, d in C.load_network(net).items():
            r = audit(name, d)
            if r:
                out["domains"][name] = r
                c, e = r["calibration"], r["evaluation_posthoc"]
                g = c["host_grouped_exceedance"]
                print(f"{name:20s} hold {c['hold_windows']:6d} hosts {c['hold_hosts']:5d} "
                      f"eff.hosts {c['effective_hosts']:7.1f} n_eff(sess) {c['n_eff_session']:8.1f} "
                      f"grouped exc {g.get('exceedance', float('nan')):.3f} | "
                      f"A1 FPR {e['a1_fpr_mean']:.3f} KS {e['ks_benign_vs_hold_seed0']:.2f}",
                      flush=True)  # fmt: skip
    C.dump(Path("reports/phase8i/calibration_audit.json"), out)


if __name__ == "__main__":
    main()
