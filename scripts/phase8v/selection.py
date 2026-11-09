"""Phase 8v pure helpers: source-side invariant-direction selection, the permutation control and
the registered comparison rules (docs/phase8v/PREREGISTRATION.md §§ 4-6). Pure numpy.

**Invariant-direction selection (`invariant_columns`).** For one leave-one-network-out fit,
using only that fit's TRAINING rows and labels:
- per source network, the univariate ROC-AUC of each column (attack vs benign training rows;
  missing values dropped);
- a column is **conflicting** when two source networks put it on opposite sides of 0.5 by at
  least `margin` each; conflicting columns are dropped, every other column is kept.
No target-network data and no evaluation label is involved.
"""

from __future__ import annotations

import zlib

import numpy as np

NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
HARD = ("nfunsw", "nfton")
SEEDS = (1060, 1061, 1062)
FAMILIES = ("FLOW", "TIME", "BIDIR", "INV", "ALL")


def auc(pos: np.ndarray, neg: np.ndarray) -> float:
    """Mann-Whitney AUC with average ranks (ties count one half)."""
    if pos.size == 0 or neg.size == 0:
        return float("nan")
    v = np.r_[pos, neg]
    o = np.argsort(v, kind="mergesort")
    sv = v[o]
    starts = np.r_[0, np.flatnonzero(np.diff(sv)) + 1]
    ends = np.r_[starts[1:], sv.size]
    r = np.empty(v.size)
    r[o] = np.repeat((starts + ends - 1) / 2 + 1, ends - starts)
    return float((r[: pos.size].sum() - pos.size * (pos.size + 1) / 2) / (pos.size * neg.size))


def invariant_columns(
    x: np.ndarray, y: np.ndarray, network: np.ndarray, margin: float = 0.1
) -> tuple[np.ndarray, dict]:
    """(kept column mask, per-column {network: AUC}) from training rows only."""
    nets = [
        n
        for n in np.unique(network)
        if (y[network == n] == 1).any() and (y[network == n] == 0).any()
    ]
    keep = np.ones(x.shape[1], bool)
    table: dict = {}
    for j in range(x.shape[1]):
        a = {}
        for n in nets:
            m = (network == n) & ~np.isnan(x[:, j])
            a[str(n)] = auc(x[m & (y == 1), j], x[m & (y == 0), j])
        table[j] = a
        vals = [v - 0.5 for v in a.values() if not np.isnan(v)]
        up = any(v >= margin for v in vals)
        down = any(v <= -margin for v in vals)
        keep[j] = not (up and down)
    return keep, table


def permute_columns(x: np.ndarray, tag: str) -> np.ndarray:
    """Each column permuted independently across the rows of one domain (deterministic)."""
    out = x.copy()
    for j in range(x.shape[1]):
        rng = np.random.default_rng([zlib.crc32(tag.encode()), j])
        out[:, j] = x[rng.permutation(x.shape[0]), j]
    return out


def compare(c: dict, b: dict) -> dict:
    """Registered comparison of a candidate summary with its matched baseline summary."""
    dp = {n: c["networks"][n]["pauc_1pct"] - b["networks"][n]["pauc_1pct"] for n in NETS}
    dr = {n: c["networks"][n]["recall_1pct"] - b["networks"][n]["recall_1pct"] for n in NETS}
    guard = {"no_catastrophic_regression": all(dr[n] >= -0.10 for n in NETS),
             "calT_macro_recall": c["macro_calT_recall"] >= b["macro_calT_recall"] - 0.03,
             "calT_fpr": all(c["networks"][n]["calT_fpr"] <= b["networks"][n]["calT_fpr"] + 0.01 for n in NETS),
             "missed_entities": c["missed_calT"] <= b["missed_calT"] + 2}  # fmt: skip
    return {"d_pauc": dp, "d_recall_1pct": dr, "d_hard_pauc": float(np.mean([dp[n] for n in HARD])),
            "d_macro_pauc": float(np.mean(list(dp.values()))),
            "d_macro_recall_1pct": float(np.mean(list(dr.values()))), "guardrails": guard,
            "guardrails_ok": all(guard.values()), "networks_improved": int(sum(v > 0 for v in dp.values()))}  # fmt: skip


def decide(summary: dict) -> dict:
    """Screening, replication and control decisions from {'<variant>|<seed>': summary}."""
    out: dict = {"screening": {}, "replication": {}, "control": {}}
    s0 = SEEDS[0]
    for fam in FAMILIES:
        if f"{fam}|{s0}" in summary:
            c = compare(summary[f"{fam}|{s0}"], summary[f"M2member|{s0}"])
            c["passes"] = bool(
                c["d_hard_pauc"] >= 0.02 and c["d_macro_pauc"] >= 0.0 and c["guardrails_ok"]
            )
            out["screening"][fam] = c
    passing = {f: v["d_hard_pauc"] for f, v in out["screening"].items() if v["passes"]}
    out["replicate_next"] = max(passing, key=passing.get) if passing else None
    for fam in FAMILIES:
        if all(f"{fam}|{s}" in summary for s in SEEDS):
            cs = [compare(summary[f"{fam}|{s}"], summary[f"M2member|{s}"]) for s in SEEDS]
            r = {"seeds": list(SEEDS), "d_hard_pauc": [c["d_hard_pauc"] for c in cs],
                 "d_macro_pauc": [c["d_macro_pauc"] for c in cs],
                 "mean_d_hard_pauc": float(np.mean([c["d_hard_pauc"] for c in cs])),
                 "mean_d_macro_pauc": float(np.mean([c["d_macro_pauc"] for c in cs])),
                 "mean_d_pauc_by_network": {n: float(np.mean([c["d_pauc"][n] for c in cs])) for n in NETS},
                 "guardrails_every_seed": all(c["guardrails_ok"] for c in cs)}  # fmt: skip
            r["replicated"] = bool(r["mean_d_hard_pauc"] >= 0.02 and all(v > 0 for v in r["d_hard_pauc"])
                                   and r["mean_d_macro_pauc"] >= 0.0 and r["guardrails_every_seed"])  # fmt: skip
            r["g5_cross_network"] = bool(r["replicated"] and sum(v > 0 for v in r["mean_d_pauc_by_network"].values()) >= 3
                                         and all(r["mean_d_pauc_by_network"][n] > 0 for n in HARD))  # fmt: skip
            out["replication"][fam] = r
        pk = f"PERM_{fam}|{s0}"
        if pk in summary and fam in out["screening"]:
            real = out["screening"][fam]["d_hard_pauc"]
            perm = compare(summary[pk], summary[f"M2member|{s0}"])["d_hard_pauc"]
            out["control"][fam] = {"perm_d_hard_pauc": perm, "real_d_hard_pauc": real,
                                   "retained_share": perm / real if real > 0 else None,
                                   "shortcut_ruled_out": bool(real > 0 and perm < 0.5 * real)}  # fmt: skip
    return out
