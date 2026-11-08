"""Phase 8t threshold oracles (docs/phase8t/PREREGISTRATION.md § 4). Pure numpy.

Convention: a window alerts when its score is strictly greater than the threshold. A threshold
of −inf alerts on everything in its group; +inf alerts on nothing.

- `global_threshold`: the largest-recall single threshold whose benign false alerts are ≤ B: the
  (B + 1)-th largest benign score (ties can only lower the count).
- `group_curve`: for one group, every threshold at a benign score (and −inf), with its exact false
  alerts and true positives.
- `allocate`: multiple-choice knapsack. One option per group, Σ false alerts ≤ B, maximise Σ true
  positives; exact dynamic programme over the integer budget.
"""

from __future__ import annotations

import numpy as np


def _finite(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    if not np.isfinite(x).all():
        raise ValueError("non-finite scores")
    return x


def global_threshold(benign: np.ndarray, budget: int) -> float:
    b = np.sort(_finite(benign))[::-1]
    if budget < 0:
        raise ValueError("negative budget")
    if budget >= b.size:
        return -np.inf
    return float(b[budget])


def count_above(sorted_scores: np.ndarray, t: float) -> int:
    return int(sorted_scores.size - np.searchsorted(sorted_scores, t, side="right"))


def group_curve(benign: np.ndarray, pos: np.ndarray, max_fa: int) -> dict:
    """Options for one group: thresholds at the (j+1)-th largest benign score for j < n_benign,
    plus −inf (every window alerts). Costs are exact false-alert counts (ties included)."""
    b = np.sort(_finite(benign))
    p = np.sort(_finite(pos))
    desc = b[::-1]
    j = np.arange(min(max_fa, b.size - 1) + 1) if b.size else np.array([], dtype=int)
    t = desc[j] if b.size else np.array([])
    t = np.r_[np.inf, t, -np.inf] if b.size else np.array([np.inf, -np.inf])
    t = np.unique(t)[::-1]  # descending, distinct
    fa = b.size - np.searchsorted(b, t, side="right")
    tp = p.size - np.searchsorted(p, t, side="right")
    keep = fa <= max_fa
    return {"t": t[keep], "fa": fa[keep].astype(int), "tp": tp[keep].astype(int)}


def allocate(curves: list[dict], budget: int) -> tuple[list[float], int, int]:
    """Exact multiple-choice knapsack. Returns (thresholds per group, total TP, total FA)."""
    neg = -(10**12)
    dp = np.full(budget + 1, neg, dtype=np.int64)
    dp[0] = 0
    choice = []
    for c in curves:
        new = np.full(budget + 1, neg, dtype=np.int64)
        arg = np.full(budget + 1, -1, dtype=np.int64)
        for k, (cost, val) in enumerate(zip(c["fa"], c["tp"], strict=True)):
            if cost > budget:
                continue
            cand = np.full(budget + 1, neg, dtype=np.int64)
            cand[cost:] = dp[: budget + 1 - cost] + val
            better = cand > new
            new[better] = cand[better]
            arg[better] = k
        dp = new
        choice.append(arg)
    b = int(np.argmax(dp))
    total_tp = int(dp[b])
    ths: list[float] = [0.0] * len(curves)
    total_fa = 0
    for g in range(len(curves) - 1, -1, -1):
        k = int(choice[g][b])
        ths[g] = float(curves[g]["t"][k])
        cost = int(curves[g]["fa"][k])
        total_fa += cost
        b -= cost
    return ths, total_tp, total_fa


def group_oracle(scores: np.ndarray, groups: np.ndarray, benign: np.ndarray, pos: np.ndarray,
                 budget: int, guard_min_benign: int | None = None) -> dict:  # fmt: skip
    """Thresholds per group chosen with labels. Guarded: a group with fewer than
    `guard_min_benign` benign windows is fixed to the global threshold (no free parameter)."""
    s = _finite(scores)
    t_glob = global_threshold(s[benign], budget)
    gids = np.unique(groups)
    curves, free = [], 0
    for g in gids:
        m = groups == g
        nb = int((m & benign).sum())
        if guard_min_benign is not None and nb < guard_min_benign:
            fa = int((s[m & benign] > t_glob).sum())
            curves.append(
                {
                    "t": np.array([t_glob]),
                    "fa": np.array([fa]),
                    "tp": np.array([int((s[m & pos] > t_glob).sum())]),
                }
            )
        else:
            curves.append(group_curve(s[m & benign], s[m & pos], budget))
            free += 1
    ths, tp, fa = allocate(curves, budget)
    return {
        "groups": gids,
        "thresholds": ths,
        "tp": tp,
        "fa": fa,
        "free_parameters": free,
        "t_global": t_glob,
    }


def apply_group_thresholds(scores: np.ndarray, groups: np.ndarray, gids: np.ndarray, ths: list[float],
                           default: float) -> np.ndarray:  # fmt: skip
    """Alert mask; groups unseen at selection time use `default`."""
    t = np.full(scores.size, default, dtype=float)
    for g, th in zip(gids, ths, strict=True):
        t[groups == g] = th
    return scores > t


def partial_auc(pos: np.ndarray, benign: np.ndarray, max_fpr: float = 0.01) -> float:
    """Normalised partial AUC: mean TPR over FPR ∈ [0, max_fpr] (step ROC, exact for ties)."""
    p, b = np.sort(_finite(pos)), np.sort(_finite(benign))
    if p.size == 0 or b.size == 0:
        return float("nan")
    ts = np.unique(np.r_[b, np.inf])[::-1]
    fpr = (b.size - np.searchsorted(b, ts, side="right")) / b.size
    tpr = (p.size - np.searchsorted(p, ts, side="right")) / p.size
    # step function: between consecutive thresholds FPR jumps; area = Σ tpr_prev · ΔFPR within the cap
    area, prev_f, prev_t = 0.0, 0.0, tpr[0]
    for f, tr in zip(fpr[1:], tpr[1:], strict=True):
        f_c = min(f, max_fpr)
        if f_c > prev_f:
            # ties move FPR and TPR together: take the trapezoid across the jump
            frac = (f_c - prev_f) / (f - prev_f)
            area += (f_c - prev_f) * (prev_t + (prev_t + frac * (tr - prev_t))) / 2
        if f >= max_fpr:
            break
        prev_f, prev_t = f, tr
    return area / max_fpr
