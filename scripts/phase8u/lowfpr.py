"""Phase 8u low-FPR learning components (docs/phase8u/PREREGISTRATION.md). Pure numpy.

**Hard-negative selection** (`select_hard_negatives`, H1):
- among a source domain's **eligible** negatives (label 0 and the host never attacks in that
  domain), the top `top_frac` by a cross-fitted mining score;
- at most `per_host_cap` per host (the highest-scoring), so a few chatty hosts cannot hold the
  mined set.

**Pairwise one-way partial-AUC surrogate** (`PairwiseTailObjective`, H2): LightGBM custom
objective = weighted binary log-loss + λ · Σ_domains w_d · L_d, with

    L_d = 1 / (P_d · N_d) · Σ_{i ∈ attacks_d} Σ_{j ∈ top-β negatives_d} max(0, 1 − (f_i − f_j))²

on raw margins f.
- The top-β (β = 5 %) eligible negatives of each domain are re-selected from the current margins
  at every boosting iteration.
- This is the standard squared-hinge surrogate of the one-way partial AUC over FPR ∈ [0, β]
  (Narasimhan & Agarwal 2013). Pairs are formed **within a source domain only**, so the term
  cannot be lowered by separating networks.
- It is a surrogate, **not** direct pAUC optimisation. Gradients are exact; the Hessian is the
  diagonal of the pairwise term (cross terms dropped), floored at 1e-6.

**Service-relative features** (`service_relative`, H3): feature − its median among the same
domain's calibration-period windows of the same service profile (UDP share > 0.5 × destination
ports in {1}, {2–5}, {> 5}). They use only that domain's unlabelled calibration windows, so they
are computable at prediction time.
"""

from __future__ import annotations

import numpy as np

SERVICE_FEATURES = ("log_flows", "log_up_bytes", "log_pkts", "med_log_dur")


def service_profile(udp_share: np.ndarray, dst_ports: np.ndarray) -> np.ndarray:
    return (np.asarray(udp_share) > 0.5).astype(int) * 3 + np.digitize(
        np.asarray(dst_ports), [1.5, 5.5]
    )


def service_medians(x: np.ndarray, profile: np.ndarray) -> dict[int, np.ndarray]:
    """Per-profile column medians of calibration windows (profiles absent from calibration use
    the all-window median: key -1)."""
    out = {-1: np.median(x, axis=0)}
    for p in np.unique(profile):
        out[int(p)] = np.median(x[profile == p], axis=0)
    return out


def service_relative(
    x: np.ndarray, profile: np.ndarray, medians: dict[int, np.ndarray]
) -> np.ndarray:
    ref = np.vstack([medians.get(int(p), medians[-1]) for p in profile]) if x.shape[0] else x
    return x - ref


def select_hard_negatives(score: np.ndarray, eligible: np.ndarray, hosts: np.ndarray,
                          top_frac: float = 0.05, per_host_cap: int = 50) -> np.ndarray:  # fmt: skip
    """Boolean mask of mined hard negatives (deterministic: ties broken by row index)."""
    s = np.asarray(score, dtype=float)
    el = np.flatnonzero(np.asarray(eligible))
    out = np.zeros(s.size, bool)
    if el.size == 0 or top_frac <= 0:
        return out
    k = max(1, int(np.ceil(top_frac * el.size)))
    order = el[np.lexsort((el, -s[el]))]  # descending score, then row index
    taken: dict = {}
    picked = 0
    for i in order:
        if picked >= k:
            break
        h = hosts[i]
        if taken.get(h, 0) >= per_host_cap:
            continue
        taken[h] = taken.get(h, 0) + 1
        out[i] = True
        picked += 1
    return out


def pairwise_tail_grad(
    f_pos: np.ndarray, f_neg: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, float]:
    """Gradient, diagonal Hessian and loss of L = 1/(P·N) Σ_i Σ_j max(0, 1 − (a_i − b_j))²,
    computed in O((P + N) log(P + N))."""
    a = np.asarray(f_pos, dtype=float)
    b = np.asarray(f_neg, dtype=float)
    p, n = a.size, b.size
    if p == 0 or n == 0:
        return np.zeros(p), np.zeros(n), np.zeros(p), np.zeros(n), 0.0
    bs = np.sort(b)
    cb = np.r_[0.0, np.cumsum(bs)]
    # for a_i: active j where b_j > a_i - 1
    k = np.searchsorted(bs, a - 1.0, side="right")
    cnt_a = n - k
    sum_b = cb[-1] - cb[k]
    ga = -2.0 * (cnt_a * (1.0 - a) + sum_b)
    as_ = np.sort(a)
    ca = np.r_[0.0, np.cumsum(as_)]
    # for b_j: active i where a_i < b_j + 1
    m = np.searchsorted(as_, b + 1.0, side="left")
    cnt_b = m
    sum_a = ca[m]
    gb = 2.0 * (cnt_b * (1.0 + b) - sum_a)
    # loss: Σ_i Σ_{active} (1 - a_i + b_j)^2 = Σ_i [cnt (1-a_i)^2 + 2(1-a_i) Σb + Σ b^2]
    cb2 = np.r_[0.0, np.cumsum(bs**2)]
    loss = float(np.sum(cnt_a * (1 - a) ** 2 + 2 * (1 - a) * sum_b + (cb2[-1] - cb2[k])))
    scale = 1.0 / (p * n)
    return ga * scale, gb * scale, 2.0 * cnt_a * scale, 2.0 * cnt_b * scale, loss * scale


class PairwiseTailObjective:
    """Callable LightGBM objective (sklearn API: (y_true, y_pred, weight) → grad, hess)."""

    def __init__(self, domain: np.ndarray, eligible_neg: np.ndarray, domain_weight: np.ndarray,
                 beta: float = 0.05, lam: float | None = None) -> None:  # fmt: skip
        self.domain = np.asarray(domain)
        self.eligible = np.asarray(eligible_neg, bool)
        self.dw = np.asarray(domain_weight, dtype=float)  # per domain id
        self.beta = beta
        self.lam = lam
        self.doms = [(d, np.flatnonzero(self.domain == d)) for d in np.unique(self.domain)]

    def __call__(self, y_true: np.ndarray, y_pred: np.ndarray, weight: np.ndarray | None = None):
        y = np.asarray(y_true, dtype=float)
        f = np.asarray(y_pred, dtype=float)
        w = np.ones(y.size) if weight is None else np.asarray(weight, dtype=float)
        p = 1.0 / (1.0 + np.exp(-np.clip(f, -35, 35)))
        grad = w * (p - y)
        hess = w * p * (1 - p)
        lam = float(w.sum()) if self.lam is None else self.lam
        for d, idx in self.doms:
            pos = idx[y[idx] == 1]
            neg = idx[(y[idx] == 0) & self.eligible[idx]]
            if pos.size == 0 or neg.size == 0:
                continue
            k = max(1, int(np.ceil(self.beta * neg.size)))
            top = neg[np.argpartition(-f[neg], k - 1)[:k]]
            ga, gb, ha, hb, _ = pairwise_tail_grad(f[pos], f[top])
            c = lam * self.dw[d]
            np.add.at(grad, pos, c * ga)
            np.add.at(grad, top, c * gb)
            np.add.at(hess, pos, c * ha)
            np.add.at(hess, top, c * hb)
        hess = np.maximum(hess, 1e-6)
        if not (np.isfinite(grad).all() and np.isfinite(hess).all()):
            raise FloatingPointError("non-finite gradient or Hessian")
        return grad, hess
