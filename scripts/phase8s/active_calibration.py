"""Phase 8s active calibration: sampling designs, a simulated reviewer and design-based threshold
estimators (docs/phase8s/PREREGISTRATION.md). Pure numpy; no label is visible to a design.

**Sampling unit.** A host's hold-out activity (its windows form a cluster). Every design is a
**Poisson design**: host h is reviewed independently with a known inclusion probability π_h, and
Σ π_h = k (the expected number of host reviews). This makes the inclusion probability of every
window exact, which design-based estimators need.

| design | π_h |
|---|---|
| `random_host` (A0) | k / H |
| `random_window` (A1) | each window is drawn with probability p; h is reviewed if any of its windows is drawn: 1 − (1 − p)^{n_h}; p solved so that Σ π_h = k |
| `pps` (A2) | min(1, c·n_h), c solved so that Σ π_h = k (capped probability-proportional-to-size) |
| `stratified` (A3) | 3 strata of equal window mass (hosts sorted by n_h); k/3 expected reviews per stratum, equal π within a stratum (capped at 1, the excess re-allocated) |
| `diversity` (A4) | greedy farthest-point coverage of standardised host features; deterministic (π ∈ {0, 1}: no design weights) |
| `tail` (A5) | capped PPS on a mixed size: ½ the host's share of windows + ½ its share of windows above the unlabelled hold-out 95th percentile |

**Reviewer** (`Reviewer`): the only object holding labels. It returns, per requested host,
BENIGN, MALICIOUS or INCONCLUSIVE under a declared error model, logs every request, and is
ORACLE-SIMULATED from dataset labels.

**Estimators** (α = 1 %), over the windows of hosts the reviewer returned BENIGN:
- C0 `unweighted`: the conformal rank ⌈(n + 1)(1 − α)⌉ over the pooled trusted windows (capped at
  n, the Phase 8j/8q/8r convention; below 99 windows it is the sample maximum);
- C1 `hajek`: the weighted (1 − α) quantile with window weight 1/π_h (Hájek-normalised
  Horvitz–Thompson CDF, inverted-CDF definition);
- C3 `conservative`: the 90th percentile of C1 over 100 host-cluster bootstrap resamples of the
  reviewed-benign hosts; ABSTAIN when the cluster-level effective sample size of the tail is
  insufficient (`tail_support`).

C2 (stratified) is not separate: under a stratified Poisson design with HT stratum totals the
stratified estimator equals C1.
"""

from __future__ import annotations

import math

import numpy as np

ALPHA = 0.01
HOUR_MS = 3_600_000
BENIGN, MALICIOUS, INCONCLUSIVE = 0, 1, 2
DESIGNS = ("random_host", "random_window", "pps", "stratified", "diversity", "tail")
PROBABILITY_DESIGNS = ("random_host", "random_window", "pps", "stratified", "tail")


# ----------------------------------------------------------------------------- designs
def _solve_capped(size: np.ndarray, k: float) -> np.ndarray:
    """π = min(1, c·size) with Σπ = k (iterative capping). Zero-size units get π = 0."""
    size = np.asarray(size, dtype=float)
    pi = np.zeros_like(size)
    pos = size > 0
    k = min(float(k), float(pos.sum()))
    if k <= 0:
        return pi
    fixed = np.zeros_like(pos)
    for _ in range(size.size + 1):
        free = pos & ~fixed
        rem = k - fixed.sum()
        if rem <= 0 or not free.any():
            break
        c = rem / size[free].sum()
        pi[free] = c * size[free]
        over = free & (pi >= 1)
        if not over.any():
            break
        pi[over] = 1.0
        fixed |= over
    pi[fixed] = 1.0
    return np.clip(pi, 0.0, 1.0)


def pi_random_host(n_h: np.ndarray, k: float) -> np.ndarray:
    return np.full(n_h.size, min(1.0, k / n_h.size))


def pi_pps(n_h: np.ndarray, k: float) -> np.ndarray:
    return _solve_capped(n_h, k)


def window_rate(n_h: np.ndarray, k: float) -> float:
    """p such that Σ_h 1 − (1 − p)^{n_h} = k (bisection)."""
    k = min(float(k), float(n_h.size))
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        if (1 - (1 - mid) ** n_h).sum() < k:
            lo = mid
        else:
            hi = mid
    return hi


def pi_random_window(n_h: np.ndarray, k: float) -> np.ndarray:
    return 1 - (1 - window_rate(n_h, k)) ** n_h


def strata_of(n_h: np.ndarray, n_strata: int = 3) -> np.ndarray:
    """Strata of (roughly) equal window mass over hosts sorted by activity."""
    o = np.argsort(n_h, kind="stable")
    cum = np.cumsum(n_h[o]) / n_h.sum()
    s = np.empty(n_h.size, dtype=int)
    s[o] = np.minimum((cum * n_strata - 1e-12).astype(int), n_strata - 1)
    return s


def pi_stratified(n_h: np.ndarray, k: float, n_strata: int = 3) -> np.ndarray:
    s = strata_of(n_h, n_strata)
    pi = np.zeros(n_h.size)
    budget = min(float(k), float(n_h.size))
    groups = [np.flatnonzero(s == j) for j in range(n_strata)]
    groups = [g for g in groups if g.size]
    left = list(range(len(groups)))
    while left and budget > 1e-9:
        share = budget / len(left)
        nxt = []
        for j in left:
            g = groups[j]
            take = min(share, g.size - pi[g].sum())
            pi[g] += take / g.size
            budget -= take
            if g.size - pi[g].sum() > 1e-9:
                nxt.append(j)
        if len(nxt) == len(left):
            break
        left = nxt
    return np.clip(pi, 0.0, 1.0)


def pi_tail(n_h: np.ndarray, tail_h: np.ndarray, k: float, lam: float = 0.5) -> np.ndarray:
    """Capped PPS on a mixed size measure: a share (1 − λ) of activity mass plus λ of tail mass
    (windows above the unlabelled hold-out 95th percentile), so that Σπ = k exactly."""
    n_h = np.asarray(n_h, dtype=float)
    tail_h = np.asarray(tail_h, dtype=float)
    size = (1 - lam) * n_h / n_h.sum()
    if tail_h.sum() > 0:
        size = size + lam * tail_h / tail_h.sum()
    return _solve_capped(size, k)


def select_diverse(features: np.ndarray, k: int) -> np.ndarray:
    """Greedy farthest-point coverage (deterministic; starts at the feature-space medoid proxy)."""
    x = np.asarray(features, dtype=float)
    k = min(int(k), x.shape[0])
    if k <= 0:
        return np.array([], dtype=int)
    sd = x.std(0)
    z = (x - x.mean(0)) / np.where(sd > 0, sd, 1.0)
    first = int(np.argmin(((z - np.median(z, 0)) ** 2).sum(1)))
    chosen = [first]
    d = ((z - z[first]) ** 2).sum(1)
    for _ in range(k - 1):
        nxt = int(np.argmax(d))
        if d[nxt] <= 0:
            break
        chosen.append(nxt)
        d = np.minimum(d, ((z - z[nxt]) ** 2).sum(1))
    return np.array(chosen, dtype=int)


def poisson_draw(pi: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    return np.flatnonzero(rng.random(pi.size) < pi)


# ----------------------------------------------------------------------------- reviewer
class Reviewer:
    """ORACLE-SIMULATED host review. The only holder of labels; designs never see it.

    Error model (host-level, so one verdict covers all of a host's windows — errors are
    perfectly correlated within a host):
    - an inconclusive result with probability `p_inc` (or `p_inc_heavy` for hosts whose activity
      is above `heavy_n`: missing-not-at-random review failure);
    - otherwise a malicious host is returned BENIGN with probability `e_fb`, a benign host
      MALICIOUS with probability `e_fm`.
    Cost (SIMULATED units, not measured analyst time): 1 per host review plus `per_window` per
    window of the host reviewed.
    """

    def __init__(self, malicious: np.ndarray, n_h: np.ndarray, *, e_fb: float = 0.0,
                 e_fm: float = 0.0, p_inc: float = 0.0, p_inc_heavy: float | None = None,
                 heavy_n: float = math.inf, per_window: float = 0.01) -> None:  # fmt: skip
        self._truth = np.asarray(malicious, dtype=bool)
        self._n = np.asarray(n_h, dtype=float)
        self.e_fb, self.e_fm, self.p_inc = e_fb, e_fm, p_inc
        self.p_inc_heavy = p_inc if p_inc_heavy is None else p_inc_heavy
        self.heavy_n, self.per_window = heavy_n, per_window
        self.log: list[tuple[int, int]] = []
        self.cost = 0.0

    def review(self, hosts: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        hosts = np.asarray(hosts, dtype=int)
        if np.unique(hosts).size != hosts.size:
            raise ValueError("duplicate host review request")
        mal = self._truth[hosts]
        p_inc = np.where(self._n[hosts] > self.heavy_n, self.p_inc_heavy, self.p_inc)
        u1, u2 = rng.random(hosts.size), rng.random(hosts.size)
        out = np.where(mal, np.where(u2 < self.e_fb, BENIGN, MALICIOUS),
                       np.where(u2 < self.e_fm, MALICIOUS, BENIGN))  # fmt: skip
        out = np.where(u1 < p_inc, INCONCLUSIVE, out)
        self.cost += float(hosts.size + self.per_window * self._n[hosts].sum())
        self.log.extend(zip(hosts.tolist(), out.tolist(), strict=True))
        return out


# ----------------------------------------------------------------------------- estimators
def _check(s: np.ndarray) -> np.ndarray:
    s = np.asarray(s, dtype=float)
    if s.size == 0:
        raise ValueError("no trusted windows")
    if not np.isfinite(s).all():
        raise ValueError("non-finite scores")
    return s


def conformal_t0(s: np.ndarray, alpha: float = ALPHA) -> float:
    s = np.sort(_check(s))
    return float(s[min(s.size, math.ceil((s.size + 1) * (1 - alpha))) - 1])


def weighted_quantile(s: np.ndarray, w: np.ndarray, q: float) -> float:
    """Inverted-CDF quantile of the weighted empirical distribution (Hájek)."""
    s = _check(s)
    w = np.asarray(w, dtype=float)
    if w.shape != s.shape or (w < 0).any() or w.sum() <= 0 or not np.isfinite(w).all():
        raise ValueError("invalid weights")
    o = np.argsort(s, kind="stable")
    cw = np.cumsum(w[o]) / w.sum()
    return float(s[o][min(int(np.searchsorted(cw, q - 1e-12, side="left")), s.size - 1)])


def kish_neff(w: np.ndarray) -> float:
    w = np.asarray(w, dtype=float)
    return float(w.sum() ** 2 / (w**2).sum()) if w.size and (w**2).sum() > 0 else 0.0


def cluster_neff(w_h: np.ndarray, n_h: np.ndarray) -> float:
    """Effective number of host clusters: Kish over each host's total weight w_h·n_h."""
    return kish_neff(np.asarray(w_h, dtype=float) * np.asarray(n_h, dtype=float))


def tail_support(s: np.ndarray, w: np.ndarray, inv: np.ndarray, t: float) -> dict:
    """Hosts (and their Kish count) carrying the weighted mass at or above the estimate t."""
    at = s >= t
    hosts = np.unique(inv[at])
    tw = np.bincount(inv[at], weights=w[at])[hosts] if at.any() else np.array([])
    return {"tail_hosts": int(hosts.size), "tail_cluster_neff": kish_neff(tw)}


def hajek(s: np.ndarray, w: np.ndarray, alpha: float = ALPHA) -> float:
    return weighted_quantile(s, w, 1 - alpha)


def conservative(s: np.ndarray, w: np.ndarray, inv: np.ndarray, rng: np.random.Generator,
                 b: int = 100, level: float = 0.90, min_tail_hosts: int = 5,
                 min_neff: float = 99.0, alpha: float = ALPHA) -> float | None:  # fmt: skip
    """C3: cluster-bootstrap upper quantile of C1; None (abstain) when the evidence is thin:
    fewer than `min_tail_hosts` hosts at or above the C1 estimate, or a window-level Kish
    effective size below `min_neff` (a 1 % quantile is then at best the sample maximum)."""
    t1 = hajek(s, w, alpha)
    sup = tail_support(s, w, inv, t1)
    if sup["tail_hosts"] < min_tail_hosts or kish_neff(w) < min_neff:
        return None
    hosts = np.unique(inv)
    groups = [np.flatnonzero(inv == h) for h in hosts]
    vals = []
    for _ in range(b):
        idx = np.concatenate([groups[j] for j in rng.integers(0, hosts.size, hosts.size)])
        vals.append(hajek(s[idx], w[idx], alpha))
    return float(np.quantile(vals, level))


# ----------------------------------------------------------------------------- sample size
def n_for_max_guarantee(alpha: float = ALPHA, delta: float = 0.05) -> int:
    """i.i.d. draws needed so that the sample maximum exceeds the (1 − α) quantile with
    probability ≥ 1 − δ: (1 − α)^n ≤ δ."""
    return int(math.ceil(math.log(delta) / math.log(1 - alpha)))


def exceedance_deff(exceed: np.ndarray, inv: np.ndarray) -> dict:
    """Design effect of the exceedance indicator under host clustering (one-way ANOVA ICC),
    deff = 1 + (m_w − 1)·ρ with m_w the window-weighted mean cluster size."""
    y = np.asarray(exceed, dtype=float)
    _, g, n = np.unique(inv, return_inverse=True, return_counts=True)
    big_n, k = y.size, n.size
    mean_g = np.bincount(g, weights=y) / n
    ssb = float((n * (mean_g - y.mean()) ** 2).sum())
    ssw = float(((y - mean_g[g]) ** 2).sum())
    msb = ssb / max(k - 1, 1)
    msw = ssw / max(big_n - k, 1)
    n0 = (big_n - (n**2).sum() / big_n) / max(k - 1, 1)
    rho = (msb - msw) / (msb + (n0 - 1) * msw) if (msb + (n0 - 1) * msw) > 0 else 0.0
    rho = float(min(max(rho, 0.0), 1.0))
    m_w = float((n**2).sum() / big_n)
    deff = 1 + (m_w - 1) * rho
    return {"icc": rho, "m_w": m_w, "deff": deff, "n_eff": big_n / deff, "clusters": int(k)}
