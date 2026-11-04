"""Phase 8q label-free threshold estimators (docs/phase8q/PREREGISTRATION.md section 3). Pure
functions of hold-out scores, hosts and end times; no label is ever an input.

- t0: the registered conformal rank ⌈(n + 1)(1 − α)⌉ (Phase 8j).
- host_capped_t0 (L1): a weighted quantile, each window weighted min(1, c·N / n_h) (a host holds at
  most a share c = α/2 of the calibration mass, so no single host can hold the alert budget).
  k contaminating hosts still hold up to k·c: two or more can still reach α.
- block_median_t0 (L2): the median over 1-h blocks (with ≥ 100 windows) of each block's
  (1 − α) quantile; with fewer than 5 such blocks, t0.
- persistent_trim_t0 (L4): t0 after removing hosts whose median hold-out score exceeds the
  (1 − α) quantile of the OTHER hosts' windows (leave-one-host-out for hosts holding ≥ α/2 of the
  windows; a large host would otherwise define the very quantile it is compared with).
- insufficient_evidence (L5 abstention): fewer than 100 distinct host-hour blocks, or fewer than
  20 effective hosts (1 / Σ share²).
"""

from __future__ import annotations

import math

import numpy as np

ALPHA = 0.01
HOUR_MS = 3_600_000


def _check(scores: np.ndarray) -> np.ndarray:
    s = np.asarray(scores, dtype=float)
    if s.size == 0:
        raise ValueError("empty calibration hold-out")
    if not np.isfinite(s).all():
        raise ValueError("non-finite calibration scores")
    return s


def t0(scores: np.ndarray, alpha: float = ALPHA) -> float:
    s = np.sort(_check(scores))
    return float(s[min(s.size, math.ceil((s.size + 1) * (1 - alpha))) - 1])


def weighted_quantile(scores: np.ndarray, weights: np.ndarray, q: float) -> float:
    """Smallest score whose cumulative normalised weight reaches q."""
    s = _check(scores)
    w = np.asarray(weights, dtype=float)
    o = np.argsort(s, kind="stable")
    cw = np.cumsum(w[o]) / w.sum()
    return float(s[o][min(int(np.searchsorted(cw, q - 1e-12, side="left")), s.size - 1)])


def host_capped_t0(
    scores: np.ndarray, hosts: np.ndarray, cap: float = ALPHA / 2, alpha: float = ALPHA
) -> float:
    s = _check(scores)
    _, inv, cnt = np.unique(np.asarray(hosts), return_inverse=True, return_counts=True)
    w = np.minimum(1.0, cap * s.size / cnt[inv])
    return weighted_quantile(s, w, 1 - alpha)


def block_median_t0(scores: np.ndarray, end_ms: np.ndarray, alpha: float = ALPHA, block_ms: int = HOUR_MS,
                    min_windows: int = 100, min_blocks: int = 5) -> float:  # fmt: skip
    s = _check(scores)
    b = np.asarray(end_ms) // block_ms
    qs = [t0(s[b == k], alpha) for k in np.unique(b) if (b == k).sum() >= min_windows]
    return float(np.median(qs)) if len(qs) >= min_blocks else t0(s, alpha)


def persistent_trim_t0(scores: np.ndarray, hosts: np.ndarray, alpha: float = ALPHA) -> float:
    s = _check(scores)
    h = np.asarray(hosts)
    pooled = np.quantile(s, 1 - alpha)
    keep = np.ones(s.size, bool)
    for host in np.unique(h):
        m = h == host
        ref = np.quantile(s[~m], 1 - alpha) if m.mean() >= alpha / 2 and (~m).any() else pooled
        if np.median(s[m]) > ref:
            keep &= ~m
    return t0(s[keep] if keep.any() else s, alpha)


def insufficient_evidence(
    hosts: np.ndarray, end_ms: np.ndarray, min_blocks: int = 100, min_hosts: float = 20.0
) -> bool:
    h = np.asarray(hosts)
    blocks = np.unique(
        np.char.add(h.astype(str), "|" + (np.asarray(end_ms) // HOUR_MS).astype(str))
    ).size
    _, cnt = np.unique(h, return_counts=True)
    p = cnt / cnt.sum()
    return bool(blocks < min_blocks or 1.0 / float((p**2).sum()) < min_hosts)


METHODS = {"U": lambda s, h, e: t0(s), "L1": lambda s, h, e: host_capped_t0(s, h),
           "L2": lambda s, h, e: block_median_t0(s, e), "L4": lambda s, h, e: persistent_trim_t0(s, h)}  # fmt: skip
