"""Phase 8t deployable conditional calibration (docs/phase8t/PREREGISTRATION.md § 8, A-1).
Pure numpy. Every threshold is the inverted-CDF (1 − α) quantile of a calibration distribution
built only from hold-out windows; no evaluation information enters.

- `service_group`: 6 window service profiles, (UDP share > 0.5) × destination ports in {1}, {2–5}, {> 5}.
- `Calibrator(method)` builds, per group (or per host), a weighted calibration distribution:
  - D0 global; D1 the group's own windows (≥ 100, else global);
  - D2 the group's windows (weight 1) mixed with the global windows (total weight κ);
  - D3 D1 only if n_g ≥ 500 and ≥ 5 distinct hosts have windows above its threshold, else global;
  - D_host the host's own windows (≥ 100, else global; unseen hosts → global).
- `threshold_for` returns each window's assigned threshold; `cdf_for` returns each window's value
  under its assigned calibration CDF (for the matched-budget comparison).
"""

from __future__ import annotations

import numpy as np

ALPHA = 0.01
METHODS = ("D0", "D1", "D2", "D3", "D_host")


def service_group(udp: np.ndarray, ports: np.ndarray) -> np.ndarray:
    return (np.asarray(udp) > 0.5).astype(int) * 3 + np.digitize(np.asarray(ports), [1.5, 5.5])


class WeightedDist:
    """A weighted empirical distribution: inverted-CDF quantile and CDF."""

    def __init__(self, s: np.ndarray, w: np.ndarray) -> None:
        s = np.asarray(s, dtype=float)
        w = np.asarray(w, dtype=float)
        if s.size == 0 or not np.isfinite(s).all() or (w < 0).any() or w.sum() <= 0:
            raise ValueError("invalid calibration distribution")
        o = np.argsort(s, kind="stable")
        self.s, self.cw = s[o], np.cumsum(w[o]) / w.sum()

    def quantile(self, q: float) -> float:
        return float(
            self.s[min(int(np.searchsorted(self.cw, q - 1e-12, side="left")), self.s.size - 1)]
        )

    def cdf(self, x: np.ndarray) -> np.ndarray:
        i = np.searchsorted(self.s, np.asarray(x, dtype=float), side="right")
        return np.where(i > 0, self.cw[np.maximum(i - 1, 0)], 0.0)


class Calibrator:
    def __init__(self, method: str, s: np.ndarray, groups: np.ndarray, hosts: np.ndarray, *,
                 kappa: float = 500.0, alpha: float = ALPHA, min_group: int = 100,
                 d3_min: int = 500, d3_tail_hosts: int = 5, min_host: int = 100) -> None:  # fmt: skip
        if method not in METHODS:
            raise ValueError(method)
        s = np.asarray(s, dtype=float)
        self.method, self.alpha = method, alpha
        self.glob = WeightedDist(s, np.ones(s.size))
        self.t_glob = self.glob.quantile(1 - alpha)
        self.dist: dict = {}
        self.support: dict = {}
        if method in ("D1", "D2", "D3"):
            for g in np.unique(groups):
                m = groups == g
                n = int(m.sum())
                if method == "D2":
                    w = np.r_[np.ones(n), np.full(s.size, kappa / s.size)]
                    self.dist[g] = WeightedDist(np.r_[s[m], s], w)
                    self.support[g] = {"n": n, "own_weight": n / (n + kappa)}
                elif n >= (min_group if method == "D1" else d3_min):
                    dg = WeightedDist(s[m], np.ones(n))
                    tail_hosts = int(np.unique(hosts[m][s[m] > dg.quantile(1 - alpha)]).size)
                    if method == "D1" or tail_hosts >= d3_tail_hosts:
                        self.dist[g] = dg
                    self.support[g] = {"n": n, "tail_hosts": tail_hosts, "local": g in self.dist}
                else:
                    self.support[g] = {"n": n, "local": False}
        elif method == "D_host":
            hs, cnt = np.unique(hosts, return_counts=True)
            for h, c in zip(hs, cnt, strict=True):
                if c >= min_host:
                    m = hosts == h
                    self.dist[h] = WeightedDist(s[m], np.ones(int(c)))
            self.support = {"hosts_local": len(self.dist), "hosts_total": int(hs.size)}

    def _unit(self, groups: np.ndarray, hosts: np.ndarray) -> np.ndarray:
        return hosts if self.method == "D_host" else groups

    def threshold_for(self, groups: np.ndarray, hosts: np.ndarray) -> np.ndarray:
        u = self._unit(groups, hosts)
        t = np.full(u.size, self.t_glob, dtype=float)
        for k, dk in self.dist.items():
            t[u == k] = dk.quantile(1 - self.alpha)
        return t

    def group_thresholds(self) -> dict:
        return {k: dk.quantile(1 - self.alpha) for k, dk in self.dist.items()}

    def cdf_for(self, s: np.ndarray, groups: np.ndarray, hosts: np.ndarray) -> np.ndarray:
        u = self._unit(groups, hosts)
        out = self.glob.cdf(s)
        for k, dk in self.dist.items():
            m = u == k
            out[m] = dk.cdf(s[m])
        return out
