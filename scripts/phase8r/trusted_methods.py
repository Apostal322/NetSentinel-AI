"""Phase 8r trusted-evidence calibration: selection policies, simulated vetting and threshold
estimators (docs/phase8r/PREREGISTRATION.md sections 3-4). Pure functions of numpy arrays.

**Vocabulary:**
- **Host metadata** (label-free; from the unlabelled hold-out): windows per host, active
  1-h blocks, median `udp_share`, median `dst_ports`.
- **Selection policy:** chooses the hosts to vet, before any label is seen.
- **Vetting:** returns benign (T3) or malicious (T4) per selected host. In this phase it is
  **ORACLE-SIMULATED** from the dataset's calibration labels (a T1 proxy for T3), with optional
  annotation errors: a malicious host passes as benign with probability `e_fb`; a benign host is
  rejected with probability `e_fm`.

**Estimators** (α = 1 %):
- A2 `trusted_t0`: the conformal rank over the trusted windows only.
- A3 `anchored_t0`: q_ref = trusted_t0. An unvetted host is screened out when more than
  `screen` (10 α) of its hold-out windows exceed q_ref; vetted-malicious hosts are always out.
  T0 = conformal rank over the trusted windows plus the retained unvetted windows.
- A4 `cluster_upper_t0`: the 90th percentile of trusted_t0 over host-cluster bootstrap resamples
  of the trusted hosts (dependence-aware, conservative).
- A5: A3, abstaining when there are fewer than 5 trusted hosts or fewer than 20 trusted
  host-hour blocks (`enough_evidence`).
"""

from __future__ import annotations

import math

import numpy as np

ALPHA = 0.01
HOUR_MS = 3_600_000
SCREEN = 10 * ALPHA
POLICIES = ("random", "diversity", "temporal_block", "service_diverse", "admin_persistent")


def t0(scores: np.ndarray, alpha: float = ALPHA) -> float:
    s = np.sort(np.asarray(scores, dtype=float))
    if s.size == 0 or not np.isfinite(s).all():
        raise ValueError("empty or non-finite calibration scores")
    return float(s[min(s.size, math.ceil((s.size + 1) * (1 - alpha))) - 1])


def host_meta(hosts: np.ndarray, end_ms: np.ndarray, udp: np.ndarray, ports: np.ndarray) -> dict:
    """Per-host label-free metadata. `inv` maps each window to its host index in `uniq`."""
    uniq, inv, cnt = np.unique(hosts, return_inverse=True, return_counts=True)
    hour = end_ms // HOUR_MS
    blocks = np.unique(np.stack([inv, hour - hour.min()]), axis=1)
    active = np.bincount(blocks[0], minlength=uniq.size)
    med_udp, med_ports = _group_median(inv, udp, uniq.size), _group_median(inv, ports, uniq.size)
    return {"uniq": uniq, "inv": inv, "windows": cnt, "active_hours": active, "hour": hour,
            "med_udp": med_udp, "med_ports": med_ports}  # fmt: skip


def _group_median(inv: np.ndarray, x: np.ndarray, n: int) -> np.ndarray:
    o = np.lexsort((x, inv))
    cnt = np.bincount(inv, minlength=n)
    starts = np.r_[0, np.cumsum(cnt)[:-1]]
    xs = x[o]
    return 0.5 * (xs[starts + (cnt - 1) // 2] + xs[starts + cnt // 2])


def select(policy: str, meta: dict, k: int, rng: np.random.Generator) -> np.ndarray:
    """Host indices to vet (at most k), chosen without labels."""
    n = meta["uniq"].size
    k = min(k, n)
    if policy == "random":
        return rng.choice(n, size=k, replace=False)
    if policy == "diversity":  # one host per activity-volume stratum
        order = np.lexsort((rng.random(n), meta["windows"]))
        return np.array([rng.choice(g) for g in np.array_split(order, k) if g.size])
    if policy == "temporal_block":  # k hosts active in one random 1-h block
        hours = np.unique(meta["hour"])
        h = rng.choice(hours)
        cand = np.unique(meta["inv"][meta["hour"] == h])
        return rng.choice(cand, size=min(k, cand.size), replace=False)
    if policy == "service_diverse":  # round robin over (UDP-dominant, destination-port bucket)
        prof = (meta["med_udp"] > 0.5).astype(int) * 3 + np.digitize(meta["med_ports"], [1.5, 5.5])
        groups = [
            rng.permutation(np.flatnonzero(prof == g)) for g in rng.permutation(np.unique(prof))
        ]
        out, i = [], 0
        while len(out) < k:
            for g in groups:
                if i < g.size and len(out) < k:
                    out.append(g[i])
            i += 1
        return np.array(out)
    if policy == "admin_persistent":  # the most persistent hosts (an administrator's "known" hosts)
        return np.lexsort((-meta["windows"], -meta["active_hours"]))[:k]
    raise ValueError(policy)


def vet(
    chosen: np.ndarray, malicious_host: np.ndarray, rng: np.random.Generator,
    e_fb: float = 0.0, e_fm: float = 0.0,
) -> tuple[np.ndarray, np.ndarray]:  # fmt: skip
    """ORACLE-SIMULATED vetting: (hosts accepted as benign, hosts found malicious)."""
    mal = malicious_host[chosen]
    u = rng.random(chosen.size)
    accepted = np.where(mal, u < e_fb, u >= e_fm)
    return chosen[accepted], chosen[mal & ~accepted]


def trusted_t0(s: np.ndarray, trusted: np.ndarray) -> float:
    return t0(s[trusted])


def anchored_t0(s: np.ndarray, inv: np.ndarray, trusted: np.ndarray, vetted: np.ndarray,
                malicious: np.ndarray, screen: float = SCREEN) -> float:  # fmt: skip
    """A3. `trusted`: window mask. `vetted`, `malicious`: host masks (vetted = any host the
    vetting touched, accepted or not)."""
    q = t0(s[trusted])
    n = vetted.size
    above = np.bincount(inv, weights=(s > q).astype(float), minlength=n)
    tot = np.bincount(inv, minlength=n)
    keep_host = ~vetted & ~malicious & (above <= screen * np.maximum(tot, 1))
    return t0(s[trusted | keep_host[inv]])


def cluster_upper_t0(s: np.ndarray, inv: np.ndarray, trusted: np.ndarray, rng: np.random.Generator,
                     b: int = 100, level: float = 0.90) -> float:  # fmt: skip
    hosts = np.unique(inv[trusted])
    st, it = s[trusted], inv[trusted]
    groups = [st[it == h] for h in hosts]
    vals = [t0(np.concatenate([groups[j] for j in rng.integers(0, hosts.size, hosts.size)]))
            for _ in range(b)]  # fmt: skip
    return float(np.quantile(vals, level))


def enough_evidence(inv: np.ndarray, hour: np.ndarray, trusted: np.ndarray,
                    min_hosts: int = 5, min_blocks: int = 20) -> bool:  # fmt: skip
    if not trusted.any():
        return False
    hosts = np.unique(inv[trusted]).size
    blocks = np.unique(np.stack([inv[trusted], hour[trusted]]), axis=1).shape[1]
    return bool(hosts >= min_hosts and blocks >= min_blocks)


def contaminate(mechanism: str, frac: float, n_trusted: int, att_idx: np.ndarray, inv: np.ndarray,
                end_ms: np.ndarray, udp: np.ndarray, ports: np.ndarray, trusted: np.ndarray,
                rng: np.random.Generator) -> np.ndarray | None:  # fmt: skip
    """Indices of attacker hold-out windows to mark as trusted so that they form `frac` of the
    trusted set (Experiment B). None when the mechanism has no eligible windows."""
    if frac <= 0:
        return np.array([], dtype=int)
    m = int(round(frac * n_trusted / (1 - frac)))
    if m == 0 or att_idx.size == 0:
        return None
    pool = att_idx
    if mechanism in ("persistent", "coordinated"):
        hs, c = np.unique(inv[att_idx], return_counts=True)
        top = hs[np.argsort(-c, kind="stable")][: 1 if mechanism == "persistent" else 3]
        if mechanism == "persistent":
            pool = att_idx[inv[att_idx] == top[0]]
        else:
            parts = [att_idx[inv[att_idx] == h] for h in top]
            per = int(math.ceil(m / len(parts)))
            pick = np.concatenate(
                [rng.choice(p, size=min(per, p.size), replace=False) for p in parts]
            )
            return pick[:m]
    if mechanism == "service_matched":
        lo_u, hi_u = np.quantile(udp[trusted], [0.1, 0.9])
        lo_p, hi_p = np.quantile(ports[trusted], [0.1, 0.9])
        ok = (
            (udp[pool] >= lo_u)
            & (udp[pool] <= hi_u)
            & (ports[pool] >= lo_p)
            & (ports[pool] <= hi_p)
        )
        pool = pool[ok]
        if pool.size == 0:
            return None
    m = min(m, pool.size)
    if mechanism == "burst":
        o = pool[np.argsort(end_ms[pool], kind="stable")]
        start = int(rng.integers(0, o.size - m + 1))
        return o[start : start + m]
    if mechanism == "gradual":
        o = pool[np.argsort(end_ms[pool], kind="stable")]
        p = np.arange(1, o.size + 1, dtype=float)
        return rng.choice(o, size=m, replace=False, p=p / p.sum())
    return rng.choice(pool, size=m, replace=False)
