"""Phase 8w network-relative representations of the 12 window features
(docs/phase8w/REFERENCE_ESTIMATION.md). Pure numpy; schema `relwin-1.0.0`.

**Reference estimator** (identical to the project's `behavior.temporal.RobustScaler`, the one
Phase 8h's B-loc used, so the signed arm IS the historical method):
- location = per-feature median of the reference windows;
- scale = max(1.4826 · MAD, floor), floor = 0.15 for the fraction features and 0.25 otherwise
  (`FLOORS`); a floored scale is recorded per feature, never hidden;
- z = clip((x − location) / scale, −10, 10).

**Representations** (always 12 columns, so the column count and order match the null control):
- `signed`: z (Phase 8h B-loc; high and low deviations keep their sign);
- `abs`: |z| (two-sided, direction discarded).
A positive/negative split (max(z, 0), max(−z, 0)) is NOT a separate arm: for a tree model it is
the same hypothesis class as `signed` (`posneg` exists only for the equivalence test).

**Context reference** (`host_reference`): a host with ≥ `min_host` reference windows gets its own
median and scale; every other window falls back to the network reference.

**What a reference estimates.** The median of the supplied windows. From an unlabelled period it
is the centre of the observed mixture, not of benign traffic; the object records its population
so no caller can mistake one for the other.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np

SCHEMA_VERSION = "relwin-1.0.0"
FRACTIONS = ("no_reply_frac", "rst_frac", "udp_share", "upload_share", "new_dst_frac")
CLIP = 10.0
MIN_REFERENCE = 200  # windows; below this a network reference is "insufficient_history"
MIN_HOST = 30  # windows; the deployed profile's own-profile minimum
POPULATIONS = (
    "label_benign_training",
    "unlabelled_history",
    "vetted_benign_simulated",
    "oracle_benign",
    "source_pooled_training",
)


def floors(names: list[str]) -> np.ndarray:
    return np.array([0.15 if n in FRACTIONS else 0.25 for n in names])


@dataclass
class Reference:
    names: list[str]
    population: str
    n: int
    status: str  # "ok" | "insufficient_history"
    location: np.ndarray = field(repr=False, default=None)
    scale: np.ndarray = field(repr=False, default=None)
    raw_mad: np.ndarray = field(repr=False, default=None)
    floored: np.ndarray = field(repr=False, default=None)
    missing_share: np.ndarray = field(repr=False, default=None)
    interval_ms: tuple[int, int] | None = None
    note: str = ""

    def to_json(self) -> dict:
        d = asdict(self)
        for k in ("location", "scale", "raw_mad", "floored", "missing_share"):
            d[k] = None if d[k] is None else np.asarray(d[k]).tolist()
        d["benign_reference"] = self.population != "unlabelled_history"
        return d


def fit_reference(x: np.ndarray, names: list[str], population: str,
                  interval_ms: tuple[int, int] | None = None, min_n: int = MIN_REFERENCE) -> Reference:  # fmt: skip
    """Median / floored-MAD reference of the rows of x. Raises on an empty or non-finite input;
    returns status "insufficient_history" (no statistics) below `min_n` rows."""
    if population not in POPULATIONS:
        raise ValueError(population)
    x = np.asarray(x, dtype=float)
    if x.ndim != 2 or x.shape[1] != len(names):
        raise ValueError("reference matrix does not match the feature names")
    if np.isinf(x).any():
        raise ValueError("non-finite reference values")
    n = int(x.shape[0])
    if n < min_n:
        return Reference(names=list(names), population=population, n=n, status="insufficient_history",
                         interval_ms=interval_ms, note=f"fewer than {min_n} reference windows")  # fmt: skip
    miss = np.isnan(x).mean(axis=0)
    loc = np.nan_to_num(np.nanmedian(x, axis=0))
    mad = np.nan_to_num(1.4826 * np.nanmedian(np.abs(x - loc), axis=0))
    fl = floors(list(names))
    note = (
        "centre of the observed mixture; NOT a benign reference"
        if population == "unlabelled_history"
        else ""
    )
    return Reference(names=list(names), population=population, n=n, status="ok", location=loc,
                     scale=np.maximum(mad, fl), raw_mad=mad, floored=mad < fl, missing_share=miss,
                     interval_ms=interval_ms, note=note)  # fmt: skip


def zscore(x: np.ndarray, ref: Reference) -> np.ndarray:
    if ref.status != "ok":
        raise ValueError(f"reference not usable: {ref.status}")
    z = (np.asarray(x, dtype=float) - ref.location) / ref.scale
    return np.clip(np.nan_to_num(z, nan=0.0), -CLIP, CLIP)


def represent(z: np.ndarray, mode: str) -> np.ndarray:
    if mode == "signed":
        return z
    if mode == "abs":
        return np.abs(z)
    if mode == "posneg":
        return np.hstack([np.maximum(z, 0.0), np.maximum(-z, 0.0)])
    raise ValueError(mode)


@dataclass
class HostReference:
    network: Reference
    hosts: np.ndarray  # sorted host ids with their own reference
    location: np.ndarray  # [n_hosts, n_features]
    scale: np.ndarray
    min_host: int

    def coverage(self, hosts: np.ndarray) -> float:
        return float(np.isin(hosts, self.hosts).mean()) if hosts.size else 0.0


def host_reference(x: np.ndarray, hosts: np.ndarray, names: list[str], population: str,
                   min_host: int = MIN_HOST) -> HostReference:  # fmt: skip
    net = fit_reference(x, names, population)
    if net.status != "ok":
        raise ValueError(f"network reference not usable: {net.status}")
    x = np.asarray(x, dtype=float)
    uniq, inv, cnt = np.unique(hosts, return_inverse=True, return_counts=True)
    own = np.flatnonzero(cnt >= min_host)
    fl = floors(list(names))
    loc = np.empty((own.size, x.shape[1]))
    sc = np.empty((own.size, x.shape[1]))
    order = np.argsort(inv, kind="stable")
    starts = np.r_[0, np.cumsum(cnt)[:-1]]
    for i, h in enumerate(own):
        rows = x[order[starts[h] : starts[h] + cnt[h]]]
        m = np.nan_to_num(np.nanmedian(rows, axis=0))
        loc[i] = m
        sc[i] = np.maximum(np.nan_to_num(1.4826 * np.nanmedian(np.abs(rows - m), axis=0)), fl)
    return HostReference(network=net, hosts=uniq[own], location=loc, scale=sc, min_host=min_host)


def zscore_host(x: np.ndarray, hosts: np.ndarray, ref: HostReference) -> np.ndarray:
    """Own-host deviation where the host has a reference; the network reference otherwise (new
    hosts, hosts with little history)."""
    z = zscore(x, ref.network)
    if ref.hosts.size == 0:
        return z
    pos = np.searchsorted(ref.hosts, hosts)
    pos = np.minimum(pos, ref.hosts.size - 1)
    has = ref.hosts[pos] == hosts
    zh = (np.asarray(x, dtype=float)[has] - ref.location[pos[has]]) / ref.scale[pos[has]]
    z[has] = np.clip(np.nan_to_num(zh, nan=0.0), -CLIP, CLIP)
    return z


def contaminated_rows(
    benign: np.ndarray, attack: np.ndarray, share: float, rng: np.random.Generator
) -> np.ndarray:
    """Reference rows in which a share `share` are attack windows (stress tests): all benign rows
    plus share/(1 − share) · n_benign attack rows, drawn with replacement if needed."""
    if not 0 <= share < 1:
        raise ValueError("share must be in [0, 1)")
    m = int(round(share / (1 - share) * benign.shape[0]))
    if m == 0 or attack.shape[0] == 0:
        return benign
    idx = rng.choice(attack.shape[0], size=m, replace=m > attack.shape[0])
    return np.vstack([benign, attack[idx]])
