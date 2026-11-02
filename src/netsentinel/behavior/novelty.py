"""Adaptive destination-novelty features (Phase 8m research module; not used by the monitor).

Every feature of a window is computed from the memory state *before* that window, and the
memory is updated with the window's contacts only after the window's features are emitted, so
the features are causal: a window never sees its own or any later traffic.

Memory policies (docs/phase8m/PREREGISTRATION.md):

- ``frozen``      (A0) the destinations seen up to `freeze_ms`; never updated afterwards (the
                  deployed `new_dst_frac` evaluation behaviour).
- ``unconditional`` (A1) every destination becomes known after its first window.
- ``guarded``     (A3) a destination becomes known only once it has been contacted by at least
                  `min_sources` distinct sources on at least `min_days` distinct UTC days; until
                  then it stays novel however often one host contacts it. No score or label is
                  used, so the model's own predictions cannot decide what becomes normal.

Per window and source the class emits (all in [0, 1] or log scale, NaN never produced):

- ``nov_frozen``, ``nov_unconditional``, ``nov_guarded``: share of the window's distinct
  destinations not in that policy's memory;
- ``nov_host``: share never contacted by this source before (per-host first contacts);
- ``log_new_guarded``: log(1 + number of guarded-novel distinct destinations);
- ``familiarity_decay``: mean over the window's destinations of exp(-age / tau), age = time since
  the destination was last contacted by anyone (0 if never);
- ``log_prevalence``: mean log(1 + distinct earlier sources of each destination), capped at
  `source_cap`.

State per destination is bounded: first/last time, a capped set of sources and a capped set of
days, so memory grows with the number of destinations only.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field

import numpy as np
import polars as pl

DAY_MS = 86_400_000
FEATURES = ("nov_frozen", "nov_unconditional", "nov_guarded", "nov_host", "log_new_guarded",
            "familiarity_decay", "log_prevalence")  # fmt: skip


@dataclass
class _Dst:
    first_ms: int
    last_ms: int
    sources: set = field(default_factory=set)
    days: set = field(default_factory=set)
    promoted: bool = False


@dataclass
class NoveltyMemory:
    """Causal destination memory over a time-ordered stream of 30 s source windows."""

    freeze_ms: int | None = None
    min_sources: int = 2
    min_days: int = 2
    tau_ms: float = 7 * DAY_MS
    source_cap: int = 16
    excluded_sources: frozenset = frozenset()
    dst: dict = field(default_factory=dict)
    pairs: set = field(default_factory=set)
    frozen: set = field(default_factory=set)
    last_win: int | None = None

    def _features(self, src: str, dsts: Iterable[str], t_ms: int) -> dict:
        ds = list(dsts)
        n = len(ds)
        nf = nu = ng = nh = 0
        fam = prev = 0.0
        for d in ds:
            s = self.dst.get(d)
            if s is None:
                nu += 1
                ng += 1
            else:
                ng += 0 if s.promoted else 1
                fam += math.exp(-max(t_ms - s.last_ms, 0) / self.tau_ms)
                prev += math.log1p(min(len(s.sources), self.source_cap))
            if self.freeze_ms is not None and t_ms >= self.freeze_ms:
                nf += d not in self.frozen
            else:
                nf += s is None
            nh += (src, d) not in self.pairs
        return {"nov_frozen": nf / n, "nov_unconditional": nu / n, "nov_guarded": ng / n,
                "nov_host": nh / n, "log_new_guarded": math.log1p(ng),
                "familiarity_decay": fam / n, "log_prevalence": prev / n}  # fmt: skip

    def _update(self, src: str, dsts: Iterable[str], t_ms: int) -> None:
        # vetted calibration: known calibration-period attackers never enter the memory (P1x);
        # after the freeze every source updates it, as it would in deployment
        if src in self.excluded_sources and (self.freeze_ms is None or t_ms < self.freeze_ms):
            return
        day = t_ms // DAY_MS
        for d in dsts:
            s = self.dst.get(d)
            if s is None:
                s = self.dst[d] = _Dst(first_ms=t_ms, last_ms=t_ms)
                if self.freeze_ms is None or t_ms < self.freeze_ms:
                    self.frozen.add(d)
            s.last_ms = max(s.last_ms, t_ms)
            if len(s.sources) < self.source_cap:
                s.sources.add(src)
            if len(s.days) < self.min_days:
                s.days.add(day)
            if (
                not s.promoted
                and len(s.sources) >= self.min_sources
                and len(s.days) >= self.min_days
            ):
                s.promoted = True
            self.pairs.add((src, d))

    def process(self, contacts: pl.DataFrame) -> pl.DataFrame:
        """`contacts`: one row per (win, src, dst) with columns win, window_end_ms, src, dst, in
        time order across calls. All windows of one index are scored before any of them updates
        the memory. Returns one row per (win, src) with the FEATURES."""
        if contacts.height == 0:
            return pl.DataFrame(schema={"key": pl.Utf8, "win": pl.Int64,
                                        **{f: pl.Float64 for f in FEATURES}})  # fmt: skip
        agg = [pl.col("window_end_ms").first(), pl.col("dst").unique()]
        g = contacts.group_by("win", "src").agg(*agg).sort("win", "src")
        first = int(g["win"][0])
        if self.last_win is not None and first <= self.last_win:
            raise ValueError(
                f"window {first} is not after the last processed window {self.last_win}"
            )
        rows, pending, cur = [], [], None
        for w, src, end, dsts in g.iter_rows():
            if w != cur:
                for p in pending:
                    self._update(*p)
                pending, cur = [], w
            t = int(end) - 1
            rows.append({"key": src, "win": int(w), **self._features(src, dsts, t)})
            pending.append((src, dsts, t))
        for p in pending:
            self._update(*p)
        self.last_win = cur
        return pl.DataFrame(rows)


def contacts_from_flows(flows: pl.DataFrame, window_s: int = 30) -> pl.DataFrame:
    """Canonical flows (end_ms, src, dst; `prepare_flows` output) -> distinct (win, src, dst)."""
    w = window_s * 1000
    return (flows.select((pl.col("end_ms").cast(pl.Int64) // w).alias("win"),
                         pl.col("src").cast(pl.Utf8), pl.col("dst").cast(pl.Utf8))
            .unique().with_columns(((pl.col("win") + 1) * w).alias("window_end_ms"))
            .sort("win", "src", "dst"))  # fmt: skip


def as_array(frame: pl.DataFrame, names: tuple[str, ...] = FEATURES) -> np.ndarray:
    return frame.select([pl.col(n).cast(pl.Float64) for n in names]).to_numpy()
