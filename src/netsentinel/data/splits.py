"""Train / validation / test split protocols and automated leakage checks.

Protocols (all deterministic given a seed):
* `random`      : stratified row-level split. Included ONLY as the naive reference for H5;
                  correlated flows from one attack burst land on both sides.
* `blocked`     : each capture day is cut into contiguous time blocks (default 15 min). Whole
                  blocks are assigned to partitions (interleaved, seeded), and flows within
                  `purge_seconds` of a boundary between blocks of different partitions are
                  dropped. Every attack lasting several blocks is represented in each partition,
                  while bursts of near-identical neighbouring flows cannot straddle partitions.
* `chronological`: per day, the first `train` fraction of time is train, then val, then test,
                  with purge gaps. Strictest in time, but attacks confined to one part of a day
                  may end up entirely in one partition (reported by `split_coverage`).
* `episode`     : DEFAULT. Attack episodes (per day: first..last second of each attack label,
                  overlapping ones merged) are cut chronologically into train | val | test by
                  `fractions`, so models must generalise forward in time within an attack.
                  Episodes shorter than `min_episode_seconds` go wholly to train (they are known
                  classes but only evaluated in leave-out protocols). Benign-only stretches are
                  cut into `block_minutes` blocks with a cyclic train/val/test pattern. Rows
                  within `purge_seconds` of any boundary between different partitions are
                  dropped, so rows of different partitions are >= 2 * purge_seconds apart
                  (300 s = the longest context window with the default purge of 150 s).
                  Episode boundaries come from labels, i.e. the published attack schedule.
* `leave_day_out`: whole capture days held out (used for open-set / unseen-scenario tests).

Splits operate on (day, row_id, event_sec); they never look at features.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import polars as pl

PARTS = ("train", "val", "test")


@dataclass(frozen=True)
class SplitConfig:
    protocol: str = "blocked"
    fractions: tuple[float, float, float] = (0.6, 0.2, 0.2)
    block_minutes: int = 15
    purge_seconds: int = 300
    test_days: tuple[str, ...] = ()
    val_days: tuple[str, ...] = ()
    min_episode_seconds: int = 900
    seed: int = 42

    def __post_init__(self) -> None:
        if self.protocol not in {"random", "blocked", "chronological", "episode", "leave_day_out"}:
            raise ValueError(f"unknown split protocol {self.protocol!r}")
        if len(self.fractions) != 3 or abs(sum(self.fractions) - 1) > 1e-9:
            raise ValueError("fractions must be three numbers summing to 1")
        if min(self.fractions) < 0:
            raise ValueError("fractions must be non-negative")


def _random(df: pl.DataFrame, cfg: SplitConfig) -> pl.Series:
    rng = np.random.default_rng(cfg.seed)
    out = np.empty(df.height, dtype=object)
    labels = df["label"].to_numpy()
    for lab in np.unique(labels):
        idx = np.flatnonzero(labels == lab)
        rng.shuffle(idx)
        n_train = int(round(cfg.fractions[0] * len(idx)))
        n_val = int(round(cfg.fractions[1] * len(idx)))
        out[idx[:n_train]] = "train"
        out[idx[n_train : n_train + n_val]] = "val"
        out[idx[n_train + n_val :]] = "test"
    return pl.Series("split", out.astype(str))


def _assign_blocks(n_blocks: int, fractions: tuple[float, ...], rng: np.random.Generator):
    """Interleaved assignment: shuffle block order, then fill partitions by quota."""
    order = rng.permutation(n_blocks)
    counts = np.floor(np.array(fractions) * n_blocks).astype(int)
    for i in np.argsort(-(np.array(fractions) * n_blocks - counts))[: n_blocks - counts.sum()]:
        counts[i] += 1
    labels = np.repeat(np.array(PARTS), counts)
    assigned = np.empty(n_blocks, dtype=object)
    assigned[order] = labels
    return assigned


def _purge_mask(sec: np.ndarray, part: np.ndarray, boundaries: list[tuple[int, str, str]], gap):
    """True for rows within `gap` seconds of a boundary between two different partitions."""
    mask = np.zeros(len(sec), dtype=bool)
    for b, left, right in boundaries:
        if left != right:
            mask |= np.abs(sec - b) < gap
    return mask


def _time_partitioned(df: pl.DataFrame, cfg: SplitConfig, chronological: bool) -> pl.Series:
    rng = np.random.default_rng(cfg.seed)
    out = np.empty(df.height, dtype=object)
    days = df["day"].to_numpy()
    secs = df["event_sec"].to_numpy()
    for day in sorted(np.unique(days)):
        idx = np.flatnonzero(days == day)
        sec = secs[idx]
        s0, s1 = int(sec.min()), int(sec.max()) + 1
        if chronological:
            span = s1 - s0
            cuts = [s0 + int(span * cfg.fractions[0]), s0 + int(span * sum(cfg.fractions[:2]))]
            part = np.where(sec < cuts[0], "train", np.where(sec < cuts[1], "val", "test"))
            boundaries = [(cuts[0], "train", "val"), (cuts[1], "val", "test")]
        else:
            width = cfg.block_minutes * 60
            block = (sec - s0) // width
            n_blocks = int(block.max()) + 1
            assigned = _assign_blocks(n_blocks, cfg.fractions, rng)
            part = assigned[block]
            boundaries = [
                (s0 + (k + 1) * width, assigned[k], assigned[k + 1]) for k in range(n_blocks - 1)
            ]
        purged = _purge_mask(sec, part, boundaries, cfg.purge_seconds)
        part = np.where(purged, "purged", part)
        out[idx] = part
    return pl.Series("split", out.astype(str))


def attack_episodes(sec: np.ndarray, labels: np.ndarray) -> list[tuple[int, int]]:
    """Per-day attack episodes: [first, last] event second of each attack label, with
    overlapping intervals merged (e.g. concurrent web attacks form one episode)."""
    spans = sorted(
        (int(sec[labels == lab].min()), int(sec[labels == lab].max()))
        for lab in np.unique(labels)
        if lab != "benign"
    )
    merged: list[list[int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]


def _episode_segments(
    s0: int, s1: int, episodes: list[tuple[int, int]], cfg: SplitConfig, phase: int
) -> list[tuple[int, int, str]]:
    """Cover [s0, s1) with (start, end, partition) segments."""
    f_tr, f_va, _ = cfg.fractions
    width = cfg.block_minutes * 60
    pattern = _cyclic_pattern(cfg.fractions)
    segs: list[tuple[int, int, str]] = []
    k = phase

    def benign_blocks(a: int, b: int) -> None:
        nonlocal k
        t = a
        while t < b:
            segs.append((t, min(t + width, b), pattern[k % len(pattern)]))
            k += 1
            t += width

    cursor = s0
    for a, b in episodes:
        b = b + 1
        benign_blocks(cursor, a)
        if b - a >= cfg.min_episode_seconds:
            c1, c2 = a + int((b - a) * f_tr), a + int((b - a) * (f_tr + f_va))
            segs += [(a, c1, "train"), (c1, c2, "val"), (c2, b, "test")]
        else:
            segs.append((a, b, "train"))  # too short to split; evaluated only in leave-out tests
        cursor = b
    benign_blocks(cursor, s1)
    return segs


def _cyclic_pattern(fractions: tuple[float, float, float]) -> list[str]:
    """Smallest train/val/test cycle (<= 10 blocks) matching the fractions, val and test apart."""
    n = 10
    counts = np.round(np.array(fractions) * n).astype(int)
    counts[0] += n - counts.sum()
    pattern = ["train"] * counts[0]
    # Insert val and test spread out over the cycle.
    for name, c in (("val", counts[1]), ("test", counts[2])):
        for i in range(c):
            pos = int((i + 0.5) * len(pattern) / c) + (1 if name == "test" else 0)
            pattern.insert(min(pos, len(pattern)), name)
    return pattern


def _episodic(df: pl.DataFrame, cfg: SplitConfig) -> pl.Series:
    rng = np.random.default_rng(cfg.seed)
    out = np.empty(df.height, dtype=object)
    days = df["day"].to_numpy()
    secs = df["event_sec"].to_numpy()
    labels = df["label"].to_numpy()
    for day in sorted(np.unique(days)):
        idx = np.flatnonzero(days == day)
        sec = secs[idx]
        s0, s1 = int(sec.min()), int(sec.max()) + 1
        episodes = attack_episodes(sec, labels[idx])
        segs = _episode_segments(s0, s1, episodes, cfg, phase=int(rng.integers(0, 10)))
        starts = np.array([s for s, _, _ in segs])
        names = np.array([p for _, _, p in segs], dtype=object)
        part = names[np.searchsorted(starts, sec, side="right") - 1]
        boundaries = [(segs[i][0], names[i - 1], names[i]) for i in range(1, len(segs))]
        purged = _purge_mask(sec, part, boundaries, cfg.purge_seconds)
        out[idx] = np.where(purged, "purged", part)
    return pl.Series("split", out.astype(str))


def _leave_day_out(df: pl.DataFrame, cfg: SplitConfig) -> pl.Series:
    if not cfg.test_days:
        raise ValueError("leave_day_out needs test_days")
    overlap = set(cfg.test_days) & set(cfg.val_days)
    if overlap:
        raise ValueError(f"days in both val and test: {sorted(overlap)}")
    expr = (
        pl.when(pl.col("day").is_in(list(cfg.test_days)))
        .then(pl.lit("test"))
        .when(pl.col("day").is_in(list(cfg.val_days)))
        .then(pl.lit("val"))
        .otherwise(pl.lit("train"))
        .alias("split")
    )
    return df.select(expr).to_series()


def make_split(df: pl.DataFrame, cfg: SplitConfig) -> pl.DataFrame:
    """Return `day`, `row_id`, `split` (train/val/test/purged) for every input row."""
    need = {"day", "row_id", "label"} | ({"event_sec"} if cfg.protocol != "random" else set())
    missing = need - set(df.columns)
    if missing:
        raise ValueError(f"make_split: missing columns {sorted(missing)}")
    if cfg.protocol == "random":
        split = _random(df, cfg)
    elif cfg.protocol == "leave_day_out":
        split = _leave_day_out(df, cfg)
    elif cfg.protocol == "episode":
        split = _episodic(df, cfg)
    else:
        split = _time_partitioned(df, cfg, chronological=cfg.protocol == "chronological")
    return df.select("day", "row_id").with_columns(split)


# ----------------------------------------------------------------------------- leakage checks


@dataclass(frozen=True)
class LeakageReport:
    duplicate_ids_across_parts: int
    block_overlap: int  # blocks (day, block) present in more than one partition
    min_boundary_gap_seconds: float  # min time distance between rows of different partitions
    exact_feature_duplicates_train_test: int
    test_rows: int

    def ok(self, purge_seconds: int) -> bool:
        return (
            self.duplicate_ids_across_parts == 0
            and self.block_overlap == 0
            and self.min_boundary_gap_seconds >= purge_seconds
        )


def leakage_report(
    df: pl.DataFrame,
    feature_cols: list[str] | None = None,
    block_minutes: int | None = None,
) -> LeakageReport:
    """Checks on a frame with `day`, `row_id`, `event_sec`, `split` (+ optional features)."""
    if block_minutes and "event_sec" in df.columns:
        # Block ids relative to each day's first event over ALL rows, as in make_split.
        df = df.with_columns(
            (
                (pl.col("event_sec") - pl.col("event_sec").min().over("day"))
                // (block_minutes * 60)
            ).alias("_blk")
        )
    kept = df.filter(pl.col("split").is_in(list(PARTS)))
    dup_ids = (
        kept.group_by("day", "row_id")
        .agg(pl.col("split").n_unique().alias("n"))
        .filter(pl.col("n") > 1)
    ).height
    block_overlap = 0
    if "_blk" in kept.columns:
        block_overlap = (
            kept.group_by("day", "_blk")
            .agg(pl.col("split").n_unique().alias("n"))
            .filter(pl.col("n") > 1)
            .height
        )
    min_gap = float("inf")
    if "event_sec" in kept.columns:
        for _, g in kept.sort("event_sec").group_by("day"):
            s = g["event_sec"].to_numpy()
            p = g["split"].to_numpy()
            change = np.flatnonzero(p[1:] != p[:-1])
            if len(change):
                min_gap = min(min_gap, float(np.min(s[change + 1] - s[change])))
    dup_feat = 0
    if feature_cols:
        train = kept.filter(pl.col("split") == "train").select(feature_cols).unique()
        test = kept.filter(pl.col("split") == "test").select(feature_cols)
        dup_feat = test.join(train, on=feature_cols, how="semi", nulls_equal=True).height
    return LeakageReport(
        duplicate_ids_across_parts=dup_ids,
        block_overlap=block_overlap,
        min_boundary_gap_seconds=min_gap,
        exact_feature_duplicates_train_test=dup_feat,
        test_rows=kept.filter(pl.col("split") == "test").height,
    )


def split_coverage(df: pl.DataFrame) -> pl.DataFrame:
    """Rows per label and partition: shows labels missing from a partition."""
    return (
        df.group_by("label", "split")
        .agg(pl.len().alias("rows"))
        .pivot(on="split", index="label", values="rows")
        .fill_null(0)
        .sort("label")
    )
