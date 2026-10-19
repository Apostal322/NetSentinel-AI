"""Split isolation, determinism and purge-gap tests on synthetic flows."""

import numpy as np
import polars as pl
import pytest

from netsentinel.data.splits import (
    SplitConfig,
    leakage_report,
    make_split,
    split_coverage,
)


def _frame(n: int = 5000, seed: int = 0) -> pl.DataFrame:
    rng = np.random.default_rng(seed)
    day = rng.choice(["2018-02-14", "2018-02-15"], size=n)
    sec = rng.integers(0, 8 * 3600, size=n) + 1_518_595_200
    attack = (sec % 7200) < 1800  # periodic attack bursts
    return pl.DataFrame(
        {
            "day": day,
            "row_id": np.arange(n, dtype=np.uint32),
            "event_sec": sec,
            "label": np.where(attack, "dos_hulk", "benign"),
            "f1": rng.normal(size=n).round(1),
        }
    )


@pytest.mark.parametrize("protocol", ["blocked", "chronological"])
def test_time_protocols_isolate_partitions(protocol):
    df = _frame()
    cfg = SplitConfig(protocol=protocol, block_minutes=15, purge_seconds=120)
    out = df.join(make_split(df, cfg), on=["day", "row_id"])
    rep = leakage_report(out, block_minutes=15 if protocol == "blocked" else None)
    assert rep.duplicate_ids_across_parts == 0
    assert rep.block_overlap == 0
    assert rep.min_boundary_gap_seconds >= 120
    assert rep.ok(120)
    assert set(out["split"].unique()) <= {"train", "val", "test", "purged"}


def test_blocked_split_covers_recurring_attacks_in_every_partition():
    df = _frame()
    out = df.join(make_split(df, SplitConfig(purge_seconds=60)), on=["day", "row_id"])
    cov = split_coverage(out).filter(pl.col("label") == "dos_hulk")
    assert all(cov[p][0] > 0 for p in ("train", "val", "test"))


def test_splits_are_deterministic_and_seed_sensitive():
    df = _frame()
    a = make_split(df, SplitConfig(seed=1))
    b = make_split(df, SplitConfig(seed=1))
    c = make_split(df, SplitConfig(seed=2))
    assert a.equals(b)
    assert not a.equals(c)


def test_random_split_fractions_and_stratification():
    df = _frame()
    out = df.join(make_split(df, SplitConfig(protocol="random")), on=["day", "row_id"])
    frac = out.group_by("split").len().with_columns(pl.col("len") / df.height)
    got = dict(zip(frac["split"], frac["len"], strict=True))
    assert got["train"] == pytest.approx(0.6, abs=0.01)
    # random splits do NOT respect time: partitions interleave second-by-second
    assert leakage_report(out).min_boundary_gap_seconds < 60


def test_leave_day_out():
    df = _frame()
    cfg = SplitConfig(protocol="leave_day_out", test_days=("2018-02-15",))
    out = df.join(make_split(df, cfg), on=["day", "row_id"])
    assert set(out.filter(pl.col("day") == "2018-02-15")["split"]) == {"test"}
    assert set(out.filter(pl.col("day") == "2018-02-14")["split"]) == {"train"}
    with pytest.raises(ValueError):
        make_split(df, SplitConfig(protocol="leave_day_out"))


def test_exact_duplicate_detection():
    df = _frame()
    out = df.join(make_split(df, SplitConfig(protocol="random")), on=["day", "row_id"])
    rep = leakage_report(out, feature_cols=["f1"])
    assert rep.exact_feature_duplicates_train_test > 0  # rounded normals collide by design


def test_config_validation():
    with pytest.raises(ValueError):
        SplitConfig(protocol="kfold")
    with pytest.raises(ValueError):
        SplitConfig(fractions=(0.5, 0.5, 0.5))
