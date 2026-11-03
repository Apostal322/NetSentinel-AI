"""Phase 8n Experiment A helpers: the reimplemented training matrix equals Phase 8h
`train_matrix`, column transforms preserve or remove exactly what they claim, and the host
bootstrap moves whole hosts (synthetic data only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import polars as pl
import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "phase8n_fragility", ROOT / "scripts/phase8n/fragility.py"
)
FR = importlib.util.module_from_spec(spec)
sys.modules["phase8n_fragility"] = FR
spec.loader.exec_module(FR)
L = sys.modules["lodo"]


def domain(n_cal: int, n_ev: int, seed: int = 0) -> dict:
    rng = np.random.default_rng(seed)

    def frame(n: int, attack: bool) -> pl.DataFrame:
        cols = {f: rng.normal(size=n) for f in FR.FEATS}
        cols["key"] = [f"h{i}" for i in rng.integers(0, 40, n)]
        if attack:
            cols["y"] = rng.random(n) < 0.3
            cols["noisy"] = rng.random(n) < 0.05
        return pl.DataFrame(cols)

    return {"cal": frame(n_cal, False), "ev": frame(n_ev, True), "network": "nfx"}


@pytest.mark.parametrize("sizes", [(300, 400), (40_000, 30_000)])  # below and above the cap
def test_train_rows_equals_phase8h_train_matrix(sizes):
    d = domain(*sizes)
    saved = L.CAP
    L.CAP = FR.C.CAP
    try:
        x_ref, _, y_ref = L.train_matrix(d, 3)
    finally:
        L.CAP = saved
    x, y, keys = FR.train_rows(d, 3)
    np.testing.assert_array_equal(x, x_ref)
    np.testing.assert_array_equal(y, y_ref)
    assert len(keys) == len(y)


def test_transforms():
    x = np.arange(24, dtype=float).reshape(2, 12)
    specs = FR.perturbations()
    np.testing.assert_array_equal(FR.transform(x, specs["P_ref"]), x)
    assert FR.transform(x, specs["A2_reverse_columns"])[0, 0] == x[0, -1]
    c = FR.transform(x, specs["A2_constant_column"])
    assert c.shape == (2, 13) and (c[:, -1] == 1).all()
    s = FR.transform(x, specs["A2_sqrt_new_dst_frac"])
    assert (
        s[1, FR.NDF] == pytest.approx(np.sqrt(x[1, FR.NDF]))
        and (s[:, : FR.NDF] == x[:, : FR.NDF]).all()
    )
    dropped = FR.transform(x, specs["A4_drop_new_dst_frac"])
    assert dropped.shape == (2, 11) and FR.NDF not in [int(v) % 12 for v in dropped[0]]
    assert "shuffle" in specs["A4_shuffle_new_dst_frac"]  # training-side only: no target transform
    np.testing.assert_array_equal(FR.transform(x, specs["A4_shuffle_new_dst_frac"]), x)


def test_host_bootstrap_moves_whole_hosts():
    keys = np.array(["a"] * 5 + ["b"] * 3 + ["c"] * 2)
    idx = FR.host_bootstrap(keys, np.random.default_rng(1))
    picked = keys[idx]
    for h in np.unique(picked):
        assert (picked == h).sum() % (keys == h).sum() == 0  # each draw brings all of a host's rows
    assert len(np.unique(keys[idx])) <= 3
