"""Phase 8h research code: the statistics and threshold calculations behind the registered
decisions (docs/phase8h/PREREGISTRATION.md, AUDIT_TRAIL.md section 3). These check the
calculations, not any research outcome."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import polars as pl
import pytest

ROOT = Path(__file__).resolve().parents[2]
for sub in ("scripts/phase8h", "scripts/phase8b"):
    sys.path.insert(0, str(ROOT / sub))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/phase8h" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


A = _load("analyze")
L = _load("lodo")


def test_sign_flip_p_is_exact():
    assert A.sign_flip_p(np.array([0.2, 0.1, 0.3])) == pytest.approx(1 / 8)
    assert A.sign_flip_p(np.array([0.5, -0.5])) == pytest.approx(3 / 4)
    assert A.sign_flip_p(np.array([-0.1, -0.2, -0.3])) == pytest.approx(1.0)


def test_mcnemar_one_sided_direction():
    assert A.mcnemar_p(5, 0) == pytest.approx(0.5**5)  # only T0 exceeds: evidence for T1
    assert A.mcnemar_p(0, 5) == pytest.approx(1.0)
    assert A.mcnemar_p(0, 0) == 1.0


def test_holm_step_down_stops_at_first_failure():
    out = A.holm({"a": 0.01, "b": 0.02, "c": 0.024, "d": 0.5})
    assert out == {"a": True, "b": False, "c": False, "d": False}  # 0.02 > 0.05 / 3


def test_seed_mean_ignores_missing_values():
    assert A.seed_mean([1.0, None, 3.0]) == pytest.approx(2.0)
    assert A.seed_mean([True, False, True, False]) == pytest.approx(0.5)
    assert A.seed_mean([{"x": 1.0, "y": None}, {"x": 3.0, "y": None}]) == {"x": 2.0, "y": None}
    assert A.seed_mean(["a", "b"]) is None and A.seed_mean(["a", "a"]) == "a"


def test_h2_units_exclude_secondary():
    res = {"p": {"benign_windows": 100, "role": "primary"},
           "s": {"benign_windows": 100, "role": "secondary"},
           "b": {"benign_windows": 59, "role": "benign_unit"}}  # fmt: skip
    assert set(A.h2_units(res)) == {"p"}


def test_t1_is_the_bootstrap_bound_not_floored():
    rng = np.random.default_rng(0)
    s = rng.normal(size=60)  # n < 99: T0 is the hold-out maximum
    th = L.thresholds(s, np.arange(60), np.ones(60, bool))
    assert th["T0"] == pytest.approx(s.max())
    bt = L.boot_thresholds(s, np.arange(60), 0.01)  # same seed as inside thresholds()
    assert th["T1"] == pytest.approx(float(np.quantile(bt, 0.90)))  # the bound itself
    assert th["T1"] <= th["T0"]  # a bootstrap quantile cannot exceed the sample maximum
    assert th["T1_floored_at_T0"] == pytest.approx(max(th["T1"], th["T0"]))


def test_block_bootstrap_resamples_whole_slots():
    scores = np.repeat(np.arange(50, dtype=float), 3)  # 3 windows per 30 s slot
    slots = np.repeat(np.arange(50), 3)
    bt = L.boot_thresholds(scores, slots, 0.01)
    assert bt is not None and len(bt) == L.N_BOOT
    assert set(np.unique(bt)) <= set(np.unique(scores))
    assert L.boot_thresholds(scores[:30], slots[:30], 0.01) is None  # < 2 blocks of slots


def test_strict_screening_drops_attacking_entities():
    cal = pl.DataFrame({"key": ["a", "a", "v", "b"], "win": [1, 2, 1, 2]})
    out = L.strict_cal({"cal": cal, "attackers": {"a"}})
    assert out["key"].to_list() == ["v", "b"]


def test_oracle_metrics_use_label_benign_windows_only():
    ev = pl.DataFrame({"key": ["x", "x", "y", "z", "n"], "win": [1, 2, 1, 1, 1],
                       "window_end_ms": [30_000, 60_000, 30_000, 30_000, 30_000],
                       "y": [True, False, False, False, False],
                       "benign": [False, False, True, True, False]})  # fmt: skip
    tgt = {"ev": ev, "hours": 1.0, "attackers": {"x"}}
    s = np.array([0.9, 0.95, 0.1, 0.2, 0.99])
    m = L.metrics(tgt, s, s > 0.5)
    assert m["fpr"] == 0.0  # x's non-attack window and the noisy window n are excluded
    assert m["window_recall"] == 1.0 and m["entity_recall"] == 1.0
