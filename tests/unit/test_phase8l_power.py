"""Phase 8l power analysis: the calculation behind the sample-size claims
(docs/phase8l/POWER_ANALYSIS.md). Checks calculations, not research outcomes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8l_power", ROOT / "scripts/phase8l/power_analysis.py"
)
P = importlib.util.module_from_spec(_spec)
sys.modules["phase8l_power"] = P
_spec.loader.exec_module(P)


def test_a_perfect_rule_with_exact_labels_is_powered_only_with_enough_units(monkeypatch):
    monkeypatch.setattr(P, "REPS", 300)
    rng = np.random.default_rng(0)
    small = P.one_config(4, 0.5, 1.0, 0.0, 100_000, 1, 0.0, rng)
    big = P.one_config(30, 0.5, 1.0, 0.0, 100_000, 1, 0.0, rng)
    assert small["power"] == 0.0  # E3: 1/C(4, 2) > 0.05 for any outcome
    assert big["power"] > 0.95


def test_three_state_labels_leave_thin_evidence_indeterminate(monkeypatch):
    monkeypatch.setattr(P, "REPS", 200)
    rng = np.random.default_rng(1)
    thin = P.one_config(20, 0.5, 0.9, 0.1, 50, 1, 0.0, rng, "three_state")
    rich = P.one_config(20, 0.5, 0.9, 0.1, 5000, 1, 0.0, rng, "three_state")
    assert thin["mean_determinable_units"] < 10 < rich["mean_determinable_units"]


def test_label_noise_shrinks_with_evidence():
    rng = np.random.default_rng(2)
    a, b = P.label_noise(50, rng), P.label_noise(5000, rng)
    assert b["adequate_labelled_unsafe"] < a["adequate_labelled_unsafe"]
    assert b["unsafe_labelled_adequate"] <= a["unsafe_labelled_adequate"]
