"""Phase 8n metric and decision logic on synthetic inputs: T0 rank, recall/FPR/entity metrics,
the G1-G3 rule and selection, the entity stability counts and the replication seeds."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AF = _load("phase8n_analyze_t", "scripts/phase8n/analyze_fragility.py")
CC = _load("phase8n_compare_t", "scripts/phase8n/compare_candidates.py")
ES = _load("phase8n_entity_t", "scripts/phase8n/entity_sensitivity.py")


def labels(n_benign: int = 200) -> SimpleNamespace:
    key = np.array(["a"] * 10 + ["b"] * 6 + ["c"] * 2 + [f"h{i % 20}" for i in range(n_benign)])
    y = np.r_[np.ones(18, bool), np.zeros(n_benign, bool)]
    lab = SimpleNamespace(key=key, y=y, benign=~y, end=np.arange(len(y)) * 30_000)
    lab.entities = ["a", "b"]  # c has 2 attack windows (< 5): not an entity
    lab.masks = {e: y & (key == e) for e in lab.entities}
    return lab


def test_t0_and_metrics():
    lab = labels()
    s_hold = np.linspace(0, 1, 200)  # k = ceil(201 * 0.99) = 199
    t0 = np.sort(s_hold)[AF.k_of(200) - 1]
    s_ev = np.zeros(len(lab.y))
    s_ev[:10] = 2.0  # entity a fully above T0
    s_ev[10] = 2.0  # one window of entity b
    s_ev[18:20] = 2.0  # two benign false alerts
    m = AF.metrics(lab, s_hold, s_ev)
    assert m["t0"] == t0
    assert m["window_recall"] == 11 / 18
    assert m["false_alerts"] == 2 and m["fpr"] == 2 / 200
    assert m["entities"] == 2 and m["entities_detected"] == 2
    assert m["detected"] == {"a": True, "b": True}
    assert m["median_delay_s"] == 0.0  # both entities alerted on their first attack window


def test_auc_edge_cases():
    assert AF.auc(np.array([1.0]), np.array([])) is None
    assert AF.auc(np.array([2.0, 3.0]), np.array([0.0, 1.0])) == 1.0
    assert AF.auc(np.array([0.5]), np.array([0.5])) == 0.5


def summary(recall: float, fa: float, r: int, u: int, ent: float) -> dict:
    nets = {n: {"window_recall": recall, "false_alerts": fa} for n in CC.NETWORKS}
    return {"network_means": nets, "R": r, "U": u, "entity_recall_pooled": ent}


def test_go_rule_clauses():
    m0 = summary(0.6, 100, 46, 9, 0.71)
    assert CC.go(summary(0.6, 100, 46, 6, 0.71), m0)["pass"]  # U down by exactly 3, R equal
    assert not CC.go(summary(0.6, 100, 46, 7, 0.71), m0)["G3_robustness"]
    assert not CC.go(summary(0.6, 100, 45, 1, 0.71), m0)["G3_robustness"]  # R lost
    assert not CC.go(summary(0.54, 100, 50, 1, 0.71), m0)["pass"]  # recall below M0 - 0.05
    assert not CC.go(summary(0.6, 126, 50, 1, 0.71), m0)["pass"]  # workload above 1.25x
    assert not CC.go(summary(0.6, 100, 50, 1, 0.68), m0)["G1_entity"]


def test_entity_counts_and_share_threshold():
    share = {"x": {"f1": 1.0, "f2": 0.1}, "y": {"f1": 0.0, "f2": 0.0}, "z": {"f1": 0.5, "f2": 0.3}}
    any_w = ES.counts(share, 1e-12, ["f1", "f2"])
    assert (any_w["R"], any_w["U"], any_w["N"]) == (2, 0, 1)
    strict = ES.counts(share, 0.2, ["f1", "f2"])
    assert (strict["R"], strict["U"], strict["N"]) == (1, 1, 1)
    assert strict["unstable_misses_by_fit"] == {"f2": 1}


def test_replication_seeds_differ_from_the_seen_fits():
    CA = _load("phase8n_candidates_t", "scripts/phase8n/candidates.py")  # noqa: N806
    assert CA.REPLICATION.isdisjoint({0, 1, 2})
    assert {3, 4, 5} <= CA.REPLICATION
