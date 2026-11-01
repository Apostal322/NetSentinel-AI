"""Phase 8i research code: the calculations behind the registered protocol
(docs/phase8i/PREREGISTRATION.md). These check calculations and data handling, not any research
outcome."""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl
import pytest

ROOT = Path(__file__).resolve().parents[2]
for sub in ("scripts/phase8i", "scripts/phase8h", "scripts/phase8b"):
    sys.path.insert(0, str(ROOT / sub))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/phase8i" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


C = _load("common")


def test_network_weights_balance_networks_not_domains():
    w = C.network_weights(["nfcic"] * 4 + ["nfunsw", "nfton"])
    assert w.sum() == pytest.approx(1.0)
    assert w[:4].sum() == pytest.approx(1 / 3) and w[4] == pytest.approx(1 / 3)
    assert np.allclose(w[:4], 1 / 12)


def test_draw_pool_is_deterministic_without_replacement_and_capped():
    keys = np.array(["a"] * 30 + ["b"] * 10 + ["c"] * 2, dtype=object)
    i1, i2 = C.draw_pool(keys, 25, 3), C.draw_pool(keys, 25, 3)
    assert np.array_equal(i1, i2) and len(set(i1)) == 25
    assert not np.array_equal(i1, C.draw_pool(keys, 25, 4))  # draws differ
    assert len(C.draw_pool(keys, 100, 0)) == len(keys)  # pool smaller than the budget: all
    single = C.draw_pool(keys, 5, 1, single_entity=True)
    assert len(set(keys[single])) == 1
    assert len(C.draw_pool(np.array([], dtype=object), 5, 0)) == 0


def test_single_entity_draw_returns_whole_entity_when_short():
    keys = np.array(["a"] * 30 + ["c"] * 2, dtype=object)
    for r in range(20):
        idx = C.draw_pool(keys, 25, r, single_entity=True)
        ent = set(keys[idx])
        assert len(ent) == 1
        assert len(idx) == (2 if ent == {"c"} else 25)


def test_relative_volume_shifts_only_volume_columns():
    x = np.arange(24, dtype=float).reshape(2, 12)
    med = np.array([1.0, 2.0, 3.0, 4.0])
    out = C.relative_volume(x, med)
    other = [i for i in range(12) if i not in C.VOL_IDX]
    assert np.array_equal(out[:, other], x[:, other])
    assert np.array_equal(out[:, C.VOL_IDX], x[:, C.VOL_IDX] - med)
    assert np.array_equal(x, np.arange(24, dtype=float).reshape(2, 12))  # input untouched


def test_rep_subset_and_relvol_compose():
    d = {"_volmed": np.zeros(4)}
    x = np.ones((3, 12))
    keep = [i for i in range(12) if i not in C.VOL_IDX]
    assert C.Rep("nv", keep).apply(x, d).shape == (3, 8)
    assert C.Rep("raw").apply(x, d) is x


def test_blocks_hours_since_start():
    start = 1_000_000
    end = np.array([start - 1, start, start + 3_599_999, start + 3_600_000, start + 7_300_000])
    assert C.blocks(end, start).tolist() == [-1, 0, 0, 1, 2]


def test_risk_coverage_keeps_lowest_scores():
    score = np.array([0.1, 0.9, 0.2, 0.8, 0.3])
    over = np.array([False, True, False, True, True])
    rc = {r["coverage"]: r for r in C.risk_coverage(score, over, (0.4, 0.6, 1.0))}
    assert rc[0.4]["exceedance"] == 0.0  # the two lowest scores do not overrun
    assert rc[0.6]["exceedance"] == pytest.approx(1 / 3)
    assert rc[1.0]["exceedance"] == pytest.approx(3 / 5)


def test_auc_orientation_and_undefined():
    y = np.array([0, 0, 1, 1])
    assert C.auc(np.array([0.1, 0.2, 0.8, 0.9]), y) == 1.0
    assert C.auc(np.array([0.9, 0.8, 0.2, 0.1]), y) == 0.0
    assert C.auc(np.array([0.1, 0.2]), np.array([0, 0])) is None


def test_t0_threshold_resolution_limit():
    # n < 199: k = ceil((n + 1) * 0.99) = n, so the threshold is the hold-out maximum (the
    # registered resolution limit); the library flags it unreliable only when k > n (n < 99)
    for n in (100, 198):
        thr, rel = C.t0(np.arange(n, dtype=float))
        assert thr == n - 1 and rel is True
    thr, rel = C.t0(np.arange(50, dtype=float))
    assert thr == 49.0 and rel is False
    thr, _ = C.t0(np.arange(199, dtype=float))
    assert thr == 197.0  # n = 199: first n below the maximum
    s = np.arange(1000, dtype=float)
    thr, rel = C.t0(s)
    assert rel and thr == s[math.ceil(1001 * 0.99) - 1]
    assert (s > thr).mean() <= C.ALPHA  # alerts are strictly above the threshold


def _frame(keys, wins, **cols):
    base = {f: [0.0] * len(keys) for f in C.FEATS}
    base.update(cols)
    return pl.DataFrame({"key": keys, "win": wins, "window_end_ms": [w * 30_000 for w in wins],
                         **base})


def test_load_domain_strict_benign_and_labels(tmp_path):
    """Entities attacking in calibration OR evaluation leave benign calibration and benign
    evaluation; calibration attack windows form the labelled pool; noisy windows are neither."""
    d = tmp_path / "dom"
    d.mkdir()
    cal = _frame(["h1", "h2", "att_cal", "att_ev"] * 30, [w for w in range(30) for _ in range(4)])
    cal.write_parquet(d / "cal_clean.parquet")
    cal.write_parquet(d / "cal_unlabelled.parquet")
    pl.DataFrame({"key": ["att_cal", "att_cal"], "win": [3, 4], "y": [True, True]}).write_parquet(
        d / "cal_truth.parquet")
    ev = _frame(["h1", "h2", "att_cal", "att_ev", "noisy"] * 20,
                [100 + w for w in range(20) for _ in range(5)])  # fmt: skip
    ev.write_parquet(d / "eval_clean.parquet")
    tr = ev.select("key", "win").with_columns((pl.col("key") == "att_ev").alias("y"))
    tr.write_parquet(d / "truth.parquet")
    pl.DataFrame({"key": ["noisy"] * 20, "win": list(range(100, 120))}).write_parquet(
        d / "noisy.parquet")
    (d / "meta.json").write_text('{"eval_hours": 0.1, "first_attack_ms": {"att_ev": 1}}')
    dom = C.load_domain(d, "testnet")
    assert set(dom["cal"]["key"].unique()) == {"h1", "h2"}
    assert dom["pool"].height == 2 and set(dom["pool"]["key"]) == {"att_cal"}
    ev2 = dom["ev"]
    assert set(ev2.filter(pl.col("benign"))["key"].unique()) == {"h1", "h2"}
    assert set(ev2.filter(pl.col("y"))["key"].unique()) == {"att_ev"}
    assert dom["attackers"] == {"att_ev"}
    btrain, hold = C.split_benign(dom)
    assert btrain["win"].max() < hold["win"].min()  # time-ordered, no overlap
    assert btrain.height + hold.height == dom["cal"].height


def test_dump_is_atomic(tmp_path):
    p = tmp_path / "r" / "x.json"
    C.dump(p, {"a": np.float64(1.5)})
    assert p.read_text("utf-8").strip().startswith("{") and not list(p.parent.glob("*.partial"))


def _flows(starts_s, src="10.0.0.1", label="benign"):
    n = len(starts_s)
    return pl.DataFrame({
        "flow_start_milliseconds": [int(s * 1000) for s in starts_s],
        "flow_end_milliseconds": [int(s * 1000) + 500 for s in starts_s],
        "ipv4_src_addr": [src] * n, "ipv4_dst_addr": ["10.0.0.9"] * n,
        "dst_port": [80] * n, "protocol": [6] * n, "in_bytes": [100] * n, "out_bytes": [50] * n,
        "in_pkts": [2] * n, "out_pkts": [1] * n, "flow_duration_milliseconds": [500] * n,
        "client_tcp_flags": [2] * n, "server_tcp_flags": [18] * n, "label": [label] * n})


@pytest.mark.parametrize("dev_cut", [False, True])  # hourly slices / per-file carry
def test_builder_carries_boundary_window_and_labels_calibration(tmp_path, monkeypatch, dev_cut):
    """A window spanning two day files is aggregated once; calibration windows holding an
    attack flow are labelled in cal_truth."""
    B = _load("build_windows")
    monkeypatch.chdir(tmp_path)
    # file 1 ends at 59.5 s (window 1), file 2 starts at 50 s (window 1 again) -> one window
    f1 = pl.concat([_flows(np.arange(0, 60, 5)), _flows([12], src="10.0.0.66", label="dos")])
    f2 = _flows(np.arange(50, 400, 5))
    f1.write_parquet(tmp_path / "2020-01-01.parquet")
    f2.write_parquet(tmp_path / "2020-01-02.parquet")
    out = tmp_path / "dom"
    res = B.build([tmp_path / "2020-01-01.parquet", tmp_path / "2020-01-02.parquet"], dev_cut,
                  out, "test")  # fmt: skip
    cal = pl.read_parquet(out / "cal_unlabelled.parquet")
    ev = pl.read_parquet(out / "eval_clean.parquet")
    for part in (cal, ev):  # no (key, window) aggregated twice within a part
        assert part.height == part.select("key", "win").unique().height
    # only the window holding the time midpoint may appear in both parts (flows split by END)
    both = cal.select("key", "win").join(ev.select("key", "win"), on=["key", "win"])
    assert both.height <= 1
    ct = pl.read_parquet(out / "cal_truth.parquet")
    assert ct.filter(pl.col("y"))["key"].to_list() == ["10.0.0.66"]
    assert res["cal_attack_windows"] == 1 and res["cal_attack_entities"] == 1
    if not dev_cut:  # the development cut keeps the first 78% of each file's span
        assert res["flows"] == f1.height + f2.height


def test_a4_margin_shortcut_equals_full_prediction():
    """A4's score = stored source margin + the new trees' margin (exp_a.fit_corrections)."""
    import lightgbm as lgb

    A = _load("exp_a")
    rng = np.random.default_rng(0)
    X = rng.normal(size=(600, 12))  # noqa: N806
    y = (X[:, 0] + 0.5 * rng.normal(size=600) > 0).astype(int)
    src = lgb.LGBMClassifier(n_estimators=30, num_leaves=7, verbose=-1, random_state=0).fit(X, y)
    a4 = lgb.LGBMClassifier(n_estimators=10, num_leaves=7, min_child_samples=5, verbose=-1,
                            random_state=0).fit(X[:200], y[:200], init_model=src.booster_)  # fmt: skip
    assert a4.booster_.num_trees() == 40  # the source trees are kept
    full = a4.predict_proba(X)[:, 1]
    short = A.expit(src.booster_.predict(X, raw_score=True)
                    + a4.booster_.predict(X, raw_score=True, start_iteration=30))  # fmt: skip
    assert np.allclose(full, short, atol=1e-9)
