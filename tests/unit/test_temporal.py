"""Phase 8B temporal scorers: causality (future windows never change past scores),
determinism and detection of an obvious burst on synthetic window sequences."""

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.temporal import (
    SCORERS,
    GuardedEWMA,
    LagIForest,
    RobustZ,
    multiscale_windows,
)
from netsentinel.behavior.windows import WINDOW_FEATURES, prepare_flows


def _windows(n_keys=3, n_win=120, burst_at=None, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for k in range(n_keys):
        for w in range(n_win):
            r = {"key": f"h{k}", "win": w, "window_end_ms": (w + 1) * 10_000}
            for f in WINDOW_FEATURES:
                r[f] = float(rng.normal(3.0, 0.3)) if f.startswith(("log", "med")) else float(
                    rng.uniform(0.0, 0.2))  # fmt: skip
            if burst_at is not None and k == 0 and w >= burst_at:
                r["log_flows"] += 4.0
                r["log_dst_ports"] += 4.0
                r["no_reply_frac"] = 0.95
            rows.append(r)
    return pl.DataFrame(rows)


def _make(name):
    if name in ("gru", "tcn"):
        return SCORERS[name](epochs=3, hidden=8, seq_len=4)
    return SCORERS[name]()


@pytest.mark.parametrize("name", sorted(SCORERS))
def test_scores_are_causal(name):
    pytest.importorskip("torch") if name in ("gru", "tcn") else None
    fit = _windows(seed=1)
    full = _windows(n_win=60, burst_at=40, seed=2)
    s = _make(name).fit(fit)
    a = s.score(full)
    prefix = full.filter(pl.col("win") < 40)
    b = s.score(prefix)
    # rows of the prefix in the same (key, win) order as in `full`
    m = (full["win"] < 40).to_numpy()
    np.testing.assert_allclose(a[m], b, rtol=1e-5, atol=1e-5)


@pytest.mark.parametrize("name", sorted(SCORERS))
def test_burst_scores_above_benign(name):
    pytest.importorskip("torch") if name in ("gru", "tcn") else None
    s = _make(name).fit(_windows(seed=1))
    df = _windows(n_win=60, burst_at=40, seed=2)
    sc = s.score(df)
    burst = ((df["key"] == "h0") & (df["win"] >= 40)).to_numpy()
    assert np.median(sc[burst]) > np.quantile(sc[~burst], 0.99)


def test_deterministic_given_seed():
    fit, df = _windows(seed=1), _windows(n_win=30, seed=3)
    a = LagIForest(seed=4).fit(fit).score(df)
    b = LagIForest(seed=4).fit(fit).score(df)
    np.testing.assert_array_equal(a, b)


def test_guarded_ewma_does_not_absorb_a_sustained_attack():
    fit = _windows(seed=1)
    df = _windows(n_win=200, burst_at=40, seed=2)
    ew = GuardedEWMA().fit(fit).score(df)
    rz = RobustZ().fit(fit).score(df)
    late = ((df["key"] == "h0") & (df["win"] >= 180)).to_numpy()
    assert np.median(ew[late]) > 0.5 * np.median(rz[late])  # still far above benign


def test_multiscale_uses_only_completed_coarse_windows():
    # host a: 1 flow per second for 120 s; base 10 s, coarse 60 s
    t = np.arange(120) * 1000 + 500
    flows = prepare_flows(pl.DataFrame({
        "flow_end_milliseconds": t, "ipv4_src_addr": ["10.0.0.1"] * 120,
        "ipv4_dst_addr": ["10.0.0.2"] * 120, "dst_port": [443] * 120, "protocol": [6] * 120,
        "in_bytes": [100] * 120, "out_bytes": [100] * 120, "in_pkts": [2] * 120,
        "out_pkts": [2] * 120, "flow_duration_milliseconds": [10] * 120}))  # fmt: skip
    w = multiscale_windows(flows, "device", 10, (60,))
    by_win = dict(zip(w["win"].to_list(), w["log_flows_c60"].to_list(), strict=True))
    assert all(by_win[i] is None for i in range(5))  # no completed coarse window before 60 s
    assert by_win[5] == pytest.approx(np.log(61))  # window [50,60) ends at 60: coarse 0 done
    assert by_win[6] == pytest.approx(np.log(61))
