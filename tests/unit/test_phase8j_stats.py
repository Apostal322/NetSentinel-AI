"""Phase 8j research code: the statistics behind the calibration-reliability design
(docs/phase8j/CALIBRATION_RELIABILITY_METHODOLOGY.md). These check calculations, not any
research outcome."""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
for sub in ("scripts/phase8j", "scripts/phase8i", "scripts/phase8h", "scripts/phase8b"):
    sys.path.insert(0, str(ROOT / sub))


def _load(name: str):
    # registered under a unique name: scripts/phase8c/dev_compare.py also exists, and other test
    # modules import it by its bare name
    spec = importlib.util.spec_from_file_location(
        f"phase8j_{name}", ROOT / "scripts/phase8j" / f"{name}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"phase8j_{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


T = _load("threshold_stats")


def test_rank_matches_the_deployed_conformal_threshold():
    from netsentinel.behavior.profile import conformal_threshold

    rng = np.random.default_rng(0)
    for n in (99, 150, 199, 313, 1000):
        s = rng.standard_normal(n)
        thr, _ = conformal_threshold(s, T.ALPHA)
        assert thr == np.sort(s)[T.k_of(n) - 1]


def test_iid_risk_is_a_sawtooth_and_199_is_on_a_bad_stretch():
    from scipy.stats import beta

    def q95(n):
        k = T.k_of(n)
        return beta.ppf(0.95, n + 1 - k, k)

    assert q95(198) <= 0.02 < q95(199)  # 199 drops from the maximum to the 2nd largest
    assert q95(312) > 0.02 >= q95(313)
    assert all(q95(n) <= 0.02 for n in range(313, 700))


def test_pac_count_is_the_largest_safe_one():
    from scipy.stats import beta

    assert T.pac_exceedances(100) == 0  # even the maximum is not safe at n = 100
    for n in (199, 313, 1000):
        lo = T.pac_exceedances(n)
        assert lo >= 1
        assert beta.sf(0.02, lo, n + 1 - lo) <= 0.05 < beta.sf(0.02, lo + 1, n - lo)


def test_pac_threshold_abstains_without_enough_independent_evidence():
    z = np.random.default_rng(1).standard_normal(4000)
    assert T.pac_threshold(z, 50.0) is None
    assert T.pac_threshold(z, float("nan")) is None
    t0 = np.sort(z)[T.k_of(len(z)) - 1]
    assert T.pac_threshold(z, 1000.0) == t0  # ample evidence: never looser than T0
    t = T.pac_threshold(z, 200.0)
    assert t is not None and t > t0  # thin evidence: stricter than T0


def test_pac_threshold_is_an_observed_score_so_ties_never_alert():
    z = np.repeat(np.arange(50, dtype=float), 40)  # heavy ties, as in N4
    t = T.pac_threshold(z, 1000.0)
    assert t in z
    assert (z > t).mean() <= 0.01


def test_autocorrelation_deflates_the_effective_sample():
    rng = np.random.default_rng(4)
    hosts = np.repeat(np.arange(20), 500)
    iid = rng.standard_normal(len(hosts))
    ar = np.concatenate([T.ar1(rng, 500, 0.9) for _ in range(20)])
    assert abs(T.lag1(iid, hosts)) < 0.05
    assert 0.85 < T.lag1(ar, hosts) < 0.95
    assert T.neff_m3(iid, hosts) > 0.8 * len(hosts)
    assert T.neff_m3(ar, hosts) < 0.1 * len(hosts)  # design effect (1 + 0.9) / (1 - 0.9) = 19


def test_out_of_fold_exceedance_flags_a_host_unlike_the_others():
    rng = np.random.default_rng(2)
    hosts = np.repeat(np.arange(12), 200)
    z = rng.standard_normal(len(hosts))
    z[hosts == 0] += 10  # host 0 sits far above everyone else
    out = T.out_of_fold_exceedance(z, hosts)
    assert out[hosts == 0].all()
    assert out[hosts != 0].mean() < 0.05
    assert not T.out_of_fold_exceedance(z, np.zeros(len(z), dtype=int)).any()  # one host


def test_cluster_bound_is_a_rate_and_zero_without_exceedances():
    rng = np.random.default_rng(3)
    hosts = np.repeat(np.arange(20), 50)
    assert T.cluster_ucb(np.zeros(1000, dtype=bool), hosts, rng) == 0.0
    e = np.zeros(1000, dtype=bool)
    e[hosts == 0] = True  # all exceedances in one host: a wide bound
    ub = T.cluster_ucb(e, hosts, rng)
    assert 0.05 < ub <= 1.0


def _flows(starts_s, src="10.0.0.1", label="benign"):
    import polars as pl

    n = len(starts_s)
    return pl.DataFrame({
        "flow_start_milliseconds": [int(s * 1000) for s in starts_s],
        "flow_end_milliseconds": [int(s * 1000) + 500 for s in starts_s],
        "ipv4_src_addr": [src] * n, "ipv4_dst_addr": ["10.0.0.9"] * n, "dst_port": [80] * n,
        "protocol": [6] * n, "in_bytes": [100] * n, "out_bytes": [50] * n, "in_pkts": [2] * n,
        "out_pkts": [1] * n, "flow_duration_milliseconds": [500] * n, "client_tcp_flags": [2] * n,
        "server_tcp_flags": [18] * n, "label": [label] * n})  # fmt: skip


def test_p1x_windows_equal_the_unlabelled_variant_without_exclusions(tmp_path, monkeypatch):
    """P1x = the Phase 8i all-flow windows, except that calibration-period attackers are kept out
    of the calibration windows and of the destination memory."""
    import polars as pl

    P = _load("build_p1x")  # noqa: N806
    monkeypatch.chdir(tmp_path)
    rng = np.random.default_rng(0)
    f = pl.concat([_flows(np.sort(rng.uniform(0, 900, 300)), src=f"10.0.0.{i}") for i in range(3)]
                  + [_flows([30, 31, 620], src="10.0.0.66", label="dos")])  # fmt: skip
    f = f.with_columns(pl.Series("ipv4_dst_addr", [f"10.1.0.{i}" for i in
                                                   rng.integers(0, 40, f.height)]))  # fmt: skip
    f.sort("flow_end_milliseconds").write_parquet(tmp_path / "2020-01-01.parquet")
    files = [tmp_path / "2020-01-01.parquet"]
    P.BW.build(files, False, tmp_path / "p8i", "test")
    mid = __import__("json").loads((tmp_path / "p8i" / "meta.json").read_text())["mid_ms"]
    b = P.P1xBuilder(mid, set())
    for df in P.BW.chunks(files, False):
        b.add(df)
    b.save(tmp_path / "none", {})
    for part in ("cal", "eval"):
        x = pl.read_parquet(tmp_path / "none" / f"{part}_p1x.parquet").sort("key", "win")
        u = pl.read_parquet(tmp_path / "p8i" / f"{part}_unlabelled.parquet").sort("key", "win")
        assert x.height > 0 and x.equals(u.select(x.columns)), part
    meta = P.build(files, False, tmp_path / "p8i", tmp_path / "p1x", 10**9)
    assert meta["excluded_hosts"] == 1  # the calibration-period attacker 10.0.0.66
    cal = pl.read_parquet(tmp_path / "p1x" / "cal_p1x.parquet")
    assert "10.0.0.66" not in cal["key"].to_list()
    assert pl.read_parquet(tmp_path / "p1x" / "eval_p1x.parquet").height == pl.read_parquet(
        tmp_path / "p8i" / "eval_unlabelled.parquet").height  # fmt: skip


def test_host_sizes_sum_to_n_and_skew_concentrates():
    for skew in (0.0, 1.0):
        m = T.sizes(10, 1000, skew)
        assert m.sum() == 1000 and (m >= 1).all()
    assert T.sizes(10, 1000, 1.0).max() > T.sizes(10, 1000, 0.0).max()
    assert math.isclose(T.sizes(4, 400, 0.0).std(), 0.0)


DC = _load("dev_compare")


def _fake_domain(benign_per_block, fp_per_block):
    d = object.__new__(DC.Domain)
    blk, s, ben = [], [], []
    for b, (n, fp) in enumerate(zip(benign_per_block, fp_per_block, strict=True)):
        blk += [b] * n
        s += [1.0] * fp + [0.0] * (n - fp)
        ben += [True] * n
    d.blk, d.nb = np.array(blk), len(benign_per_block)
    d.ev = {"s": np.array(s), "benign": np.array(ben)}
    d.ben_per_blk = np.bincount(d.blk, minlength=d.nb)
    return d


def test_overrun_tests_against_the_tolerance_and_skips_small_blocks():
    d = _fake_domain([20_000, 20_000, 20_000, 29], [266, 600, 0, 29])  # 1.33%, 3%, 0%, tiny
    over = d.overrun(0.5)
    assert over[0] == 0.0  # 1.33% is not significantly above 2 alpha
    assert over[1] == 1.0  # 3% is
    assert over[2] == 0.0
    assert np.isnan(over[3])  # fewer than 30 verified-benign windows: not scored


def test_variants_keep_the_full_hold_out_and_drop_duplicates():
    d = object.__new__(DC.Domain)
    n = 600
    d.cal = {
        "hold": np.ones(n, dtype=bool),
        "key": np.repeat([f"h{i}" for i in range(12)], 50),
        "end": np.tile(np.arange(50) * 30_000.0, 12),
    }  # hold-out spans 25 min
    out = DC.variants(d, np.random.default_rng(0))
    assert sum(f for f, _ in out) == 1 and len(out[0][1]) == n and out[0][0]
    sigs = {idx.tobytes() for _, idx in out}
    assert len(sigs) == len(out)  # the 3 h / 12 h truncations equal the full set: dropped


def test_tau_is_the_least_abstention_meeting_the_overrun_target():
    rng = np.random.default_rng(5)
    units = np.repeat(["a", "b", "c"], 400)
    x = rng.normal(size=(1200, 3))
    y = (x[:, 0] + 0.3 * rng.normal(size=1200) > 1.0).astype(float)  # predictable overruns
    rows = {"x": x, "over_t0": y, "unit": units}
    t = DC.choose_tau(rows, ["a", "b", "c"], "over_t0")
    assert not t["flag"] and t["oof_overrun"] <= 0.10 and 0.5 < t["oof_coverage"] < 1.0
