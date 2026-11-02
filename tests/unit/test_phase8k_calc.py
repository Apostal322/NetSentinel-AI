"""Phase 8k research code: the calculations behind the confirmatory verdict
(docs/phase8k/PREREGISTRATION.md). These check calculations, not research outcomes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
for sub in ("scripts/phase8j", "scripts/phase8i", "scripts/phase8h", "scripts/phase8b"):
    sys.path.insert(0, str(ROOT / sub))


def _load(name: str):
    # unique module names: scripts/phase8c has a dev_compare.py that other tests import by name
    spec = importlib.util.spec_from_file_location(
        f"phase8k_{name}", ROOT / "scripts/phase8k" / f"{name}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"phase8k_{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


X = _load("dev_experiments")
CA = _load("confirm_analysis")


def test_weighted_threshold_matches_the_plain_quantile_with_equal_weights():
    s = np.arange(1000, dtype=float)
    t = X.weighted_threshold(s, np.ones(1000), 0.01)
    assert (s > t).mean() <= 0.01 and (s >= t).mean() > 0.01


def test_host_weights_balance_and_cap():
    keys = np.array(["a"] * 90 + ["b"] * 10)
    w = X.host_weights(keys, None)
    assert np.isclose(w[keys == "a"].sum(), w[keys == "b"].sum())
    keys = np.array(["big"] * 60 + [f"h{i}" for i in range(40) for _ in range(1)])
    w = X.host_weights(keys, 0.05)
    assert np.isclose(w.sum(), 1.0)
    assert w[keys == "big"].sum() <= 0.05 + 1e-9  # the dominant host is capped


def test_hypergeometric_control_and_exact_interval():
    # 9 units, 3 unsafe, 6 accepted with none unsafe: 1 / C(9, 6) = 1/84
    assert np.isclose(CA.hypergeom_p(9, 3, 6, 0), 1 / 84)
    assert CA.clopper(0, 3)[0] == 0.0 and 0.70 < CA.clopper(0, 3)[1] < 0.71
    assert CA.clopper(0, 0) is None


def _fam(unsafe, fa, fpr):
    return {"unsafe": unsafe, "false_accept": fa, "fpr_accepted_pooled": fpr}


def _report(**kw):
    base = {"far": 0.0, "frr": 0.0, "accepted_determinable": 2, "fpr_accepted_pooled": 0.01,
            "fpr_accepted_ucb95": 0.02, "random_selection_p": 0.01, "entity_recall_accepted": 0.8,
            "coverage_attack_entities_on_adequate": 0.9,
            "per_family": {"F1": _fam(2, 0, 0.01)}}  # fmt: skip
    return {**base, **kw}


def test_verdict_needs_every_criterion():
    assert CA.verdict(_report())["verdict"] == "success"
    for bad in ({"far": 0.34}, {"frr": 0.6}, {"accepted_determinable": 1},
                {"fpr_accepted_ucb95": 0.031}, {"random_selection_p": 0.06},
                {"entity_recall_accepted": 0.49}, {"coverage_attack_entities_on_adequate": 0.4},
                {"frr": None},
                {"per_family": {"F2": _fam(2, 1, 0.01)}},
                {"per_family": {"F2": _fam(0, 0, 0.03)}}):  # fmt: skip
        assert CA.verdict(_report(**bad))["verdict"] == "failure", bad


def test_pooled_fpr_weights_families_then_units():
    units = [{"unit": "a", "fpr": 0.01}, {"unit": "b", "fpr": 0.03}, {"unit": "c", "fpr": 0.10}]
    fam = {"a": "F1", "b": "F1", "c": "F2"}
    assert np.isclose(CA.pooled(units, fam, "fpr"), (0.02 + 0.10) / 2)


def test_two_level_bound_covers_a_homogeneous_rate():
    rng = np.random.default_rng(0)
    units = [
        {"unit": f"u{i}", "host_fp": np.full(50, 1.0), "host_n": np.full(50, 100.0)}
        for i in range(4)
    ]
    fam = {f"u{i}": "F1" for i in range(4)}
    assert np.isclose(CA.two_level_ucb(units, fam, rng), 0.01)


def test_e3_gate_is_the_best_possible_random_selection_p():
    assert np.isclose(CA.best_possible_p(4, 2), 1 / 6)  # a perfect rule cannot reach 0.05
    assert np.isclose(CA.best_possible_p(6, 3), 1 / 20)
    assert CA.best_possible_p(5, 0) == 1.0


def test_bootstrap_ignores_units_without_verified_benign_windows():
    rng = np.random.default_rng(1)
    units = [{"unit": "a", "host_fp": np.full(20, 1.0), "host_n": np.full(20, 100.0)},
             {"unit": "b", "host_fp": np.zeros(0), "host_n": np.zeros(0)}]  # fmt: skip
    assert np.isclose(CA.two_level_ucb(units, {"a": "F1", "b": "F1"}, rng), 0.01)
    assert CA.two_level_ucb(units[1:], {"b": "F1"}, rng) is None


TM = _load("telemetry_maps")


def test_tstat_header_names_are_cleaned(tmp_path):
    p = tmp_path / "tcp_complete.csv"
    p.write_text("#15#c_ip:1,c_port:2,first:29,timestamp,label\n1.1.1.1,5,1.0,x,HTTP\n", "utf-8")
    assert TM.tstat_columns(p) == ["c_ip", "c_port", "first", "timestamp", "label"]


def test_tstat_tcp_maps_direction_headers_and_resets():
    import polars as pl

    row = {"first": "1000.5", "last": "3000.0", "c_ip": "10.0.0.1", "s_ip": "10.0.0.2",
           "s_port": "443", "c_bytes_all": "100", "s_bytes_all": "0", "c_pkts_all": "3",
           "s_pkts_all": "0", "durat": "1999.5", "c_rst_cnt": "0", "s_rst_cnt": "2",
           "label": "service_scan"}  # fmt: skip
    out = TM.tstat_tcp(pl.DataFrame([row]))
    r = out.row(0, named=True)
    assert (r["ipv4_src_addr"], r["dst_port"], r["protocol"]) == ("10.0.0.1", 443, 6)
    assert r["in_bytes"] == 100 + 40 * 3 and r["out_bytes"] == 0 and r["out_pkts"] == 0
    assert (r["cli_rst"], r["srv_rst"], r["is_attack"]) == (0, 1, 1.0)
    assert r["flow_end_milliseconds"] == 3000


def test_tstat_udp_end_covers_both_sides_and_benign_labels():
    import polars as pl

    rows = [{"c_ip": "a", "s_ip": "b", "s_port": "53", "c_first_abs": "1000", "c_durat": "0",
             "c_bytes_all": "60", "c_pkts_all": "1", "s_first_abs": "1005", "s_durat": "10",
             "s_bytes_all": "90", "s_pkts_all": "1", "label": "DNS"},
            {"c_ip": "a", "s_ip": "b", "s_port": "53", "c_first_abs": "2000", "c_durat": "5",
             "c_bytes_all": "60", "c_pkts_all": "1", "s_first_abs": "0", "s_durat": "0",
             "s_bytes_all": "0", "s_pkts_all": "0", "label": "something new"}]  # fmt: skip
    out = TM.tstat_udp(pl.DataFrame(rows))
    assert out["flow_end_milliseconds"].to_list() == [1015, 2005]
    assert out["out_pkts"].to_list() == [1.0, 0.0]
    assert out["is_attack"].to_list() == [0.0, 1.0]  # an unknown label counts as an attack


def test_zeek_conn_maps_ip_bytes_resets_and_labels():
    import polars as pl

    df = pl.DataFrame({"ts": [10.0, 20.0], "duration": [1.5, None], "src_ip_zeek": ["a", "c"],
                       "dest_ip_zeek": ["b", "d"], "dest_port_zeek": [22, 53],
                       "proto": ["tcp", "udp"], "orig_ip_bytes": [120, 60],
                       "resp_ip_bytes": [0, 80], "orig_pkts": [3, 1], "resp_pkts": [0, 1],
                       "history": ["ShR", "Dd"], "label_binary": ["True", "False"]})  # fmt: skip
    out = TM.zeek_conn(df)
    assert out["flow_end_milliseconds"].to_list() == [11500, 20000]
    assert out["protocol"].to_list() == [6, 17]
    assert out["cli_rst"].to_list() == [1, 0] and out["srv_rst"].to_list() == [0, 0]
    assert out["is_attack"].to_list() == [1.0, 0.0]
