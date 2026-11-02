"""Phase 8l DEDALE analysis and evaluation adapter: synthetic checks (no DEDALE data)."""

from __future__ import annotations

import gzip
import importlib.util
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl
import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "phase8l"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"phase8l_t_{name}", SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


AN = _load("dedale_analysis")
EB = _load("dedale_eval_build")


def k_of(n: int, alpha: float = 0.01) -> int:
    return min(math.ceil((n + 1) * (1 - alpha)), n)


def test_t0_is_the_conformal_order_statistic():
    z = np.arange(1, 1000, dtype=float)  # 999 scores
    assert AN.t0(z, k_of) == 990.0  # k = ceil(1000 * 0.99) = 990


def test_three_state_and_n9():
    hold = {"n": 5000, "fpr": 0.012, "upper": 0.025, "lower": 0.008}
    inc = {"n": 5000, "fpr": 0.021, "upper": 0.035, "lower": 0.012}
    fail = {"n": 5000, "fpr": 0.06, "upper": 0.09, "lower": 0.04}
    assert AN.three_state(hold) == "HOLDS"
    assert AN.three_state(inc) == "INCONCLUSIVE"
    assert AN.three_state(fail) == "FAILS"
    assert AN.h1_outcome(fail, n9=True) == "FAILS"
    assert AN.h1_outcome(hold, n9=True) == "NOT EVALUABLE"
    assert AN.three_state({"n": 0}) == "INDETERMINATE"


def test_bounds_bracket_the_rate():
    rng = np.random.default_rng(0)
    host = np.repeat(np.arange(26), 400)
    a = (rng.random(host.size) < 0.01).astype(float)
    lo, hi = AN.boot_bounds(a, host, np.random.default_rng(1))
    assert lo < a.mean() < hi
    c_lo, c_hi = AN.cp_bounds(0.01, 2000)
    assert c_lo < 0.01 < c_hi and AN.cp_bounds(0.0, 2000)[0] == 0.0
    assert AN.cp_bounds(0.01, 200)[1] > c_hi  # fewer effective windows, wider bound
    s = AN.fpr_summary(a, host, np.tile(np.arange(400), 26), lambda z, h: 5000.0, 3)
    assert s["upper"] == max(s["boot"][1], s["cp"][1]) and s["lower"] == min(
        s["boot"][0], s["cp"][0]
    )


def test_holm_overrun_wilson():
    assert AN.holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])
    assert AN.overrun_p(0.0, 1000, 2.0) == 1.0
    assert AN.overrun_p(0.10, 1000, 2.0) < 1e-6 < AN.overrun_p(0.02, 1000, 2.0)
    lo, hi = AN.wilson(5, 10)
    assert lo < 0.5 < hi


def test_logistic_slope_recovers_trend():
    rng = np.random.default_rng(2)
    t = np.tile(np.arange(14), 2000)
    g = np.repeat(np.arange(2000), 14)
    p = 1 / (1 + np.exp(-(-4 + 0.1 * t)))
    y = (rng.random(t.size) < p).astype(float)
    r = AN.logistic_slope(y, t, g)
    assert abs(r["slope_per_day"] - 0.1) < 3 * r["se"] and r["se"] > 0


def test_attribute_hosts_uses_leases():
    leases = pl.DataFrame(
        {
            "ts": ["100.0", "500.0"],
            "mac": ["m1", "m2"],
            "assigned_addr": ["172.16.1.9", "172.16.1.9"],
        }
    )
    keys = pl.Series(["172.16.1.9", "172.16.1.9", "172.16.1.9", "8.8.8.8"])
    end = pl.Series([50_000, 200_000, 600_000, 200_000])
    internal = lambda a: a.startswith("172.16.1.")  # noqa: E731
    got = AN.attribute_hosts(keys, end, leases, internal).to_list()
    assert got == ["m1", "m1", "m2", "8.8.8.8"]  # before first lease: forward fill


def test_entity_detection_delays():
    h = 3_600_000
    wins = pl.DataFrame(
        {
            "host": ["c2"] * 4 + ["x"],
            "window_end_ms": [0, h, 2 * h, 3 * h, h],
            "y1": [False, True, True, False, True],
        }
    )
    alerts = np.array([[0, 0], [0, 1], [1, 1], [1, 0], [1, 1]], dtype=float)
    r = AN.entity_detection(wins, alerts, "c2", comp_ms=0)
    s0, s1 = r["per_seed"]
    assert r["detected_seeds"] == 2 and s0["delay_first_label1_h"] == 1.0
    assert s1["delay_first_label1_h"] == 0.0 and s0["delay_any_after_compromise_h"] == 2.0


def test_eval_parser_keeps_labels_apart(tmp_path):
    hdr = (
        "date;ts;uid;ip_src;port_src;ip_dst;port_dst;proto;service;duration;orig_bytes;"
        "resp_bytes;conn_state;local_orig;local_resp;missed_bytes;history;orig_pkts;"
        "orig_ip_bytes;resp_pkts;resp_ip_bytes;tunnel_parents;ip_proto;label;step;"
        "attack_step;tactic;technique;comments"
    )
    b = EB.A.BOUNDARY_MS / 1000
    tail = ";1;1;SF;T;F;0;Sh;1;60;1;80;-;6;{lab};0;{step};;;"
    rows = [
        f"d;{b - 10};u;172.16.1.3;5;172.19.0.2;443;tcp;ssl;5" + tail.format(lab=0, step="benign"),
        f"d;{b + 36000};u;172.16.1.3;5;172.19.0.2;443;tcp;ssl;1"
        + tail.format(lab=1, step="command_and_control"),
        f"d;{b + 7};u;172.16.1.9;5;1.1.1.1;443;tcp;ssl;1" + tail.format(lab=0, step="benign"),
    ]
    p = tmp_path / "c.csv.gz"
    p.write_bytes(gzip.compress(("\n".join([hdr, *rows]) + "\n").encode()))
    flows, lab, info = EB.parse_eval_day(p, 15)
    assert flows.height == 2 and set(flows["label"]) == {"benign"}  # placeholder only
    assert info["dropped_ending_before_boundary"] == 1  # the first flow ends 5 s before it
    assert lab.height == 2 and int(lab["label"].sum()) == 1
    truth = EB.window_truth(lab)
    assert (
        truth.height == 1
        and truth["y1"][0]
        and truth["steps"][0].to_list() == ["command_and_control"]
    )
    assert EB.outside_script(lab.with_columns(pl.lit("9.9.9.9").alias("dst"))) == ["9.9.9.9"]


def test_modes_refuse_without_freeze(monkeypatch, tmp_path):
    f = _load("dedale_fetch")
    monkeypatch.setattr(f, "FREEZE", tmp_path / "none.md")
    monkeypatch.setitem(sys.modules, "phase8l_dedale_fetch", f)
    monkeypatch.setattr(AN, "_load", lambda name, path: f if "fetch" in name else None)
    with pytest.raises(SystemExit, match="refused"):
        AN._guard(tmp_path / "x.json")


def test_freeze_verification_checks_every_listed_hash(tmp_path):
    f = _load("dedale_fetch")
    (tmp_path / "docs").mkdir()
    pre = tmp_path / "docs" / "pre.md"
    pre.write_bytes(b"rule\r\n")
    code = tmp_path / "a.py"
    code.write_text("x = 1\n", "utf-8")
    freeze = tmp_path / "docs" / "FREEZE.md"
    lines = f"{f.lf_sha256(pre)}  docs/pre.md\n{f.lf_sha256(code)}  a.py\n"
    freeze.write_text("# freeze\n" + lines, "utf-8")
    ok = dict(freeze=freeze, prereg=pre, check_git=False, root=tmp_path)
    assert f.freeze_ok(**ok)
    code.write_text("x = 2\n", "utf-8")
    assert not f.freeze_ok(**ok)  # a frozen file changed
    freeze.write_text(f"{f.lf_sha256(code)}  a.py\n", "utf-8")
    assert not f.freeze_ok(**ok)  # pre-registration not listed


def test_stage_b_needs_n8_pass(tmp_path):
    f = _load("dedale_fetch")
    r = tmp_path / "n8.json"
    assert not f.n8_passed(r)
    r.write_text('{"outcome": "NOT EVALUABLE"}', "utf-8")
    assert not f.n8_passed(r)
    r.write_text('{"outcome": "PASS"}', "utf-8")
    assert f.n8_passed(r)


def test_time_helpers_and_logistic_guard():
    mon = AN.BOUNDARY_MS  # 2025-01-06 00:00 UTC, a Monday
    sat = mon + 5 * 86_400_000
    assert AN.weekday(np.array([mon, sat])).tolist() == [True, False]
    assert (
        AN.window_time(np.array([mon])).item() == mon - 1
    )  # the window ending at 00:00 is Sunday's
    r = AN.logistic_slope(np.zeros(50), np.arange(50) % 5, np.arange(50) % 3)
    assert r["slope_per_day"] is None


def test_overrun_and_holm_against_direct_values():
    from scipy.stats import binom

    assert AN.overrun_p(0.05, 1000, 2.0) == pytest.approx(binom.sf(24, 500, 0.02))
    assert AN.holm([0.02, 0.02, 0.5]) == pytest.approx([0.06, 0.06, 0.5])


def test_attribute_hosts_groups_ties_and_missing_leases():
    leases = pl.DataFrame(
        {
            "ts": ["100.0", "100.0", "300.0"],
            "mac": ["mA", "mB", "mA2"],
            "assigned_addr": ["172.16.1.9", "172.16.1.8", "172.16.1.9"],
        }
    )
    keys = pl.Series(["172.16.1.8", "172.16.1.9", "172.16.1.9", "172.16.1.7"])
    end = pl.Series([100_000, 300_000, 299_999, 100_000])
    internal = lambda a: a.startswith("172.16.1.")  # noqa: E731
    got = AN.attribute_hosts(keys, end, leases, internal).to_list()
    assert got == ["mB", "mA2", "mA", "172.16.1.7"]  # equal time counts as held; no lease: address
    assert AN.entity_host("172.16.1.9", 350_000, leases, internal) == "mA2"


def test_calibration_hosts_remove_excluded_holders():
    cal = pl.DataFrame(
        {
            "key": ["172.16.1.10", "172.16.1.2", "172.16.1.11", "172.16.1.4"],
            "host": ["m10", "m10", "m11", "m4"],
        }
    )
    pop = {
        "eligible": ["172.16.1.10", "172.16.1.11"],
        "clients_3_4": ["172.16.1.4"],
        "excluded_internal": ["172.16.1.2"],
    }
    h = AN.calibration_hosts(cal, pop, ["172.16.1.2"])
    assert h["eligible"] == {"m11"} and h["excluded"] == {"m10"} and h["clients_3_4"] == {"m4"}


def test_truth_window_index_matches_the_builder():
    from netsentinel.behavior.windows import aggregate, prepare_flows

    n = 3
    raw = pl.DataFrame(
        {
            "ts": [1736158000.123, 1736158029.999, 1736158031.0],
            "duration": [0.5, 0.0004, 2.25],
            "ip_src": ["172.16.1.3"] * n,
            "ip_dst": ["172.19.0.2"] * n,
            "port_dst": [443.0] * n,
            "proto": ["tcp"] * n,
            "orig_ip_bytes": [60.0] * n,
            "resp_ip_bytes": [80.0] * n,
            "orig_pkts": [1.0] * n,
            "resp_pkts": [1.0] * n,
            "history": ["Sh"] * n,
            "label": [1.0, 0.0, 1.0],
        }
    )
    flows = EB.A.canonical(raw)
    # build_windows.with_flags, inlined (importing build_windows rebinds `common`)
    rst = lambda c: ((pl.col(c) & 4) > 0).cast(pl.Int8)  # noqa: E731
    frame = flows.with_columns(
        rst("client_tcp_flags").alias("cli_rst"),
        rst("server_tcp_flags").alias("srv_rst"),
        (pl.col("label") != "benign").cast(pl.Float64).alias("is_attack"),
    )
    wins = aggregate(prepare_flows(frame), "device", 30)
    end_ms = (pl.col("ts") * 1000).cast(pl.Int64) + (pl.col("duration") * 1000).cast(pl.Int64)
    lab = raw.select(
        pl.col("ip_src").alias("src"),
        pl.col("ip_dst").alias("dst"),
        end_ms.alias("end_ms"),
        pl.col("label").cast(pl.Int64),
        pl.lit("c2").alias("attack_step"),
    )
    truth = EB.window_truth(lab)
    assert truth.height == 2
    assert wins.join(truth, on=["key", "win"], how="inner").height == truth.height
