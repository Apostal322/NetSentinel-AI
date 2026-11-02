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
    leases = pl.DataFrame({"ts": ["100.0", "500.0"], "mac": ["m1", "m2"],
                           "assigned_addr": ["172.16.1.9", "172.16.1.9"]})  # fmt: skip
    keys = pl.Series(["172.16.1.9", "172.16.1.9", "172.16.1.9", "8.8.8.8"])
    end = pl.Series([50_000, 200_000, 600_000, 200_000])
    internal = lambda a: a.startswith("172.16.1.")  # noqa: E731
    got = AN.attribute_hosts(keys, end, leases, internal).to_list()
    assert got == ["m1", "m1", "m2", "8.8.8.8"]  # before first lease: forward fill


def test_entity_detection_delays():
    h = 3_600_000
    wins = pl.DataFrame({"host": ["c2"] * 4 + ["x"], "window_end_ms": [0, h, 2 * h, 3 * h, h],
                         "y1": [False, True, True, False, True]})  # fmt: skip
    alerts = np.array([[0, 0], [0, 1], [1, 1], [1, 0], [1, 1]], dtype=float)
    r = AN.entity_detection(wins, alerts, "c2", comp_ms=0)
    s0, s1 = r["per_seed"]
    assert r["detected_seeds"] == 2 and s0["delay_first_label1_h"] == 1.0
    assert s1["delay_first_label1_h"] == 0.0 and s0["delay_any_after_compromise_h"] == 2.0


def test_eval_parser_keeps_labels_apart(tmp_path):
    hdr = ("date;ts;uid;ip_src;port_src;ip_dst;port_dst;proto;service;duration;orig_bytes;"
           "resp_bytes;conn_state;local_orig;local_resp;missed_bytes;history;orig_pkts;"
           "orig_ip_bytes;resp_pkts;resp_ip_bytes;tunnel_parents;ip_proto;label;step;"
           "attack_step;tactic;technique;comments")  # fmt: skip
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
