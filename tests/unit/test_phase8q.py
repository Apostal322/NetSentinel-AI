"""Phase 8q: label-audit rules (interval boundaries, overlapping rows, families, roles) and the
label-free threshold estimators (empty / non-finite / tied scores, contamination behaviour)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LA = _load("phase8q_label_audit_t", "scripts/phase8q/label_audit.py")
CM = _load("phase8q_methods_t", "scripts/phase8q/calibration_methods.py")


def utc_ms(day_start_utc_ms: int, local_hhmm: str) -> int:
    h, m = map(int, local_hhmm.split(":"))
    return day_start_utc_ms + ((h + LA.UTC_OFFSET_H) * 60 + m) * 60_000


DAY_20 = 1519084800000  # 2018-02-20 00:00 UTC


def test_interval_boundaries_and_utc_offset():
    src = np.array(["18.219.9.1"] * 4)
    ends = np.array([utc_ms(DAY_20, "13:13"), utc_ms(DAY_20, "13:32"), utc_ms(DAY_20, "13:33"),
                     utc_ms(DAY_20, "10:12")])  # fmt: skip
    rows = LA.in_rows("2018-02-20", ends, src)
    assert rows.tolist() == [1, 1, -1, 0]  # LOIC-UDP row inclusive at both ends; LOIC-HTTP row 0


def test_interval_requires_the_named_host():
    rows = LA.in_rows("2018-02-20", np.array([utc_ms(DAY_20, "13:20")]), np.array(["10.0.0.1"]))
    assert rows.tolist() == [-1]


def test_roles_per_dataset():
    assert LA.source_role("nfcic", "2018-02-22", "18.218.115.60", 10, None, set()) == "documented"
    assert LA.source_role("nfcic", "2018-02-22", "77.72.82.135", 10, None, set()) == "undocumented"
    assert LA.source_role("nfunsw", "all", "175.45.176.3", 10, None, set()) == "documented"
    assert LA.source_role("nfunsw", "all", "175.45.176.4", 10, None, set()) == "undocumented"
    assert LA.source_role("nfton", "all", "192.168.1.37", 10, None, set()) == "documented"
    assert (
        LA.source_role("nfton", "all", "192.168.1.193", 10, "192.168.1.33", set())
        == "attacked_host"
    )
    heavy = {"192.168.100.147"}
    assert LA.source_role("nfbot", "all", "192.168.100.147", 10**6, None, heavy) == "documented"
    assert (
        LA.source_role("nfbot", "all", "192.168.100.5", 800, "192.168.100.147", heavy)
        == "attacked_host"
    )


def test_table_covers_every_raw_cic_attack_label():
    names = set().union(*[r[3] for rows in LA.CIC_TABLE.values() for r in rows])
    assert {
        "ssh_bruteforce",
        "dos_hulk",
        "ddos_loic_http",
        "ddos_loic_udp",
        "ddos_hoic",
        "web_xss",
        "bot",
    } <= names


def test_t0_errors_and_ties():
    with pytest.raises(ValueError):
        CM.t0(np.array([]))
    with pytest.raises(ValueError):
        CM.t0(np.array([0.1, np.nan]))
    assert CM.t0(np.full(500, 0.3)) == 0.3  # all tied: the threshold is the tied value
    assert CM.t0(np.linspace(0, 1, 200)) == pytest.approx(np.linspace(0, 1, 200)[198])


def test_host_cap_limits_a_dominant_host_but_keeps_small_hosts():
    benign = np.linspace(0, 1, 1000)
    hb = np.array([f"b{i % 200}" for i in range(1000)])  # 200 hosts of 5 windows
    evil = np.full(100, 5.0)  # one host with 100 high windows (9 % of the mass)
    s, h = np.r_[benign, evil], np.r_[hb, np.array(["evil"] * 100)]
    assert CM.t0(s) == 5.0
    assert (
        CM.host_capped_t0(s, h, cap=0.02) == 5.0
    )  # a 2 % cap still lets one host hold the 1 % budget
    assert CM.host_capped_t0(s, h) < 5.0  # the registered cap alpha/2 does not
    assert abs(CM.host_capped_t0(benign, hb) - CM.t0(benign)) < 0.01  # small hosts unchanged


def test_block_median_resists_a_short_episode():
    rng = np.random.default_rng(0)
    end = np.repeat(np.arange(10) * CM.HOUR_MS, 200)
    s = rng.random(2000)
    s[:200] = 5.0  # one hour of contamination
    assert CM.block_median_t0(s, end) < 1.0
    assert CM.block_median_t0(s[:300], end[:300]) == CM.t0(s[:300])  # too few blocks: t0


def test_persistent_trim_and_abstention():
    rng = np.random.default_rng(1)
    s = np.r_[rng.random(1000), np.full(50, 0.999)]
    h = np.r_[np.array([f"b{i % 100}" for i in range(1000)]), np.array(["evil"] * 50)]
    assert CM.persistent_trim_t0(s, h) < CM.t0(s)
    end = np.arange(1050) * 60_000
    assert CM.insufficient_evidence(np.array(["a"] * 1050), end)  # one host
    many = np.array([f"h{i}" for i in range(1050)])
    assert not CM.insufficient_evidence(many, end)
