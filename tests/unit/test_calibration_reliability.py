"""Phase 7 P2: threshold diagnostics, cross-fitting, statuses, safe updates and rollback."""

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.calibrate import calibrate_flows, save_profile
from netsentinel.behavior.profile import threshold_diagnostics
from netsentinel.behavior.registry import (
    activate,
    read_registry,
    resolve_calibration,
    rollback,
    update_check,
)
from tests.unit.test_behavior import synth

T0 = 1_600_000_000_000


def test_threshold_diagnostics_quantify_small_holdout_risk():
    d = threshold_diagnostics(117, 0.01)  # Phase 6 H1 CTU-26 held-out size
    assert d["k"] == 117 and d["reliable"] is False
    assert 0.02 < d["fpr_upper95"] < 0.03  # ~2.5%: sampling alone can exceed 2x target
    assert 117 < d["windows_needed_for_2x_target"] < 300  # ~ 3/n bound for the max score
    big = threshold_diagnostics(d["windows_needed_for_2x_target"], 0.01)
    assert big["reliable"] is True


def test_crossfit_scores_every_window_and_split_does_not():
    cal = synth(240, seed=31)
    cf = calibrate_flows(cal, window_s=30, threshold_method="crossfit")
    sp = calibrate_flows(cal, window_s=30, threshold_method="split")
    g_cf, g_sp = cf.levels["global"], sp.levels["global"]
    assert g_cf.threshold_method == "crossfit5" and g_sp.threshold_method == "split"
    assert g_cf.n_holdout_windows > 3 * g_sp.n_holdout_windows - 5
    assert g_cf.threshold_diag["fpr_upper95"] < g_sp.threshold_diag["fpr_upper95"]
    with pytest.raises(ValueError):
        calibrate_flows(cal, threshold_method="magic")


def test_short_history_is_provisional_not_ready():
    prof = calibrate_flows(synth(30, seed=32), window_s=30, threshold_method="split")
    assert prof.status == "baseline_provisional"
    assert any("realised FPR may reach" in w or "too few" in w
               for w in prof.levels["global"].warnings)  # fmt: skip


def test_contamination_warning_when_calibration_contains_bursts():
    cal = pl.concat([synth(240, seed=33, burst_at_min=m) for m in (40,)] +
                    [synth(240, seed=34, start_ms=T0 + 240 * 60_000, burst_at_min=b)
                     for b in (20, 60, 100, 140, 180, 220)])  # fmt: skip
    prof = calibrate_flows(cal, window_s=30, mode="unlabelled")
    warns = " ".join(prof.levels["device"].warnings + prof.levels["global"].warnings)
    assert "unlabelled calibration" in warns
    assert prof.levels["device"].trimmed_windows > 0


def _save(tmp_path, frame, **kw):
    prof = calibrate_flows(frame, window_s=30)
    return save_profile(prof, tmp_path, sources=[{"path": "synthetic"}],
                        operator_statement="synthetic test", **kw)  # fmt: skip


def test_update_check_blocks_activation_of_anomalous_period_and_rollback(tmp_path):
    first = _save(tmp_path, synth(240, seed=35))
    activate(first.name, tmp_path)
    assert resolve_calibration("active", tmp_path) == first
    # a normal new period: consistent with the active baseline -> can be activated
    normal = synth(240, seed=36, start_ms=T0 + 240 * 60_000)
    chk = update_check(first, normal)
    assert chk["review_required"] is False
    second = _save(tmp_path, normal, update_check=chk)
    activate(second.name, tmp_path)
    # a new period full of scans: anomalous under the active baseline -> review required
    scans = pl.concat([synth(120, seed=37, start_ms=T0 + 480 * 60_000, burst_at_min=m)
                       for m in range(0, 120, 3)])  # fmt: skip
    chk2 = update_check(second, scans)
    assert chk2["review_required"] is True and "attack traffic" in chk2["reason"]
    third = _save(tmp_path, scans, update_check=chk2)
    with pytest.raises(ValueError, match="requires review"):
        activate(third.name, tmp_path)
    assert read_registry(tmp_path)["active"] == second.name  # unchanged
    activate(third.name, tmp_path, reviewed=True, note="vetted by operator")
    assert read_registry(tmp_path)["active"] == third.name
    rollback(tmp_path)
    reg = read_registry(tmp_path)
    assert reg["active"] == second.name and reg["history"][-1]["note"].startswith("rollback")
    with pytest.raises(FileNotFoundError):
        resolve_calibration("active", tmp_path / "empty")


def test_update_gate_flags_a_short_burst_the_rate_test_misses(tmp_path):
    """Phase 8F: a 60 s scan inside an otherwise normal candidate period."""
    first = _save(tmp_path, synth(240, seed=35))
    normal = synth(240, seed=36, start_ms=T0 + 240 * 60_000)
    row = normal.row(0, named=True)
    at = T0 + 360 * 60_000
    scan = pl.DataFrame([{**row, "flow_start_milliseconds": at + i * 75,
                          "flow_end_milliseconds": at + i * 75, "flow_duration_milliseconds": 0,
                          "ipv4_dst_addr": f"172.31.{i // 250}.{i % 250}", "dst_port": 1000 + i,
                          "protocol": 6, "in_bytes": 60, "out_bytes": 0, "in_pkts": 1,
                          "out_pkts": 0} for i in range(800)], schema=normal.schema)  # fmt: skip
    chk = update_check(first, pl.concat([normal, scan]).sort("flow_end_milliseconds"))
    assert chk["review_required"] and chk["strong_outliers"] and not chk["rate_review"]
    assert update_check(first, normal)["review_required"] is False


def _persistent_host(minutes: int, start_ms: int, host: str = "10.0.0.99") -> pl.DataFrame:
    """A host absent from the calibration that is active all period, 2 flows per minute."""
    rng = np.random.default_rng(1)
    rows = []
    for m in range(minutes):
        for _ in range(2):
            t0 = start_ms + m * 60_000 + int(rng.integers(0, 60_000))
            dur = int(rng.integers(1, 3000))
            rows.append((t0, t0 + dur, host, f"93.184.0.{rng.integers(1, 20)}", 443, 6,
                         int(rng.integers(100, 5000)), int(rng.integers(48_000, 72_000)),
                         int(rng.integers(2, 20)), int(rng.integers(2, 40)), dur, 0,
                         0))  # fmt: skip
    return pl.DataFrame(rows, schema=synth(1).columns, orient="row")


def test_update_gate_flags_a_persistently_anomalous_entity(tmp_path):
    """Phase 8g (CTU-13 scenario 9, docs/phase8g/V4_FAILURE_ANALYSIS.md): one host alerting in
    about 10% of its windows all period moves neither the global rate nor any single score past
    the strong-outlier limit, so the refresh learned it. The per-entity test requires review."""
    first = _save(tmp_path, synth(240, seed=35))
    normal = synth(240, seed=36, start_ms=T0 + 240 * 60_000)
    cand = pl.concat([normal, _persistent_host(240, T0 + 240 * 60_000)]).sort(
        "flow_end_milliseconds")  # fmt: skip
    chk = update_check(first, cand)
    assert not chk["rate_review"] and not chk["strong_outliers"]
    assert chk["review_required"] and "persistently" in chk["reason"]
    assert [(e["level"], e["entity"]) for e in chk["excess_entities"]] == [("device", "10.0.0.99")]
    assert update_check(first, normal)["excess_entities"] == []
