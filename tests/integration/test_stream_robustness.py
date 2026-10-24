"""Phase 8e streaming security: deterministic adversarial timestamp scenarios
(scripts/phase8e/stream_robustness.py). Every scenario must lose no genuine record, emit no
forged record, keep memory bounded and report the anomaly as an explicit health flag."""

import importlib.util
from pathlib import Path

import pytest

from netsentinel.streaming.live import END, START, WindowStream
from netsentinel.telemetry.zeek import IDLE, parse_conn_lines

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "stream_robustness", ROOT / "scripts/phase8e/stream_robustness.py"
)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

EXPECTED_HEALTH = {
    "baseline": ("ok", []),
    "single_future_burst": ("clock_anomaly", ["clock_anomaly"]),
    "repeated_future_bursts": ("clock_anomaly", ["clock_anomaly"]),
    "alternating_valid_invalid": ("integrity_degraded", ["integrity_degraded"]),
    "long_idle_gap": ("ok", ["resynced"]),
    "clock_reset_backward": ("clock_reset", ["clock_reset"]),
    "out_of_order_and_duplicates": ("ok", []),
    "repeated_resync_attempts": ("clock_anomaly", ["clock_anomaly"]),
    "forged_flood_dominant": ("clock_anomaly", ["clock_anomaly"]),
    "buffer_exhaustion": ("buffer_pressure", ["buffer_pressure"]),
}  # fmt: skip


@pytest.fixture(scope="module")
def results():
    return sr.run_all()


@pytest.mark.parametrize("name", sorted(EXPECTED_HEALTH))
def test_no_genuine_loss_no_forged_leak_bounded_memory(results, name):
    r = results[name]
    assert r["genuine_lost"] == 0, r
    assert r["windows_differing"] == 0, r
    assert r["forged_emitted"] == 0, r
    # memory bound: window buffer (<= max_buffer) + quarantine (<= 4 x resync_after)
    assert r["peak_held"] <= 50_000 + 4 * 1000
    health, flags = EXPECTED_HEALTH[name]
    assert r["health"] == health and r["health_flags"] == flags, r


def test_duplicates_are_counted_not_emitted(results):
    assert results["out_of_order_and_duplicates"]["stats"]["duplicates"] > 400


def test_advance_closes_windows_during_idle_periods():
    ws = WindowStream(window_s=30, lateness_s=60)
    for i in range(120):  # 2 minutes of traffic, then silence
        ws.push(sr.rec(i * 1000, "10.0.0.1", i))
    open_before = len(ws.heap)
    assert open_before >= 2  # the last windows are still open without new traffic
    closed = ws.advance(119_000 + 10 * 60_000)  # ten minutes later, wall clock
    assert closed and not ws.heap
    assert ws.advance(10**15) == []  # an absurd wall clock is ignored, not trusted


def test_follow_mode_idle_marker_passes_through_the_parser():
    header = "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
    lines = ["#separator \\x09\n", header, IDLE,
             "1600000000.0\t10.0.0.1\t1\t10.0.0.2\t80\ttcp\n", IDLE]  # fmt: skip
    out = list(parse_conn_lines(lines))
    assert out[0] is IDLE and out[2] is IDLE and out[1][START] == 1_600_000_000_000
    assert out[1][END] == 1_600_000_000_000
