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
    "buffer_exhaustion": ("ok", ["buffer_spill"]),  # Phase 8g: spilled, not force-closed
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


# ---------------------------------------------------------------- Phase 8f (near the boundaries)
spec8f = importlib.util.spec_from_file_location(
    "stream_near_trigger", ROOT / "scripts/phase8f/stream_near_trigger.py"
)
nt = importlib.util.module_from_spec(spec8f)
spec8f.loader.exec_module(nt)

EXPECTED_8F = {
    "future_share_85": "integrity_degraded", "future_share_89": "integrity_degraded",
    "future_share_90": "clock_anomaly", "future_share_91": "clock_anomaly",
    "future_share_95": "clock_anomaly", "oscillating_88_92": "clock_anomaly",
    "repeated_cycles_then_clean": "clock_anomaly", "sustained_89_long": "integrity_degraded",
    "backward_share_89": "integrity_degraded", "backward_share_95": "clock_anomaly",
    "in_skew_future_2pct": "ok", "in_skew_single_record": "ok",
}  # fmt: skip


@pytest.fixture(scope="module")
def results_8f():
    return nt.run_all()


@pytest.mark.parametrize("name", sorted(EXPECTED_8F))
def test_near_trigger_and_in_skew_scenarios_lose_nothing(results_8f, name):
    r = results_8f[name]
    assert r["genuine_lost"] == 0 and r["windows_differing"] == 0, r
    assert r["peak_held"] <= 50_000 + 4 * 1000  # window buffer + quarantine cap
    assert r["health"] == EXPECTED_8F[name], r
    if not name.startswith("in_skew"):
        assert r["forged_emitted"] == 0, r


def test_in_skew_forgery_is_counted_and_cannot_pull_the_watermark(results_8f):
    r = results_8f["in_skew_single_record"]
    assert r["stats"]["late"] == 0 and r["stats"]["uncorroborated_ahead"] == 1
    old = sr.run(nt.scenarios()["in_skew_single_record"], clock_quorum=1)  # pre-8f clock
    assert old["genuine_lost"] > 8000 and old["health"] == "ok"  # the silent failure fixed


def test_quarantine_memory_stays_bounded_under_sustained_near_trigger_forgery(results_8f):
    st = results_8f["sustained_89_long"]["stats"]
    assert st["max_quarantined"] <= 4 * 1000 and st["quarantine_evicted"] > 200_000


# ---------------------------------------------------------------- Phase 8g (CTU-13 findings)
def _long_connections():
    g = sr.genuine_stream(0, 3 * 3600)  # 3 h, 3 hosts at 1 record/s
    out = []
    for i, r in enumerate(g):
        out.append(r)
        if i > 5 * 3600 and i % 100 == 0:  # a connection that lasted 2.5 h, logged when it ends
            out.append(sr.rec(r[START] - 9_000_000, "10.0.0.5", 5_000_000 + i, dur=9_000_000))
    return out


def test_long_lived_connections_are_not_dropped(monkeypatch):
    recs = _long_connections()
    r = sr.run(recs, lateness_s=360)
    assert r["genuine_lost"] == 0 and r["windows_differing"] == 0, r
    assert r["stats"]["clock_skew"] == 0 and r["health"] == "ok"
    orig = WindowStream._side  # the pre-8g rule (BEHIND by start) drops them silently
    monkeypatch.setattr(WindowStream, "_side", lambda self, s, e=None: orig(self, s, None))
    old = sr.run(recs, lateness_s=360)
    assert old["genuine_lost"] == 143 and old["health"] == "ok"


def _dense_out_of_order(n_s=600):
    import random

    rng = random.Random(3)
    g = sr.genuine_stream(0, n_s)
    return sorted(g, key=lambda r: r[START] + rng.uniform(-20_000, 20_000))


def test_dense_traffic_spills_to_disk_without_loss():
    recs = _dense_out_of_order()
    old = sr.run(recs, max_buffer=100, max_spill=0)  # pre-8g behaviour: forced closes
    assert old["genuine_lost"] > 0 and old["health"] == "buffer_pressure"
    new = sr.run(recs, max_buffer=100)
    assert new["genuine_lost"] == 0 and new["windows_differing"] == 0, new
    assert new["stats"]["forced_closes"] == 0 and new["health_flags"] == ["buffer_spill"]
    assert new["peak_held"] <= 100 + 4 * 1000


def test_exhausted_spill_budget_degrades_explicitly():
    r = sr.run(_dense_out_of_order(), max_buffer=100, max_spill=200)
    assert r["stats"]["forced_closes"] > 0 and r["health"] == "buffer_pressure"
    assert r["stats"]["max_spilled"] <= 200 + 1000  # budget + one pending flush per window


def test_spilled_windows_deduplicate_and_clean_up(tmp_path):
    ws = WindowStream(30, lateness_s=600, max_buffer=50, max_spill=10_000, spill_dir=tmp_path)
    recs = sr.genuine_stream(0, 120)
    for r in recs:
        ws.push(r)
    for r in recs[:90]:  # duplicates arriving while their windows are on disk
        ws.push(dict(r))
    assert ws.stats.spilled_windows > 0 and any(tmp_path.iterdir())
    out = [x for _, rs in ws.flush() for x in rs]
    assert len(out) == len(recs) and ws.stats.duplicates == 90
    assert ws.stats.accepted == len(recs) and not any(tmp_path.iterdir())
