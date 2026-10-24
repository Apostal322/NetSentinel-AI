"""Phase 8E streaming monitor: replay equivalence with offline scoring, out-of-order and
duplicate handling, late events, bounded buffers (synthetic demo capture, behaviour path)."""

import random

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.calibrate import calibrate_flows, save_profile
from netsentinel.behavior.monitor import score_flows
from netsentinel.demo.fixtures import DEMO_T0, write_demo_pcap
from netsentinel.incidents import aggregate_incidents
from netsentinel.inference.pipeline import AnalysisPipeline
from netsentinel.streaming.live import END, START, StreamMonitor, WindowStream
from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.pcap import read_packets

CUT_MS = int((DEMO_T0 + 15 * 60) * 1000)


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    d = tmp_path_factory.mktemp("stream")
    recs = list(assemble_flows(read_packets(write_demo_pcap(d / "demo.pcap"))))
    cal = [r for r in recs if r[END] < CUT_MS]
    rest = sorted((r for r in recs if r[END] >= CUT_MS), key=lambda r: r[START])
    prof = calibrate_flows(records_to_frame(cal), window_s=10, mode="vetted_benign")
    cal_dir = save_profile(prof, d / "cal", sources=[], operator_statement="synthetic test")
    return cal_dir, rest


def _offline(cal_dir, recs):
    pipe = AnalysisPipeline(None, cal_dir)
    w = score_flows(pipe.profile, records_to_frame(recs))
    incs = aggregate_incidents(w, [], pipe.calibration["calibration_id"], "s", 10)
    return w, incs


def _stream(cal_dir, recs, **kw):
    pipe = AnalysisPipeline(None, cal_dir)
    m = StreamMonitor(pipe, source="s", **kw)
    m.keep_windows = True
    m.feed(recs)
    res = m.close()
    w = pl.concat(m.windows_out, how="diagonal_relaxed") if m.windows_out else pl.DataFrame()
    return w, m.tracker.incidents(), res


def _same_windows(a: pl.DataFrame, b: pl.DataFrame):
    cols = ["level", "key", "win", "n_flows", "score", "anomalous"]
    a, b = a.select(cols).sort("level", "key", "win"), b.select(cols).sort("level", "key", "win")
    assert a.height == b.height
    assert a.drop("score").equals(b.drop("score"))
    np.testing.assert_allclose(a["score"].to_numpy(), b["score"].to_numpy(), rtol=1e-9)


def test_in_order_stream_equals_offline(setup):
    cal_dir, rest = setup
    w0, i0 = _offline(cal_dir, rest)
    w1, i1, res = _stream(cal_dir, rest, batch_flows=500)
    _same_windows(w0, w1)
    assert [(i.incident_id, i.n_windows) for i in i0] == [(i.incident_id, i.n_windows) for i in i1]
    assert res.stats["late"] == 0 and res.stats["duplicates"] == 0
    assert res.flows == len(rest) and res.incidents == len(i0) > 0


def test_out_of_order_and_duplicates_within_lateness(setup):
    cal_dir, rest = setup
    rng = random.Random(3)
    jitter = sorted(rest, key=lambda r: r[START] + rng.uniform(-20_000, 20_000))
    dups = [dict(r) for r in rng.sample(rest, 50)]
    stream = jitter[:]
    for r in dups:  # re-insert each duplicate within 5 s of its original position
        stream.insert(stream.index(next(x for x in stream if x[START] >= r[START])), r)
    w0, i0 = _offline(cal_dir, rest)
    w1, i1, res = _stream(cal_dir, stream, lateness_s=60)
    _same_windows(w0, w1)
    assert [i.incident_id for i in i0] == [i.incident_id for i in i1]
    assert res.stats["duplicates"] == 50 and res.stats["late"] == 0


def test_late_records_are_counted_not_merged():
    ws = WindowStream(window_s=10, lateness_s=0)
    base = {"IPV4_SRC_ADDR": "a", "IPV4_DST_ADDR": "b", "L4_SRC_PORT": 1, "L4_DST_PORT": 2,
            "PROTOCOL": 6, "IN_BYTES": 1, "OUT_BYTES": 1}  # fmt: skip
    closed = []
    for t in (1_000, 12_000, 25_000):
        closed += ws.push({**base, START: t, END: t + 100})
    assert [w for w, _ in closed] == [0, 1]
    assert ws.push({**base, START: 2_000, END: 2_100}) == []  # window 0 already closed
    assert ws.stats.late == 1
    assert [w for w, _ in ws.flush()] == [2]


def test_buffer_is_bounded_and_clock_skew_ignored():
    ws = WindowStream(window_s=10, lateness_s=3600, max_buffer=100)
    base = {"IPV4_SRC_ADDR": "a", "IPV4_DST_ADDR": "b", "L4_DST_PORT": 2, "PROTOCOL": 6}
    for i in range(1000):
        ws.push({**base, "L4_SRC_PORT": i, START: i * 100, END: i * 100 + 5})
    assert ws.stats.max_buffered <= 101 and ws.stats.forced_closes > 0
    ws2 = WindowStream(window_s=10, lateness_s=0, max_skew_s=60)
    ws2.push({**base, START: 0, END: 5})
    ws2.push({**base, START: 10**10, END: 10**10 + 5})  # skewed sensor clock
    assert ws2.stats.clock_skew == 1 and ws2.stats.windows_closed == 0


def test_clock_resyncs_after_a_real_time_gap():
    """Phase 8c defect (ToN_IoT run): after a gap longer than max_skew_s the clock froze, so
    windows closed only via the buffer cap. A sustained run of later records is a real jump."""
    base = {"IPV4_SRC_ADDR": "a", "IPV4_DST_ADDR": "b", "L4_DST_PORT": 2, "PROTOCOL": 6}
    ws = WindowStream(window_s=30, lateness_s=60, max_buffer=10**9, max_skew_s=3600,
                      resync_after=100)  # fmt: skip
    t = 0
    for i in range(500):  # before the gap
        t = i * 1000
        ws.push({**base, "L4_SRC_PORT": i, START: t, END: t + 5})
    gap = t + 10 * 3600 * 1000
    for i in range(5000):  # 10 h later, 1 record per second
        s = gap + i * 1000
        ws.push({**base, "L4_SRC_PORT": 10_000 + i, START: s, END: s + 5})
    st = ws.stats
    assert st.clock_resyncs == 1 and st.clock_skew == 100
    assert st.forced_closes == 0 and st.late == 0
    assert st.max_buffered < 600  # windows keep closing after the gap
    one = WindowStream(window_s=30, lateness_s=0, max_skew_s=60, resync_after=100)
    one.push({**base, START: 0, END: 5})
    one.push({**base, START: 10**10, END: 10**10 + 5})  # a single skewed record is still ignored
    assert one.stats.clock_resyncs == 0 and one.stats.clock_skew == 1


def _forged_burst_stream(resync_after=1000):
    base = {"IPV4_SRC_ADDR": "a", "IPV4_DST_ADDR": "b", "L4_DST_PORT": 2, "PROTOCOL": 6}
    ws = WindowStream(window_s=30, lateness_s=60, max_buffer=10**9, max_skew_s=3600,
                      resync_after=resync_after)  # fmt: skip
    port = 0

    def push(t):
        nonlocal port
        port += 1
        ws.push({**base, "L4_SRC_PORT": port, START: t, END: t + 5})

    t = 0
    for i in range(1800):  # 30 min of genuine traffic
        t = i * 1000
        push(t)
    forged = t + 30 * 86_400_000
    for i in range(1000):  # malformed or forged timestamps 30 days ahead
        push(forged + i)
    for i in range(1, 7201):  # genuine traffic continues for 2 h
        push(t + i * 1000)
    return ws.stats


def test_forged_future_timestamps_are_reverted_with_bounded_loss():
    """Phase 8d: without probation, 1,000 forged future records made 97% of the following
    genuine records late (dropped) for as long as the forged time lay ahead."""
    st = _forged_burst_stream()
    assert st.clock_resyncs == 1 and st.clock_reverts == 1 and st.health == "clock_anomaly"
    assert st.late <= 1100  # bounded: about one probation period of genuine records
    assert st.accepted >= 1800 + 1000 + 7200 - 1100


def test_genuine_gap_is_confirmed_not_reverted():
    base = {"IPV4_SRC_ADDR": "a", "IPV4_DST_ADDR": "b", "L4_DST_PORT": 2, "PROTOCOL": 6}
    ws = WindowStream(window_s=30, lateness_s=60, max_buffer=10**9, max_skew_s=3600,
                      resync_after=1000)  # fmt: skip
    for i in range(1800):
        ws.push({**base, "L4_SRC_PORT": i, START: i * 1000, END: i * 1000 + 5})
    gap = 1800 * 1000 + 20 * 3600 * 1000
    for i in range(5000):
        s = gap + i * 1000
        ws.push({**base, "L4_SRC_PORT": 10_000 + i, START: s, END: s + 5})
    st = ws.stats
    assert st.clock_resyncs == 1 and st.clock_reverts == 0 and st.health == "ok"
    assert st.late == 0 and st.forced_closes == 0
