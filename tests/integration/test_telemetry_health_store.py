"""Phase 8g finalization: stream / parse health reaches the event store with every behaviour
window. Before, a behaviour-only monitor (no model bundle) stored its windows without any
health, so `buffer_pressure` or `clock_anomaly` was visible only in the CLI summary and the
dashboard showed quiet windows as if nothing had been lost."""

import sqlite3

import pytest

from netsentinel.behavior.calibrate import calibrate_flows, save_profile
from netsentinel.demo.fixtures import DEMO_T0, write_demo_pcap
from netsentinel.inference.pipeline import AnalysisPipeline
from netsentinel.storage.events import EventStore
from netsentinel.streaming.live import END, START, StreamMonitor
from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.pcap import read_packets

CUT_MS = int((DEMO_T0 + 15 * 60) * 1000)
OLD_BEHAVIOR_TABLE = """CREATE TABLE behavior_events (
    event_id TEXT PRIMARY KEY, window_end TEXT NOT NULL, source TEXT NOT NULL,
    level TEXT NOT NULL, entity TEXT NOT NULL, window_s INTEGER NOT NULL, n_flows INTEGER,
    score REAL, severity REAL, threshold REAL, anomalous INTEGER NOT NULL, model_scope TEXT,
    explanation TEXT, calibration TEXT NOT NULL)"""


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    d = tmp_path_factory.mktemp("health")
    recs = list(assemble_flows(read_packets(write_demo_pcap(d / "demo.pcap"))))
    cal = [r for r in recs if r[END] < CUT_MS]
    rest = sorted((r for r in recs if r[END] >= CUT_MS), key=lambda r: r[START])
    prof = calibrate_flows(records_to_frame(cal), window_s=10, mode="vetted_benign")
    return save_profile(prof, d / "cal", sources=[], operator_statement="synthetic test"), rest


def _monitor(cal_dir, recs, db, **kw):
    store = EventStore(db)
    m = StreamMonitor(AnalysisPipeline(None, cal_dir), store, source="s", batch_flows=200, **kw)
    m.feed(recs)
    res = m.close()
    rows = store.behavior(limit=5000)
    store.close()
    return res, rows


def test_behaviour_only_monitor_stores_degraded_health(setup, tmp_path):
    cal_dir, rest = setup
    res, rows = _monitor(cal_dir, rest, tmp_path / "e.sqlite", max_buffer=5, max_spill=0)
    assert res.stats["health"] == "buffer_pressure" and rows
    assert "buffer_pressure" in {r["telemetry_health"] for r in rows}
    assert res.assessment["state"] != "normal_valid_baseline"
    assert not res.assessment["normality_supported"]


def test_api_reports_the_stored_health_of_each_window(setup, tmp_path):
    from fastapi.testclient import TestClient

    from netsentinel.api.app import Settings, create_app

    cal_dir, rest = setup
    _monitor(cal_dir, rest, tmp_path / "e.sqlite", max_buffer=5, max_spill=0)
    api = TestClient(create_app(Settings(bundle_dir=tmp_path / "no_bundle",
                                         events_db=tmp_path / "e.sqlite")))  # fmt: skip
    rows = api.get("/behavior", params={"limit": 5000}).json()
    assert rows and "buffer_pressure" in {r["telemetry_health"] for r in rows}


def test_healthy_monitor_stores_ok(setup, tmp_path):
    cal_dir, rest = setup
    res, rows = _monitor(cal_dir, rest, tmp_path / "e.sqlite")
    assert res.stats["health"] == "ok" and {r["telemetry_health"] for r in rows} == {"ok"}


def test_old_database_gains_the_column_and_keeps_its_rows(tmp_path):
    db = tmp_path / "old.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute(OLD_BEHAVIOR_TABLE)
        conn.execute("INSERT INTO behavior_events VALUES ('e1', '2026-01-01T12:00:30', 's', "
                     "'device', '10.0.0.1', 30, 3, 1.0, 50.0, 5.0, 0, 'own', '[]', "
                     "'c')")  # fmt: skip
    store = EventStore(db)
    import polars as pl

    store.add_behavior(pl.DataFrame({
        "level": ["device"], "key": ["10.0.0.2"], "win": [2], "window_end_ms": [1_767_268_860_000],
        "n_flows": [4], "score": [2.0], "severity": [40.0], "threshold": [5.0],
        "anomalous": [False], "model_scope": ["own"], "explanation": [[]],
    }), "s", "c", 30, telemetry_health="clock_anomaly")  # fmt: skip
    rows = {r["entity"]: r for r in store.behavior()}
    store.close()
    assert rows["10.0.0.1"]["telemetry_health"] is None  # stored before Phase 8g
    assert rows["10.0.0.2"]["telemetry_health"] == "clock_anomaly"
