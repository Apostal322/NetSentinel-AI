"""Phase 8e explicit uncertainty states (netsentinel.inference.assessment): every state is
reachable, evidence is never silenced by drift / expiry / degraded telemetry, and only
`normal_valid_baseline` supports a claim of normality."""

import sqlite3

import pytest

from netsentinel.inference.assessment import STATES, UNCERTAINTY_ORDER, Context, assess
from netsentinel.inference.schema import AssessmentOut, Prediction, ServiceOut
from netsentinel.storage.events import EventStore
from netsentinel.streaming.offline import parse_health

H = 3_600_000
READY = dict(has_profile=True, has_model=True, profile_status="baseline_ready",
             threshold_reliable=True, calibration_end_ms=0, telemetry_health="ok")  # fmt: skip


def _state(ctx_kw=None, verdict="benign", ts="no_evidence", beh="normal", base="consistent",
           t=H):  # fmt: skip
    return assess(Context(**{**READY, **(ctx_kw or {})}), verdict, ts, beh, base, t)


def test_normal_only_under_valid_fresh_baseline_and_healthy_telemetry():
    a = _state()
    assert a["state"] == "normal_valid_baseline" and a["normality_supported"]
    assert not a["evidence_present"] and a["qualifiers"] == [] and a["reasons"] == []


@pytest.mark.parametrize("kw,expected", [
    (dict(ctx_kw={"has_profile": False, "has_model": False}), "model_unavailable"),
    (dict(ctx_kw={"telemetry_health": "clock_anomaly"}), "telemetry_degraded"),
    (dict(ctx_kw={"has_profile": False}), "insufficient_calibration"),
    (dict(beh="insufficient_history"), "insufficient_calibration"),
    (dict(ctx_kw={"profile_status": "baseline_provisional"}), "insufficient_calibration"),
    (dict(ctx_kw={"threshold_reliable": False}), "insufficient_calibration"),
    (dict(ctx_kw={"tail_dominated": True}), "insufficient_calibration"),
    (dict(t=25 * H), "calibration_expired"),
    (dict(base="drift_suspected"), "drift_detected"),
    (dict(base="stale"), "drift_detected"),
    (dict(ctx_kw={"threat_mode": "unsupported_domain"}), "unsupported_network"),
    (dict(verdict="unusual", beh="anomalous"), "anomalous_behavior"),
    (dict(verdict="suspicious", ts="suspicious"), "suspicious_evidence"),
    (dict(verdict="attack", ts="known_attack_category"), "suspicious_evidence"),
])  # fmt: skip
def test_each_state_is_reachable(kw, expected):
    a = _state(**kw)
    assert a["state"] == expected
    assert a["normality_supported"] is False
    AssessmentOut(**a)  # schema accepts every state


def test_all_states_are_covered_by_the_schema_and_order():
    assert set(UNCERTAINTY_ORDER) | {"suspicious_evidence", "anomalous_behavior",
                                     "normal_valid_baseline"} == set(STATES)  # fmt: skip


@pytest.mark.parametrize("ctx_kw,base,t", [
    ({"telemetry_health": "integrity_degraded"}, "consistent", H),
    ({}, "drift_suspected", H),
    ({}, "consistent", 100 * H),
    ({"tail_dominated": True, "threat_mode": "unsupported_domain"}, "stale", 100 * H),
])  # fmt: skip
def test_evidence_is_never_silenced_by_uncertainty(ctx_kw, base, t):
    a = _state(ctx_kw, verdict="unusual", beh="anomalous", base=base, t=t)
    assert a["state"] == "anomalous_behavior" and a["evidence_present"]
    assert a["qualifiers"] and not a["normality_supported"]
    assert len(a["reasons"]) == len(a["qualifiers"])


def test_no_condition_is_hidden_by_precedence():
    a = _state({"telemetry_health": "clock_reset", "has_profile": False}, base="stale", t=99 * H)
    assert a["state"] == "telemetry_degraded"
    assert a["qualifiers"] == ["insufficient_calibration", "calibration_expired",
                               "drift_detected"]  # fmt: skip


def test_parse_health_ignores_benign_skips():
    assert parse_health({"packets": 100, "skipped": {"not_ip": 60}}) == "ok"
    assert parse_health({"packets": 100, "skipped": {"short_tcp": 2}}) == "parse_errors"
    assert parse_health({"lines": 1000, "skipped": {"field_count": 10}}) == "ok"  # exactly 1%
    assert parse_health({"lines": 0, "skipped": {}}) == "ok"


OLD_SCHEMA = """CREATE TABLE events (observation_id TEXT PRIMARY KEY, ts TEXT NOT NULL,
source TEXT NOT NULL, verdict TEXT NOT NULL, service TEXT, anomaly_score REAL,
p_malicious REAL, attack_category TEXT, bundle TEXT, payload TEXT NOT NULL,
threat_status TEXT, behavior_status TEXT, behavior_score REAL, app_protocol TEXT,
app_status TEXT);
INSERT INTO events VALUES ('old1', '2026-01-01T00:00:00', 'pcap:old', 'benign', 'web', 1.0,
NULL, NULL, 'b', '{"observation_id": "old1"}', NULL, NULL, NULL, NULL, NULL);"""


def test_event_store_migrates_pre_8e_databases_and_filters_by_state(tmp_path):
    db = tmp_path / "old.sqlite"
    with sqlite3.connect(db) as c:
        c.executescript(OLD_SCHEMA)
    store = EventStore(db)  # opening adds the Phase 8e column; old rows are kept
    from datetime import datetime

    p = Prediction(observation_id="new1", timestamp=datetime(2026, 1, 2), source="pcap:new",
                   verdict="benign", service=ServiceOut(category="web"), anomaly=None, threat=None,
                   evidence=[], missing_features=[], model_versions={},
                   assessment=AssessmentOut(state="drift_detected", normality_supported=False,
                                            evidence_present=False))  # fmt: skip
    store.add([p])
    s = store.summary()
    assert s["counts"]["benign"] == 2
    assert s["assessment_states"] == {"not_recorded": 1, "drift_detected": 1}
    got = store.query(states=["drift_detected"])
    assert [e["observation_id"] for e in got] == ["new1"]
    assert got[0]["assessment"]["normality_supported"] is False
    assert len(store.query()) == 2
    with pytest.raises(ValueError):
        store.query(states=["fine"])
    store.close()
