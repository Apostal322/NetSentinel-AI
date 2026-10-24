"""Dashboard smoke test (Streamlit AppTest) on a small synthetic event store: every page renders
without an exception and shows the stored counts. Needs the `dashboard` extra."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from netsentinel.inference.schema import (  # noqa: E402
    AnomalyOut,
    ApplicationOut,
    AssessmentOut,
    BehaviorOut,
    Prediction,
    ServiceOut,
)
from netsentinel.storage.events import EventStore  # noqa: E402

APP = str(Path(__file__).resolve().parents[2] / "dashboard" / "app.py")
PAGES = ["Live traffic", "Behavior intelligence", "Application intelligence",
         "Incident explorer", "Traffic explorer", "Anomalies", "Threats", "Model management",
         "Research & diagnostics"]  # fmt: skip


def _pred(i: int, verdict: str) -> Prediction:
    ts = datetime(2026, 1, 1, 12, 0, 0) + timedelta(seconds=7 * i, microseconds=1000 * (i % 2))
    return Prediction(
        observation_id=f"obs{i}", timestamp=ts, source="pcap:demo.pcap", verdict=verdict,
        service=ServiceOut(category="web"),
        anomaly=AnomalyOut(score=50.0, threshold=97.5, is_anomalous=False, context="__global__"),
        threat=None, evidence=[], missing_features=[], model_versions={"bundle": "b-test"},
        application=ApplicationOut(transport="tcp", app_protocol="tls", app_status="predicted",
                                   app_method="ml_port_agree", service_category="web"),
        behavior=BehaviorOut(behavior_status="anomalous" if verdict == "unusual" else "normal",
                             anomaly_score=99.0, baseline_status="baseline_ready",
                             calibration="calibration-test"),
        threat_status="unverified_domain",
        assessment=AssessmentOut(
            state="anomalous_behavior" if verdict == "unusual" else "insufficient_calibration",
            normality_supported=False, evidence_present=verdict == "unusual"),
    )  # fmt: skip


def test_all_pages_render(tmp_path, monkeypatch):
    db = tmp_path / "events.sqlite"
    store = EventStore(db)
    store.add([_pred(i, "unusual" if i % 10 == 0 else "benign") for i in range(60)])
    import polars as pl

    store.add_behavior(pl.DataFrame({
        "level": ["global", "device"], "key": ["*", "10.0.0.1"], "win": [1, 1],
        "window_end_ms": [1_767_268_830_000] * 2, "n_flows": [5, 3], "score": [2.0, 9.0],
        "severity": [40.0, 99.0], "threshold": [5.0, 5.0], "anomalous": [False, True],
        "model_scope": ["global", "10.0.0.1"], "explanation": [[], ["connection_rate_above"]],
    }), "pcap:demo.pcap", "calibration-test", 30)  # fmt: skip
    from netsentinel.incidents import aggregate_incidents

    w = {"level": "device", "key": "10.0.0.1", "win": 1, "window_start_ms": 1_767_268_800_000,
         "window_end_ms": 1_767_268_830_000, "score": 9.0, "threshold": 5.0, "anomalous": True,
         "n_flows": 3, "explanation": ["connection_rate_above_local_baseline"]}  # fmt: skip
    store.upsert_incidents(aggregate_incidents([w], [], "calibration-test", "pcap:demo.pcap", 30))
    store.close()
    monkeypatch.setenv("NETSENTINEL_EVENTS_DB", str(db))
    monkeypatch.setenv("NETSENTINEL_MODELS_DIR", str(tmp_path / "models"))
    for page in PAGES:
        at = AppTest.from_file(APP, default_timeout=60).run()
        assert not at.exception, at.exception
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, (page, at.exception)
        if page == "Incident explorer":
            assert at.dataframe and "10.0.0.1" in at.dataframe[0].value["entity"].tolist()
        if page == "Live traffic":
            values = {m.label: m.value for m in at.metric}
            assert values["unusual"] == "6" and values["benign"] == "54"
            # Phase 8e: quiet flows without a valid baseline are flagged, not shown as normal
            assert any("No alert does not mean normal" in w.value for w in at.warning)
