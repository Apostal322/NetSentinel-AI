"""Phase 8C incident aggregation: grouping, stable IDs, severity, lifecycle in the store."""

from datetime import UTC, datetime

import pytest

from netsentinel.incidents import IncidentTracker, aggregate_incidents
from netsentinel.inference.schema import BehaviorOut, Prediction, ServiceOut
from netsentinel.storage.events import EventStore

W = 30_000


def win(key, i, score=2.0, thr=1.0, level="device", anomalous=True, n=5):
    return {"level": level, "key": key, "win": i, "window_start_ms": i * W,
            "window_end_ms": (i + 1) * W, "score": score, "threshold": thr,
            "anomalous": anomalous, "n_flows": n,
            "explanation": ["connection_rate_above"]}  # fmt: skip


def pred(oid, key, i, verdict="unusual"):
    end = datetime.fromtimestamp((i + 1) * W / 1000, UTC)
    return Prediction(
        observation_id=oid, timestamp=end, source="t", verdict=verdict,
        service=ServiceOut(category="web"), anomaly=None, threat=None, evidence=[],
        missing_features=[], model_versions={}, threat_status="unverified_domain",
        behavior=BehaviorOut(behavior_status="anomalous", baseline_status="baseline_ready",
                             level="device", entity=key, window_end=end))  # fmt: skip


def test_grouping_by_entity_and_gap():
    ws = [win("a", 0), win("a", 1), win("a", 3), win("a", 30),  # gap 26 windows > 300 s
          win("b", 1), win("a", 2, anomalous=False)]  # fmt: skip
    incs = aggregate_incidents(ws, [], "cal1", "t", 30, gap_s=300)
    got = sorted((i.entity, i.n_windows, i.first_window_start_ms) for i in incs)
    assert got == [("a", 1, 30 * W), ("a", 3, 0), ("b", 1, W)]


def test_ids_are_stable_and_input_order_independent():
    ws = [win("a", 0), win("a", 1), win("b", 4)]
    one = [i.incident_id for i in aggregate_incidents(ws, [], "cal1", "t", 30)]
    two = [i.incident_id for i in aggregate_incidents(ws[::-1], [], "cal1", "t", 30)]
    assert one == two and len(set(one)) == 2
    other_cal = [i.incident_id for i in aggregate_incidents(ws, [], "cal2", "t", 30)]
    assert not set(one) & set(other_cal)


def test_severity_and_auto_status():
    (weak,) = aggregate_incidents([win("a", 0, score=1.1)], [], "c", "t", 30)
    assert weak.severity == "low" and weak.status == "insufficient_evidence"
    (strong,) = aggregate_incidents([win("a", 0, score=3.5)], [], "c", "t", 30)
    assert strong.severity == "high" and strong.status == "new"
    (long,) = aggregate_incidents([win("a", i, score=1.3) for i in range(4)], [], "c", "t", 30)
    assert long.severity == "medium"
    (prov,) = aggregate_incidents([win("a", 0, score=5)], [], "c", "t", 30,
                                  baseline_status="baseline_provisional")  # fmt: skip
    assert prov.status == "insufficient_evidence"


def test_flows_attach_to_their_window_incident():
    t = IncidentTracker("c", "t", 30)
    t.add_windows([win("a", 0), win("a", 1), win("b", 0)])
    n = t.attach([pred("f1", "a", 0), pred("f2", "a", 1), pred("f3", "b", 0),
                  pred("f4", "c", 0)])  # fmt: skip
    assert n == 3
    a = next(i for i in t.incidents() if i.entity == "a").to_dict()
    assert a["n_flow_events"] == 2 and a["flow_evidence"] == ["f1", "f2"]
    assert a["threat_status_worst"] == "unverified_domain"


def test_store_lifecycle_preserved_and_reopened(tmp_path):
    st = EventStore(tmp_path / "e.sqlite")
    incs = aggregate_incidents([win("a", 0, score=3)], [], "c", "t", 30)
    st.upsert_incidents(incs)
    iid = incs[0].incident_id
    st.set_incident_status(iid, "resolved", note="false positive: backup job")
    st.upsert_incidents(incs)  # re-analysis of the same data: status kept
    assert st.get_incident(iid)["status"] == "resolved"
    more = aggregate_incidents([win("a", 0, score=3), win("a", 2, score=3)], [], "c", "t", 30)
    assert more[0].incident_id == iid
    st.upsert_incidents(more)  # new evidence for the same incident: re-opened
    d = st.get_incident(iid)
    assert d["status"] == "new" and d["n_windows"] == 2
    assert [h["to"] for h in d["status_history"]] == ["resolved", "new"]
    page, total = st.incidents(status=["new"], limit=1)
    assert total == 1 and page[0]["incident_id"] == iid
    with pytest.raises(ValueError):
        st.set_incident_status(iid, "closed")
    with pytest.raises(KeyError):
        st.set_incident_status("inc-missing", "resolved")


def test_store_pagination_and_filters(tmp_path):
    st = EventStore(tmp_path / "e.sqlite")
    ws = [win(f"h{k}", k * 20, score=1.1 + k) for k in range(7)]
    st.upsert_incidents(aggregate_incidents(ws, [], "c", "t", 30))
    p1, total = st.incidents(limit=3)
    p2, _ = st.incidents(limit=3, offset=3)
    p3, _ = st.incidents(limit=3, offset=6)
    ids = [d["incident_id"] for d in p1 + p2 + p3]
    assert total == 7 and len(set(ids)) == 7
    high, n_high = st.incidents(severity=["high"])
    assert n_high == sum(1.1 + k >= 3 for k in range(7)) and all(
        d["severity"] == "high" for d in high)  # fmt: skip
    assert st.incidents(entity="h3")[1] == 1
