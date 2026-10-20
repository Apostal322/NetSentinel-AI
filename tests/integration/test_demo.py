"""`netsentinel demo` end to end (synthetic fixtures; checks software behaviour only)."""

import json
import sqlite3
from collections import Counter
from pathlib import Path

from netsentinel.cli import main
from netsentinel.demo.fixtures import DEMO_T0
from netsentinel.demo.runner import run_demo
from netsentinel.inference.pipeline import AnalysisPipeline
from netsentinel.storage.events import EventStore
from netsentinel.streaming.live import END, START, StreamMonitor
from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.pcap import read_packets


def test_demo_runs_offline_and_separates_injected_traffic(tmp_path):
    res = run_demo(tmp_path / "ws", quiet=True)
    assert res["threat_mode"] == "unverified_domain"  # safe default, no attack verdicts
    assert "suspicious" not in res["verdicts"] and "attack" not in res["verdicts"]
    assert res["flows"] == 3600 and res["behavior_windows"]["device"]["anomalous"] >= 5
    rows = [json.loads(p) for (p,) in sqlite3.connect(res["events_db"]).execute(
        "SELECT payload FROM events")]  # fmt: skip
    injected = [r for r in rows if r["application"]["app_status"] != "predicted"]
    benign = [r for r in rows if r["application"]["app_status"] == "predicted"]
    # the SSH brute force + port scan (2400 flows) use protocols unknown to the demo classifier
    assert len(injected) == 2400 and len(benign) == 1200
    assert sum(r["verdict"] == "unusual" for r in injected) / len(injected) >= 0.95
    assert sum(r["verdict"] == "unusual" for r in benign) / len(benign) <= 0.05
    assert {r["application"]["app_protocol"] for r in benign} <= {"tls", "dns"}
    assert all(r["application"]["application_identity"] is None for r in rows)
    # incidents: each attacker is exactly one device incident (Phase 8C)
    con = sqlite3.connect(res["events_db"])
    dev = [e for (e,) in con.execute("SELECT entity FROM incidents WHERE level = 'device'")]
    assert dev.count("10.9.9.9") == 1 and dev.count("10.9.9.8") == 1
    assert res["incidents"]["count"] == con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    # streaming the same capture (Phase 8E) reproduces verdicts and incidents
    pcap = Path(res["workspace"]) / "fixtures" / "demo.pcap"
    cut = int((DEMO_T0 + 15 * 60) * 1000)
    recs = sorted((r for r in assemble_flows(read_packets(pcap)) if r[END] >= cut),
                  key=lambda r: r[START])  # fmt: skip
    store = EventStore(Path(res["workspace"]) / "stream.sqlite")
    pipe = AnalysisPipeline(res["bundle"], res["calibration"], res["classifier"])
    mon = StreamMonitor(pipe, store, source=rows[0]["source"], batch_flows=400)
    mon.feed(recs)
    out = mon.close()
    assert out.flows == 3600 and out.stats["late"] == 0
    assert dict(Counter(r["verdict"] for r in rows)) == out.verdicts
    offline_ids = sorted(i for (i,) in con.execute("SELECT incident_id FROM incidents"))
    stream_ids = sorted(i for (i,) in store._conn.execute("SELECT incident_id FROM incidents"))
    assert offline_ids == stream_ids


def test_demo_cli_refuses_non_empty_workspace(tmp_path):
    (tmp_path / "x").write_text("keep me")
    assert main(["demo", "--workspace", str(tmp_path), "--quiet"]) == 2
    assert (tmp_path / "x").read_text() == "keep me"
