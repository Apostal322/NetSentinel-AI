"""`netsentinel demo` end to end (synthetic fixtures; checks software behaviour only)."""

import json
import sqlite3

from netsentinel.cli import main
from netsentinel.demo.runner import run_demo


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


def test_demo_cli_refuses_non_empty_workspace(tmp_path):
    (tmp_path / "x").write_text("keep me")
    assert main(["demo", "--workspace", str(tmp_path), "--quiet"]) == 2
    assert (tmp_path / "x").read_text() == "keep me"
