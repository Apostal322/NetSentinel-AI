"""`netsentinel monitor` (Phase 8E): local Zeek conn.log, behaviour-only and follow mode."""

import json
import sqlite3
import threading
import time

from netsentinel.cli import main
from netsentinel.streaming.live import follow_lines
from tests.integration.test_offline_app import zeek_long


def test_monitor_reads_log_and_stores_incidents(tmp_path, capsys):
    cal_log = zeek_long(tmp_path / "cal.log", hours=2.0, seed=1)
    mon_log = zeek_long(tmp_path / "mon.log", hours=1.0, seed=2, start=1_600_007_200,
                        scan_at=1800)  # fmt: skip
    root = tmp_path / "cals"
    assert main(["calibrate", str(cal_log), "--out", str(root), "--mode", "vetted_benign",
                 "--assert-benign", "--window", "30"]) == 0  # fmt: skip
    cal = next(root.glob("calibration-*"))
    capsys.readouterr()
    # the fixture appends the scan records AFTER an hour of benign records: with the default
    # 60 s lateness they are late, counted and dropped (never merged into closed windows)
    assert main(["monitor", "--zeek-log", str(mon_log), "--calibration", str(cal),
                 "--events-db", str(tmp_path / "a.sqlite")]) == 0  # fmt: skip
    out = json.loads(capsys.readouterr().out)
    assert out["stats"]["late"] == 800 and out["flows"] + 800 == out["parse"]["records"]
    db = tmp_path / "ev.sqlite"
    assert main(["monitor", "--zeek-log", str(mon_log), "--calibration", str(cal),
                 "--events-db", str(db), "--lateness", "7200"]) == 0  # fmt: skip
    out = json.loads(capsys.readouterr().out)
    assert out["flows"] == out["parse"]["records"] > 1000 and out["stats"]["late"] == 0
    con = sqlite3.connect(db)
    ents = [e for (e,) in con.execute("SELECT entity FROM incidents WHERE level = 'device'")]
    assert "10.0.0.1" in ents  # the scanning host


def test_monitor_requires_calibration_and_existing_log(tmp_path):
    assert main(["monitor", "--zeek-log", str(tmp_path / "missing.log"),
                 "--calibration", str(tmp_path)]) == 2  # fmt: skip


def test_follow_lines_sees_appended_data(tmp_path):
    p = tmp_path / "grow.log"
    p.write_text("a\n", encoding="utf-8")
    got = []

    def writer():
        time.sleep(0.3)
        with p.open("a", encoding="utf-8") as fh:
            fh.write("b\nc")
            fh.flush()
            time.sleep(0.3)
            fh.write("\n")

    t = threading.Thread(target=writer)
    t.start()
    for line in follow_lines(p, poll_s=0.05, idle_timeout_s=1.0):
        got.append(line.strip())
    t.join()
    assert got == ["a", "b", "c"]
