"""Phase 8f calibration validity in the product: new calibrations carry a validity reference
and lineage; `analyze` / `monitor --validity-shadow` report the shift test as a labelled,
non-adopted diagnostic that changes nothing else; behavior-1.1.0 calibrations still load."""

import json
import shutil

import joblib

from netsentinel.behavior.calibrate import load_profile
from netsentinel.cli import main
from tests.integration.test_offline_app import zeek_long


def _calibrate(tmp_path, capsys, previous=None):
    cal_log = zeek_long(tmp_path / "cal.log", hours=2.0, seed=1)
    args = ["calibrate", str(cal_log), "--out", str(tmp_path / "cals"), "--mode",
            "vetted_benign", "--assert-benign"]  # fmt: skip
    if previous:
        args += ["--previous", previous]
    assert main(args) == 0
    capsys.readouterr()
    return sorted((tmp_path / "cals").glob("calibration-*"))[-1]


def test_new_calibrations_store_a_validity_reference_and_lineage(tmp_path, capsys):
    cal = _calibrate(tmp_path, capsys)
    prof, mf = load_profile(cal)
    assert mf["schema_version"] == "behavior-1.2.0"
    blocks = mf["validity_reference"]["levels"]
    assert blocks["global"] >= 10 and prof.levels["global"].validity_ref is not None
    child = _calibrate(tmp_path, capsys, previous=str(cal))
    assert json.loads((child / "manifest.json").read_text())["parent_calibration"] == cal.name
    assert main(["calibration", "list", "--root", str(tmp_path / "cals")]) == 0
    rows = json.loads(capsys.readouterr().out)["calibrations"]
    assert {r["parent"] for r in rows} == {None, cal.name}
    assert all("device_threshold_reliable" in r and r["validity_reference_blocks"] for r in rows)


def test_monitor_validity_shadow_is_reported_but_changes_nothing(tmp_path, capsys):
    cal = _calibrate(tmp_path, capsys)
    mon_log = zeek_long(tmp_path / "mon.log", hours=1.0, seed=2, start=1_600_007_200,
                        scan_at=1800)  # fmt: skip
    base = ["monitor", "--zeek-log", str(mon_log), "--calibration", str(cal), "--lateness", "7200"]
    assert main([*base, "--events-db", str(tmp_path / "a.sqlite")]) == 0
    plain = json.loads(capsys.readouterr().out)
    assert plain["calibration_validity_shadow"] is None
    assert main([*base, "--events-db", str(tmp_path / "b.sqlite"), "--validity-shadow"]) == 0
    shadow = json.loads(capsys.readouterr().out)
    v = shadow["calibration_validity_shadow"]
    assert v["adopted"] is False and "shadow evaluation only" in v["note"]
    assert v["status"] in ("valid", "possible_shift", "confirmed_shift", "unreliable_threshold")
    assert v["levels"]["global"]["blocks_scored"] >= 10
    for k in ("flows", "anomalous_windows", "incidents", "assessment"):
        assert shadow[k] == plain[k]  # the diagnostic never changes detection output


def test_old_schema_calibrations_load_with_an_untestable_shift_test(tmp_path, capsys):
    cal = _calibrate(tmp_path, capsys)
    old = tmp_path / "old" / cal.name
    shutil.copytree(cal, old)
    prof = joblib.load(old / "profile.joblib")
    for lp in prof.levels.values():
        del lp.__dict__["validity_ref"]  # a pre-8f pickle has no such attribute
    joblib.dump(prof, old / "profile.joblib", compress=3)
    mf = json.loads((old / "manifest.json").read_text())
    from netsentinel.ledger import file_sha256

    mf["schema_version"] = "behavior-1.1.0"
    mf["sha256"]["profile.joblib"] = file_sha256(old / "profile.joblib")
    (old / "manifest.json").write_text(json.dumps(mf))
    mon_log = zeek_long(tmp_path / "mon.log", hours=1.0, seed=2, start=1_600_007_200)
    from netsentinel.behavior import validity

    p, _ = load_profile(old)
    v = validity.shadow(p, {})
    assert v["shift_test"] == "untestable" and v["adopted"] is False
    from netsentinel.telemetry.frames import records_to_frame
    from netsentinel.telemetry.zeek import read_conn_log

    frame = records_to_frame(list(read_conn_log(mon_log)))
    blocks = validity.frame_blocks(p, frame)
    assert validity.shadow(p, blocks)["shift_test"] == "untestable"
