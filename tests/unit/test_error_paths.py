"""Error and edge paths of the Phase 6 CLI / behaviour code (synthetic inputs)."""

import polars as pl

from netsentinel.behavior.windows import aggregate, prepare_flows
from netsentinel.cli import main
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log
from tests.unit.test_behavior import synth

HEAD = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tduration\torig_ip_bytes\tresp_ip_bytes\torig_pkts\tresp_pkts\thistory\n")  # fmt: skip


def test_out_of_order_flows_give_identical_windows():
    df = synth(30, seed=21)
    a = aggregate(prepare_flows(df), "device", 30)
    b = aggregate(prepare_flows(df.sample(fraction=1.0, shuffle=True, seed=1)), "device", 30)
    cols = ["key", "win", "n_flows", "log_up_bytes", "log_dst_hosts", "new_dst_frac"]
    assert a.sort("key", "win").select(cols).equals(b.sort("key", "win").select(cols))


def test_invalid_timestamps_are_skipped_and_counted(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(HEAD + "abc\tC1\t10.0.0.1\t1\t1.2.3.4\t80\ttcp\t0.1\t1\t1\t1\t1\tS\n"
                 "5.0\tC2\t10.0.0.1\t1\t1.2.3.4\t80\ttcp\t0.1\t1\t1\t1\t1\tS\n")  # fmt: skip
    st = ZeekStats()
    assert len(list(read_conn_log(p, st))) == 1 and st.skipped == {"unparseable": 1}


def test_cli_refuses_missing_empty_and_unknown_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["calibrate", "nope.log", "--out", "cal"]) == 2  # missing capture
    (tmp_path / "empty.log").write_text(HEAD)
    assert main(["calibrate", "empty.log", "--out", "cal"]) == 2  # no flows
    assert main(["calibrate", "empty.log", "--mode", "vetted_benign", "--out", "cal"]) == 2
    assert not (tmp_path / "cal").exists() or not any((tmp_path / "cal").iterdir())


def test_profile_rejects_frames_without_endpoints():
    bad = synth(5, seed=2).drop("ipv4_src_addr")
    try:
        prepare_flows(bad)
    except ValueError as exc:
        assert "ipv4_src_addr" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("missing column accepted")
    assert isinstance(prepare_flows(synth(2, seed=3)), pl.DataFrame)


def test_period_filter_keeps_flows_by_end_time(tmp_path):
    from datetime import datetime

    from netsentinel.streaming.offline import load_capture

    p = tmp_path / "conn.log"
    rows = "".join(f"{t}.0\tC{t}\t10.0.0.1\t1\t1.2.3.4\t80\ttcp\t1.0\t1\t1\t1\t1\tS\n"
                   for t in (10, 20, 30))  # fmt: skip
    p.write_text(HEAD + rows)
    f, _, parse = load_capture(p, "zeek", since=datetime(1970, 1, 1, 0, 0, 21),
                               until=datetime(1970, 1, 1, 0, 0, 31))  # fmt: skip
    assert f.height == 1 and parse["time_filter"]["flows_kept"] == 1  # ends at 21 s and 31 s
    f2, _, _ = load_capture(p, "zeek", until=datetime(1970, 1, 1, 0, 0, 5))
    assert f2 is None
