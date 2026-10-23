"""ToN_IoT CSV adapter (scripts/phase8c/toniot.py) on SYNTHETIC rows only (the real data is a
protected confirmatory set and has not been downloaded)."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("toniot", ROOT / "scripts/phase8c/toniot.py")
toniot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toniot)

COLUMNS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "duration",
           "src_bytes", "dst_bytes", "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes",
           "dst_pkts", "dst_ip_bytes", "label", "type"]  # fmt: skip
HEADER = ",".join(COLUMNS)


def test_maps_fields_and_reset_semantics(tmp_path):
    p = tmp_path / "Network_dataset_1.csv"
    p.write_text(HEADER + "\n"
                 "1554198358.5,192.168.1.37,4444,192.168.1.193,49178,tcp,-,290.3,101568,"
                 "2592,OTH,0,108,108064,31,3832,0,normal\n"
                 "1554198359,192.168.159.31,51000,192.168.1.5,22,tcp,-,0,0,0,REJ,0,1,60,1,40,1,"
                 "scanning\n"
                 "1554198360,10.0.0.1,5353,224.0.0.251,5353,udp,dns,-,30,0,S0,0,1,58,0,0,0,normal\n"
                 "bad,row\n", encoding="utf-8")  # fmt: skip
    stats = {}
    r = list(toniot.records([p], stats))
    assert stats == {"rows": 4, "skipped": 1} and len(r) == 3
    a, b, c = r
    assert (
        a["FLOW_START_MILLISECONDS"] == 1554198358500 and a["FLOW_DURATION_MILLISECONDS"] == 290300
    )
    assert a["FLOW_END_MILLISECONDS"] == 1554198358500 + 290300
    assert (a["IN_BYTES"], a["OUT_BYTES"], a["IN_PKTS"], a["OUT_PKTS"]) == (108064, 3832, 108, 31)
    assert a["IS_ATTACK"] == 0.0 and b["IS_ATTACK"] == 1.0
    assert b["SERVER_TCP_FLAGS"] == 4 and b["CLIENT_TCP_FLAGS"] == 0  # REJ = responder reset
    assert c["PROTOCOL"] == 17 and c["FLOW_DURATION_MILLISECONDS"] == 0 and c["TCP_FLAGS"] == 0


def test_records_feed_the_standard_window_pipeline(tmp_path):
    from netsentinel.behavior.windows import aggregate, prepare_flows
    from netsentinel.telemetry.frames import records_to_frame

    p = tmp_path / "Network_dataset_1.csv"
    rows = [f"{1554198000 + i},192.168.1.{i % 3},4000,192.168.1.200,80,tcp,http,0.5,10,20,SF,0,"
            f"3,200,3,400,0,normal" for i in range(120)]  # fmt: skip
    p.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    flows = prepare_flows(records_to_frame(list(toniot.records([p]))))
    w = aggregate(flows, "device", 30)
    assert set(w["key"].unique().to_list()) == {"192.168.1.0", "192.168.1.1", "192.168.1.2"}
    assert flows["is_attack"].sum() == 0
