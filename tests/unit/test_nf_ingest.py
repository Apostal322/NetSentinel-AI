"""NetFlow v3 ingestion on a SYNTHETIC BagIt zip."""

import hashlib
import zipfile

import polars as pl
import pytest

from netsentinel.data.nf_v3 import ingest_nf_zip, local_time

HEADER = (
    "FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,"
    "L4_DST_PORT,PROTOCOL,L7_PROTO,IN_BYTES,IN_PKTS,OUT_BYTES,OUT_PKTS,TCP_FLAGS,CLIENT_TCP_FLAGS,"
    "SERVER_TCP_FLAGS,FLOW_DURATION_MILLISECONDS,MIN_TTL,Label,Attack"
)
ROWS = [
    # 2018-02-14 12:28:07.705 UTC = 08:28:07 local (UTC-4)
    "1518611287705,1518611287905,172.31.0.2,53,172.31.66.58,63593,17,5,156,1,0,0,0,0,0,200,64,0,Benign",
    # 18:01:00 UTC = 14:01 local, SSH brute force
    "1518631260000,1518631261000,18.221.219.4,40000,172.31.69.25,22,6,92,3000,20,1000,10,27,"
    "2,25,1000,64,1,SSH-Bruteforce",
    # 03:30 UTC on 02-15 = 23:30 local on 02-14 (day boundary uses local date)
    "1518665400000,1518665400010,10.0.0.1,1,10.0.0.2,80,6,7,100,1,100,1,2,2,0,10,64,1,"
    "DoS attacks-Hulk",
]


def _bag(tmp_path, rows=ROWS, corrupt=False):
    csv = (HEADER + "\n" + "\n".join(rows) + "\n").encode()
    digest = hashlib.sha1(csv).hexdigest()
    path = tmp_path / "nf.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("bag/data/NF-test.csv", csv + (b"x" if corrupt else b""))
        z.writestr("bag/data/NetFlow_v3_Features.csv", "Feature,Description\n")
        z.writestr("bag/manifest-sha1.txt", f"{digest} data/NF-test.csv\n")
    return path


def test_ingest_local_days_aliases_and_labels(tmp_path):
    fmap = {"ssh_bruteforce": "bruteforce", "dos_attacks_hulk": "dos"}
    rep = ingest_nf_zip(_bag(tmp_path), tmp_path / "out", utc_offset_hours=-4, family_map=fmap)
    assert rep.sha1_ok and rep.rows_written == 3
    assert rep.days == {"2018-02-14": 3}
    df = pl.read_parquet(tmp_path / "out/2018-02-14.parquet")
    assert df["timestamp"][0].strftime("%H:%M:%S") == "08:28:07"
    assert df["timestamp"][1].strftime("%H:%M") == "14:01"
    assert df["label"].to_list() == ["benign", "ssh_bruteforce", "dos_attacks_hulk"]
    assert df["family"].to_list() == ["benign", "bruteforce", "dos"]
    assert df["flow_duration"].to_list() == [200_000, 1_000_000, 10_000]  # microseconds
    assert df["dst_port"].to_list() == [63593, 22, 80]
    assert df["syn_flag_cnt"].to_list() == [0.0, 1.0, 1.0]
    assert df["srv_ack"].to_list() == [0, 1, 0]
    assert df["row_id"].to_list() == [0, 1, 2]


def test_ingest_rejects_corrupted_member(tmp_path):
    with pytest.raises(ValueError, match="SHA-1"):
        ingest_nf_zip(_bag(tmp_path, corrupt=True), tmp_path / "out", utc_offset_hours=0)


def test_local_time_helper():
    assert local_time(1518611287705, -4).strftime("%Y-%m-%d %H:%M") == "2018-02-14 08:28"
