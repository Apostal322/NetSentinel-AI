import math

import polars as pl
import pytest

from netsentinel.data.ids2018 import canonical, ingest_csv
from tests.conftest import write_synthetic_ids2018_csv


def test_canonical_names():
    assert canonical("Flow Byts/s") == "flow_byts_per_s"
    assert canonical("Down/Up Ratio") == "down_per_up_ratio"
    assert canonical("CWE Flag Count") == "cwe_flag_count"


def test_ingest_drops_repeated_headers_and_maps_labels(tmp_path, synthetic_rows):
    src = write_synthetic_ids2018_csv(tmp_path / "day.csv", synthetic_rows, repeat_header_after=2)
    report = ingest_csv(src, tmp_path / "out.parquet", day="2018-02-14")

    assert report.rows_written == 4
    assert report.repeated_header_rows == 1
    assert report.label_counts == {"benign": 2, "ftp_bruteforce": 1, "ssh_bruteforce": 1}
    df = pl.read_parquet(tmp_path / "out.parquet")
    assert df["row_id"].to_list() == [0, 1, 2, 3]
    assert df["family"].to_list() == ["benign", "bruteforce", "bruteforce", "benign"]
    assert df["timestamp"].dtype == pl.Datetime("us")
    assert df["dst_port"].dtype == pl.Int64
    assert df["src_ip"].null_count() == 4  # identifier columns exist but are empty here


def test_ingest_streams_in_blocks_with_continuous_row_ids(tmp_path, synthetic_rows):
    rows = synthetic_rows * 200  # 800 rows, ~150 kB -> many 4 kB blocks
    src = write_synthetic_ids2018_csv(tmp_path / "d.csv", rows, repeat_header_after=500)
    report = ingest_csv(src, tmp_path / "o.parquet", "2018-02-14", block_bytes=4096)
    df = pl.read_parquet(report.output)
    assert report.rows_written == 800
    assert report.repeated_header_rows == 1
    assert df["row_id"].to_list() == list(range(800))
    assert not (tmp_path / "o.parquet.partial").exists()


def test_ingest_keeps_inf_and_nan_explicit(tmp_path, synthetic_rows):
    src = write_synthetic_ids2018_csv(tmp_path / "day.csv", synthetic_rows)
    df = pl.read_parquet(ingest_csv(src, tmp_path / "o.parquet", "2018-02-14").output)
    assert math.isinf(df["flow_byts_per_s"][1])
    assert math.isnan(df["flow_pkts_per_s"][1])
    assert df["init_fwd_win_byts"][3] == -1


def test_ingest_corrects_12h_clock_and_drops_invalid_dates(tmp_path, synthetic_rows):
    rows = [
        {**synthetic_rows[0], "Timestamp": "14/02/2018 02:01:09"},  # afternoon -> 14:01:09
        {**synthetic_rows[0], "Timestamp": "14/02/2018 10:33:26"},  # morning, unchanged
        {**synthetic_rows[0], "Timestamp": "14/02/2018 12:15:00"},  # noon hour, unchanged
        {**synthetic_rows[0], "Timestamp": "05/01/1970 03:01:17"},  # invalid -> dropped
    ]
    src = write_synthetic_ids2018_csv(tmp_path / "d.csv", rows)
    report = ingest_csv(src, tmp_path / "o.parquet", "2018-02-14")
    df = pl.read_parquet(report.output)
    assert [t.strftime("%H:%M:%S") for t in df["timestamp"]] == ["14:01:09", "10:33:26",
                                                                  "12:15:00"]  # fmt: skip
    assert df["clock_corrected"].to_list() == [True, False, False]
    assert df["row_id"].to_list() == [0, 1, 2]
    assert report.invalid_timestamp_rows == 1
    assert report.clock_corrected_rows == 1


def test_ingest_rejects_unknown_label(tmp_path, synthetic_rows):
    rows = [*synthetic_rows, {**synthetic_rows[0], "Label": "Port-Scan-Made-Up"}]
    src = write_synthetic_ids2018_csv(tmp_path / "day.csv", rows)
    with pytest.raises(ValueError, match="unknown labels"):
        ingest_csv(src, tmp_path / "o.parquet", "2018-02-14")


def test_ingest_rejects_malformed_numeric(tmp_path, synthetic_rows):
    rows = [*synthetic_rows, {**synthetic_rows[0], "Tot Fwd Pkts": "abc"}]
    src = write_synthetic_ids2018_csv(tmp_path / "day.csv", rows)
    with pytest.raises(Exception):  # noqa: B017 - polars raises InvalidOperationError/ComputeError
        ingest_csv(src, tmp_path / "o.parquet", "2018-02-14")


def test_ingest_rejects_missing_columns(tmp_path):
    (tmp_path / "bad.csv").write_text("Dst Port,Label\n80,Benign\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing columns"):
        ingest_csv(tmp_path / "bad.csv", tmp_path / "o.parquet", "2018-02-14")


def test_ingest_keeps_identifier_columns_when_present(tmp_path, synthetic_rows):
    rows = [{**r, "Src IP": "10.0.0.1", "Dst IP": "10.0.0.2"} for r in synthetic_rows]
    src = write_synthetic_ids2018_csv(tmp_path / "d.csv", rows, extra_identifiers=True)
    report = ingest_csv(src, tmp_path / "o.parquet", "2018-02-14")
    assert report.has_identifiers
    assert pl.read_parquet(report.output)["src_ip"].to_list() == ["10.0.0.1"] * 4
