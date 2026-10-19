"""Shared fixtures. Everything here is SYNTHETIC test data, never a stand-in for real results."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from netsentinel.data.ids2018 import RAW_COLUMNS


def write_synthetic_ids2018_csv(
    path: Path,
    rows: list[dict[str, object]],
    repeat_header_after: int | None = None,
    extra_identifiers: bool = False,
) -> Path:
    """Write a CICFlowMeter-V3-shaped CSV. Unspecified numeric cells default to 0."""
    header = list(RAW_COLUMNS)
    if extra_identifiers:
        header = ["Flow ID", "Src IP", "Src Port", "Dst IP", *header]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for i, row in enumerate(rows):
            if repeat_header_after is not None and i == repeat_header_after:
                writer.writerow(header)
            writer.writerow([row.get(col, 0) for col in header])
    return path


@pytest.fixture
def synthetic_rows() -> list[dict[str, object]]:
    base = {"Protocol": 6, "Flow Duration": 1000, "Tot Fwd Pkts": 2, "Tot Bwd Pkts": 1}
    return [
        {**base, "Dst Port": 443, "Timestamp": "14/02/2018 08:31:01", "Label": "Benign"},
        {**base, "Dst Port": 21, "Timestamp": "14/02/2018 10:32:05", "Label": "FTP-BruteForce",
         "Flow Byts/s": "Infinity", "Flow Pkts/s": "NaN"},
        {**base, "Dst Port": 22, "Timestamp": "14/02/2018 14:01:09", "Label": "SSH-Bruteforce"},
        {**base, "Dst Port": 53, "Protocol": 17, "Timestamp": "14/02/2018 15:00:00",
         "Label": "Benign", "Init Fwd Win Byts": -1},
    ]  # fmt: skip
