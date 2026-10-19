"""Checks against the REAL ingested dataset. Skipped unless the data exists; run with
`uv run pytest -m data`."""

import json
from pathlib import Path

import pytest

from netsentinel.features.schema import CONSTANT_COLUMNS

EDA = Path("reports/eda/eda.json")
pytestmark = [
    pytest.mark.data,
    pytest.mark.skipif(not EDA.exists(), reason="run `netsentinel data eda` first"),
]


def test_schema_constant_columns_match_eda():
    eda = json.loads(EDA.read_text("utf-8"))
    assert set(CONSTANT_COLUMNS) == set(eda["constant_columns"])
