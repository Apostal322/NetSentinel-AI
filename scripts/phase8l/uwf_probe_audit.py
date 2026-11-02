"""Phase 8l: composition of the F2 (UWF-ZeekData24) probe week, the only UWF file opened.

The probe week (2024-03-03 - 03-10 folder) was downloaded under authorization in Phase 8k and is
excluded from confirmation, so its full labels may be counted. No other UWF week and not the
`csv/Benign/` partition are read. Reports label counts, tactic counts, distinct sources and
destinations, and the time span.

Output: reports/phase8l/uwf_probe_audit.json
Usage: <python> -I scripts/phase8l/uwf_probe_audit.py
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
FILE = (ROOT / "data" / "raw" / "phase8k_probes" / "uwf"
        / "part-00000-0955ed97-8460-41bd-872a-7375a7f0207e-c000.snappy.parquet")  # fmt: skip
OUT = ROOT / "reports" / "phase8l" / "uwf_probe_audit.json"


def main() -> None:
    df = pl.read_parquet(FILE, columns=["label_binary", "label_tactic", "src_ip_zeek",
                                        "dest_ip_zeek", "ts"])  # fmt: skip
    utc = lambda t: dt.datetime.fromtimestamp(t, dt.UTC).isoformat()  # noqa: E731
    res = {"rows": df.height,
           "label_binary": dict(df.group_by("label_binary").len().iter_rows()),
           "label_tactic": dict(df.group_by("label_tactic").len().sort("len", descending=True).iter_rows()),
           "sources": df["src_ip_zeek"].n_unique(), "destinations": df["dest_ip_zeek"].n_unique(),
           "first": utc(df["ts"].min()), "last": utc(df["ts"].max())}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
