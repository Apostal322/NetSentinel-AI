"""NF-v3-style records (from PCAP flows or Zeek) -> canonical frame for the inference engine.

Uses the same canonicalisation and alias derivation as NF-v3 ingestion
(netsentinel.data.nf_v3.add_nf_aliases), so training and inference share one definition.
Fields absent from the source stay null and are reported by the engine as missing.
"""

from __future__ import annotations

from collections.abc import Iterable

import polars as pl

from netsentinel.data.nf_v3 import add_nf_aliases, canonical
from netsentinel.features.nf_schema import NF_FLOW_COLUMNS

INT_FIELDS = {"flow_start_milliseconds", "flow_end_milliseconds", "l4_src_port", "l4_dst_port",
              "protocol", "in_bytes", "in_pkts", "out_bytes", "out_pkts", "tcp_flags",
              "client_tcp_flags", "server_tcp_flags", "flow_duration_milliseconds"}  # fmt: skip
STRING_FIELDS = {"ipv4_src_addr", "ipv4_dst_addr"}


def records_to_frame(records: Iterable[dict], utc_offset_hours: float = 0.0) -> pl.DataFrame:
    rows = [{canonical(k): v for k, v in r.items()} for r in records]
    if not rows:
        raise ValueError("no flow records")
    df = pl.DataFrame(rows, infer_schema_length=None)
    casts = []
    for c in df.columns:
        if c in STRING_FIELDS:
            casts.append(pl.col(c).cast(pl.Utf8))
        elif c in INT_FIELDS:
            casts.append(pl.col(c).cast(pl.Int64))
        else:
            casts.append(pl.col(c).cast(pl.Float32))
    df = df.with_columns(casts)
    missing = [c for c in NF_FLOW_COLUMNS if c not in df.columns and not c.startswith(("cli_",
                                                                                      "srv_"))]  # fmt: skip
    df = df.with_columns([pl.lit(None, dtype=pl.Float32).alias(c) for c in missing])
    df = add_nf_aliases(df, utc_offset_hours)
    return df.sort("flow_end_milliseconds").with_row_index("row_id")
