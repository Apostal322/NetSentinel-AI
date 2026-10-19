"""Versioned feature definitions shared by training and inference.

Change any list or derived-feature definition below -> bump FEATURE_SCHEMA_VERSION. Datasets
and model artifacts record the version and refuse to load against a different one.

Never features: absolute timestamps, row ids, IPs, source ports, flow ids (identifiers or
schedule artefacts). The raw destination port is excluded by default and only enters through
the explicit `flow_port` ablation, because attacks in IDS2018 target few fixed ports.
"""

from __future__ import annotations

import hashlib
import json

import polars as pl

from netsentinel.data.ids2018 import FEATURE_SOURCE_COLUMNS, canonical
from netsentinel.features.context import DEFAULT_WINDOWS, context_feature_names

FEATURE_SCHEMA_VERSION = "1.0.0"

# Columns constant over all 10 ingested days; dropped. Must equal `constant_columns` in
# reports/eda/eda.json, enforced by tests/ml/test_real_data.py (pytest -m data).
CONSTANT_COLUMNS: tuple[str, ...] = (
    "bwd_psh_flags",
    "bwd_urg_flags",
    "fwd_byts_per_b_avg",
    "fwd_pkts_per_b_avg",
    "fwd_blk_rate_avg",
    "bwd_byts_per_b_avg",
    "bwd_pkts_per_b_avg",
    "bwd_blk_rate_avg",
)
# Fields shown to act as collection artefacts / shortcuts in CIC datasets (Engelen et al. 2021).
SHORTCUT_SUSPECTS: tuple[str, ...] = (
    "init_fwd_win_byts",
    "init_bwd_win_byts",
    "fwd_header_len",
    "fwd_seg_size_min",
)
IDENTIFIERS = ("dst_port", "protocol", "src_port")
DERIVED: tuple[str, ...] = ("proto_tcp", "proto_udp", "proto_other", "port_class")


def raw_flow_columns() -> list[str]:
    cols = [canonical(c) for c in FEATURE_SOURCE_COLUMNS]
    return [c for c in cols if c not in CONSTANT_COLUMNS and c not in IDENTIFIERS]


def flow_feature_columns() -> list[str]:
    """Columns the dataset builder keeps from the raw flow (before derived features)."""
    return raw_flow_columns()


def add_derived(df: pl.DataFrame | pl.LazyFrame):
    """Protocol one-hot and coarse destination-port class (0 well-known <1024, 1 registered
    <49152, 2 dynamic). Uses only fields present in every flow record."""
    port = pl.col("dst_port")
    return df.with_columns(
        (pl.col("protocol") == 6).cast(pl.Int8).alias("proto_tcp"),
        (pl.col("protocol") == 17).cast(pl.Int8).alias("proto_udp"),
        (~pl.col("protocol").is_in([6, 17])).cast(pl.Int8).alias("proto_other"),
        pl.when(port < 1024).then(0).when(port < 49152).then(1).otherwise(2)
        .cast(pl.Int8).alias("port_class"),
    )  # fmt: skip


FEATURE_SETS = ("flow", "flow_noshortcut", "flow_port", "flow_ctx5", "flow_ctx", "ctx_only")


def feature_set(name: str, windows: tuple[int, ...] = DEFAULT_WINDOWS) -> list[str]:
    flow = [*raw_flow_columns(), *DERIVED]
    ctx = context_feature_names(windows)
    if name == "flow":
        return flow
    if name == "flow_noshortcut":
        return [c for c in flow if c not in SHORTCUT_SUSPECTS]
    if name == "flow_port":
        return [*flow, "dst_port"]
    if name == "flow_ctx5":
        return flow + [c for c in ctx if c.endswith("_5s")]
    if name == "flow_ctx":
        return flow + ctx
    if name == "ctx_only":
        return ctx
    raise ValueError(f"unknown feature set {name!r}; choose from {FEATURE_SETS}")


def schema_fingerprint(columns: list[str]) -> str:
    """Stable hash of an ordered feature list; stored with every model artifact."""
    payload = json.dumps({"version": FEATURE_SCHEMA_VERSION, "columns": columns})
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
