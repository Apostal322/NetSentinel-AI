"""Build the model-ready dataset: per-day causal context on the full stream, then a
deterministic stratified subsample with inverse-probability weights.

Sampling: within each (day, label) stratum a row is kept if hash(row_id, seed) falls under the
stratum's rate, where rate = min(1, cap / stratum_size); benign uses `benign_per_day`, attacks
`attack_cap_per_label_day`. `sample_weight = 1 / rate`, so weighted metrics estimate what the
full capture would give (prevalence-corrected precision, false alerts per hour).
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

import polars as pl

from netsentinel.features.context import DEFAULT_WINDOWS, compute_context_chunked
from netsentinel.features.nf_schema import NF_FEATURE_SCHEMA_VERSION, nf_flow_feature_columns
from netsentinel.features.schema import FEATURE_SCHEMA_VERSION, flow_feature_columns

log = logging.getLogger(__name__)
HASH_MOD = 1_000_000
DAY_GLOB = "[0-9][0-9][0-9][0-9]-*.parquet"
SCHEMAS = {  # schema name -> (feature columns kept from the raw flow, schema version)
    "cic": (flow_feature_columns, FEATURE_SCHEMA_VERSION),
    "nf": (nf_flow_feature_columns, NF_FEATURE_SCHEMA_VERSION),
}


@dataclass(frozen=True)
class BuildConfig:
    benign_per_day: int = 50_000
    attack_cap_per_label_day: int = 25_000
    windows: tuple[int, ...] = DEFAULT_WINDOWS
    chunk_seconds: int = 3600
    seed: int = 42
    schema: str = "cic"


def _sample_rates(lf: pl.LazyFrame, cfg: BuildConfig) -> pl.DataFrame:
    counts = lf.group_by("label").agg(pl.len().alias("n")).collect()
    cap = (
        pl.when(pl.col("label") == "benign")
        .then(pl.lit(cfg.benign_per_day))
        .otherwise(pl.lit(cfg.attack_cap_per_label_day))
    )
    return (
        counts.with_columns(pl.min_horizontal(pl.lit(1.0), cap / pl.col("n")).alias("rate"))
        .with_columns(
            # The realised rate is quantised to HASH_MOD steps; weights use the quantised value.
            (pl.col("rate") * HASH_MOD).ceil().cast(pl.Int64).alias("keep_below"),
        )
        .with_columns((pl.col("keep_below") / HASH_MOD).alias("rate"))
    )


def build_day(path: Path, cfg: BuildConfig) -> tuple[pl.DataFrame, dict]:
    lf = pl.scan_parquet(path)
    ctx = compute_context_chunked(lf, cfg.windows, cfg.chunk_seconds)
    rates = _sample_rates(lf, cfg)
    feats = SCHEMAS[cfg.schema][0]()
    keep_cols = ["day", "row_id", "timestamp", "label", "family", "dst_port", "protocol", *feats]
    keep_cols = list(dict.fromkeys(keep_cols))  # protocol/dst_port may also be features
    sampled = (
        lf.select(keep_cols)
        .join(rates.lazy().select("label", "keep_below", "rate"), on="label", how="left")
        .filter(pl.col("row_id").hash(seed=cfg.seed) % HASH_MOD < pl.col("keep_below"))
        .with_columns((1.0 / pl.col("rate")).cast(pl.Float32).alias("sample_weight"))
        .drop("keep_below", "rate")
        .collect()
    )
    out = sampled.join(ctx, on="row_id", how="left")
    missing_ctx = out["event_sec"].null_count()
    if missing_ctx:
        raise RuntimeError(f"{path.name}: {missing_ctx} sampled rows without context features")
    stats = {
        "day": path.stem,
        "rows_full": int(rates["n"].sum()),
        "rows_sampled": out.height,
        "strata": rates.select("label", "n", "rate").to_dicts(),
    }
    return out.sort("event_sec", "row_id"), stats


def build_dataset(interim_dir: str | Path, out_dir: str | Path, cfg: BuildConfig) -> dict:
    interim_dir, out_dir = Path(interim_dir), Path(out_dir)
    if cfg.schema not in SCHEMAS:
        raise ValueError(f"unknown schema {cfg.schema!r}")
    paths = sorted(interim_dir.glob(DAY_GLOB))
    if not paths:
        raise FileNotFoundError(f"no ingested days in {interim_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    days = []
    for p in paths:
        log.info("building %s", p.name)
        frame, stats = build_day(p, cfg)
        frame.write_parquet(out_dir / f"{p.stem}.parquet", compression="zstd")
        days.append(stats)
        del frame
    meta = {
        "feature_schema_version": SCHEMAS[cfg.schema][1],
        "build_config": asdict(cfg),
        "days": days,
    }
    (out_dir / "dataset_meta.json").write_text(json.dumps(meta, indent=2), "utf-8")
    return meta


def load_dataset(
    processed_dir: str | Path,
    columns: list[str] | None = None,
    expected_version: str = FEATURE_SCHEMA_VERSION,
) -> pl.DataFrame:
    processed_dir = Path(processed_dir)
    meta_path = processed_dir / "dataset_meta.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"{meta_path} missing; run `netsentinel features build`")
    meta = json.loads(meta_path.read_text("utf-8"))
    if meta["feature_schema_version"] != expected_version:
        raise ValueError(
            f"dataset built with feature schema {meta['feature_schema_version']}, code expects "
            f"{expected_version}; rebuild the dataset"
        )
    return pl.concat(
        [pl.read_parquet(p, columns=columns) for p in sorted(processed_dir.glob(DAY_GLOB))],
        how="vertical",
    )
