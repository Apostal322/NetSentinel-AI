"""CSE-CIC-IDS2018 (CICFlowMeter-V3 CSV) ingestion: raw CSV -> typed, canonical Parquet.

Known quirks handled here (observed in the files, see docs/datasets/cse_cic_ids2018.md):
* Some files repeat the header row in the middle of the data -> those rows are dropped and counted.
* `Flow Byts/s` and `Flow Pkts/s` contain `Infinity` / `NaN` -> kept as IEEE inf/NaN here,
  handled explicitly by the feature pipeline (never silently imputed at ingest).
* The 2018-02-20 file has four extra columns (Flow ID, Src IP, Src Port, Dst IP). They are kept
  for leakage analysis only and are never model features.
* `Init Fwd Win Byts` / `Init Bwd Win Byts` use -1 as "not observed".
* Timestamps are naive local capture time at 1 s resolution and mark the flow *start*.
* Timestamps use a 12-hour clock with the AM/PM marker missing: every day spans clock hours
  01-12, hours 06-07 are (almost) absent, and afternoon attacks match the UNB schedule only after
  +12 h (e.g. SSH brute force 2018-02-14 appears at 02:01-03:32, published 14:01-15:31), while
  morning attacks match as-is (FTP brute force 10:33). Capture ran ~08:00-19:59, so clock hours
  < PM_HOUR_BELOW are shifted by +12 h and flagged in `clock_corrected`. See
  scripts/check_clock.py and docs/datasets/cse_cic_ids2018.md.
* A handful of rows carry 1970 timestamps with negative durations; they are dropped and counted.
"""

from __future__ import annotations

import csv
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import polars as pl

log = logging.getLogger(__name__)

RAW_COLUMNS: tuple[str, ...] = (
    "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
    "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min", "Pkt Len Max",
    "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
    "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
    "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
    "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max",
    "Idle Min", "Label",
)  # fmt: skip
IDENTIFIER_COLUMNS: tuple[str, ...] = ("Flow ID", "Src IP", "Src Port", "Dst IP")
TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"
PM_HOUR_BELOW = 8  # clock hours 1..7 are afternoon (13..19 h)

# Raw label -> (canonical attack label, attack family). Unknown raw labels fail ingestion.
LABELS: dict[str, tuple[str, str]] = {
    "Benign": ("benign", "benign"),
    "FTP-BruteForce": ("ftp_bruteforce", "bruteforce"),
    "SSH-Bruteforce": ("ssh_bruteforce", "bruteforce"),
    "DoS attacks-GoldenEye": ("dos_goldeneye", "dos"),
    "DoS attacks-Slowloris": ("dos_slowloris", "dos"),
    "DoS attacks-SlowHTTPTest": ("dos_slowhttptest", "dos"),
    "DoS attacks-Hulk": ("dos_hulk", "dos"),
    "DDoS attacks-LOIC-HTTP": ("ddos_loic_http", "ddos"),
    "DDOS attack-LOIC-UDP": ("ddos_loic_udp", "ddos"),
    "DDOS attack-HOIC": ("ddos_hoic", "ddos"),
    "Brute Force -Web": ("web_bruteforce", "web_attack"),
    "Brute Force -XSS": ("web_xss", "web_attack"),
    "SQL Injection": ("web_sql_injection", "web_attack"),
    "Infilteration": ("infiltration", "infiltration"),
    "Bot": ("bot", "botnet"),
}


def canonical(name: str) -> str:
    """'Flow Byts/s' -> 'flow_byts_per_s', 'Down/Up Ratio' -> 'down_per_up_ratio'."""
    s = name.strip().lower().replace("/", "_per_")
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


INT_COLUMNS = {"Dst Port", "Protocol", "Flow Duration", "Src Port"}
FEATURE_SOURCE_COLUMNS = tuple(c for c in RAW_COLUMNS if c not in {"Timestamp", "Label"})


@dataclass
class IngestReport:
    source: str
    output: str
    day: str
    rows_written: int
    repeated_header_rows: int
    has_identifiers: bool
    label_counts: dict[str, int]
    invalid_timestamp_rows: int = 0
    clock_corrected_rows: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def _typed_frame(lf: pl.LazyFrame, columns: list[str], day: str) -> pl.LazyFrame:
    exprs: list[pl.Expr] = [
        pl.col("Timestamp")
        .str.strptime(pl.Datetime("us"), TIMESTAMP_FORMAT, strict=True)
        .alias("timestamp"),
        pl.col("Label")
        .replace_strict({k: v[0] for k, v in LABELS.items()}, return_dtype=pl.Utf8)
        .alias("label"),
        pl.col("Label")
        .replace_strict({k: v[1] for k, v in LABELS.items()}, return_dtype=pl.Utf8)
        .alias("family"),
        pl.lit(day).alias("day"),
    ]
    for col in FEATURE_SOURCE_COLUMNS:
        dtype = pl.Int64 if col in INT_COLUMNS else pl.Float32
        # Strict cast: a malformed numeric cell stops ingestion instead of becoming null.
        exprs.append(pl.col(col).cast(pl.Float64, strict=True).cast(dtype).alias(canonical(col)))
    for col in IDENTIFIER_COLUMNS:
        if col in columns:
            exprs.append(pl.col(col).alias(canonical(col)))
        else:
            exprs.append(pl.lit(None, dtype=pl.Utf8).alias(canonical(col)))
    hour = pl.col("timestamp").dt.hour()
    return (
        lf.select(exprs)
        .with_row_index("row_id")
        .with_columns((hour < PM_HOUR_BELOW).alias("clock_corrected"))
        .with_columns(
            pl.when(pl.col("clock_corrected"))
            .then(pl.col("timestamp") + pl.duration(hours=12))
            .otherwise(pl.col("timestamp"))
            .alias("timestamp")
        )
    )


def ingest_csv(
    src: str | Path, dst: str | Path, day: str, block_bytes: int = 64 << 20
) -> IngestReport:
    """Stream the CSV in ~`block_bytes` blocks (pyarrow reader), type each block with Polars and
    append it to one Parquet file. Peak memory is a few blocks, independent of file size
    (a single lazy Polars plan over the 4 GB 2018-02-20 file used >7 GB RAM)."""
    import pyarrow as pa
    import pyarrow.csv as pacsv
    import pyarrow.parquet as pq

    src, dst = Path(src), Path(dst)
    if not src.is_file():
        raise FileNotFoundError(src)
    with src.open(encoding="utf-8", newline="") as fh:
        columns = next(csv.reader(fh))
    missing = [c for c in RAW_COLUMNS if c not in columns]
    unexpected = [c for c in columns if c not in RAW_COLUMNS and c not in IDENTIFIER_COLUMNS]
    if missing or unexpected:
        raise ValueError(f"{src.name}: missing columns {missing}, unexpected {unexpected}")

    reader = pacsv.open_csv(
        src,
        read_options=pacsv.ReadOptions(block_size=block_bytes),
        convert_options=pacsv.ConvertOptions(column_types={c: pa.string() for c in columns}),
    )
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".parquet.partial")
    writer = None
    repeated = offset = invalid = 0
    try:
        for batch in reader:
            chunk = pl.from_arrow(pa.Table.from_batches([batch]))
            is_header = chunk["Label"] == "Label"
            repeated += int(is_header.sum())
            chunk = chunk.filter(~is_header)
            unknown = sorted(set(chunk["Label"].unique()) - LABELS.keys())
            if unknown:
                raise ValueError(
                    f"{src.name}: unknown labels {unknown}; extend LABELS deliberately"
                )
            typed = (
                _typed_frame(chunk.lazy(), columns, day)
                .with_columns(pl.col("row_id") + offset)
                .collect()
            )
            offset += typed.height  # row_id = position among data rows, before any drop
            valid = typed["timestamp"].dt.date().cast(pl.Utf8) == day
            invalid += int((~valid).sum())
            table = typed.filter(valid).to_arrow()
            if writer is None:
                writer = pq.ParquetWriter(tmp, table.schema, compression="zstd")
            writer.write_table(table)
    finally:
        if writer is not None:
            writer.close()
    if writer is None:
        raise ValueError(f"{src.name}: no data rows")
    tmp.replace(dst)  # only complete files get the final name

    out = pl.scan_parquet(dst)
    rows = out.select(pl.len()).collect().item()
    counts = out.group_by("label").agg(pl.len()).collect()
    if rows == 0:
        dst.unlink()
        raise ValueError(f"{src.name}: no rows dated {day}; is the manifest day correct?")
    corrected = out.select(pl.col("clock_corrected").sum()).collect().item()
    report = IngestReport(
        invalid_timestamp_rows=invalid,
        clock_corrected_rows=int(corrected),
        source=str(src),
        output=str(dst),
        day=day,
        rows_written=int(rows),
        repeated_header_rows=int(repeated),
        has_identifiers="Src IP" in columns,
        label_counts={r["label"]: int(r["len"]) for r in counts.iter_rows(named=True)},
    )
    log.info(
        "ingested %s: %d rows, %d repeated headers, %d invalid timestamps, %d clock-corrected",
        src.name, rows, repeated, invalid, corrected,
    )  # fmt: skip
    return report
