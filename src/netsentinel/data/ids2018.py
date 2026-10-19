"""CSE-CIC-IDS2018 (CICFlowMeter-V3 CSV) ingestion: raw CSV -> typed, canonical Parquet.

Known quirks handled here (observed in the files, see docs/datasets/cse_cic_ids2018.md):
* Some files repeat the header row in the middle of the data -> those rows are dropped and counted.
* `Flow Byts/s` and `Flow Pkts/s` contain `Infinity` / `NaN` -> kept as IEEE inf/NaN here,
  handled explicitly by the feature pipeline (never silently imputed at ingest).
* The 2018-02-20 file has four extra columns (Flow ID, Src IP, Src Port, Dst IP). They are kept
  for leakage analysis only and are never model features.
* `Init Fwd Win Byts` / `Init Bwd Win Byts` use -1 as "not observed".
* Timestamps are naive local capture time at 1 s resolution and mark the flow *start*.
"""

from __future__ import annotations

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
    return lf.select(exprs).with_row_index("row_id")


def ingest_csv(src: str | Path, dst: str | Path, day: str) -> IngestReport:
    src, dst = Path(src), Path(dst)
    if not src.is_file():
        raise FileNotFoundError(src)
    lf = pl.scan_csv(src, infer_schema=False)
    columns = lf.collect_schema().names()
    missing = [c for c in RAW_COLUMNS if c not in columns]
    unexpected = [c for c in columns if c not in RAW_COLUMNS and c not in IDENTIFIER_COLUMNS]
    if missing or unexpected:
        raise ValueError(f"{src.name}: missing columns {missing}, unexpected {unexpected}")

    repeated = lf.filter(pl.col("Label") == "Label").select(pl.len()).collect().item()
    raw_labels = lf.filter(pl.col("Label") != "Label").group_by("Label").agg(pl.len()).collect()
    unknown = sorted(set(raw_labels["Label"]) - LABELS.keys())
    if unknown:
        raise ValueError(f"{src.name}: unknown labels {unknown}; extend LABELS deliberately")

    dst.parent.mkdir(parents=True, exist_ok=True)
    typed = _typed_frame(lf.filter(pl.col("Label") != "Label"), columns, day)
    typed.sink_parquet(dst, compression="zstd")

    out = pl.scan_parquet(dst)
    rows = out.select(pl.len()).collect().item()
    counts = out.group_by("label").agg(pl.len()).collect()
    report = IngestReport(
        source=str(src),
        output=str(dst),
        day=day,
        rows_written=int(rows),
        repeated_header_rows=int(repeated),
        has_identifiers="Src IP" in columns,
        label_counts={r["label"]: int(r["len"]) for r in counts.iter_rows(named=True)},
    )
    log.info("ingested %s: %d rows, %d repeated headers", src.name, rows, repeated)
    return report
