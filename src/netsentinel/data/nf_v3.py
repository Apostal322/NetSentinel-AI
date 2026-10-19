"""NetFlow v3 (UQ, nProbe) ingestion: zipped BagIt CSV -> typed per-day Parquet.

* Reads the CSV straight from the zip (no extraction) with the bounded-memory block reader
  used for IDS2018, and verifies the BagIt SHA-1 of the member against `manifest-sha1.txt`.
* `FLOW_START_MILLISECONDS` is epoch ms (UTC). Rows are converted to naive LOCAL capture time
  with a per-dataset UTC offset (documented in configs/datasets/nf_v3.yaml) and partitioned by
  local date, so day-based splits and context windows match the IDS2018 conventions.
* Writes alias columns (`timestamp`, `flow_duration` in us, `tot_fwd_pkts`, ... ,
  `syn_flag_cnt`) so the existing context-feature and dataset-build code works unchanged.
* Identifiers (IPs, source port) are kept for leakage analysis only, never features.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import re
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

log = logging.getLogger(__name__)

STRING_COLUMNS = ("IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Attack")
INT_COLUMNS = (
    "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL",
    "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS", "TCP_FLAGS", "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS", "FLOW_DURATION_MILLISECONDS", "Label",
)  # fmt: skip
REQUIRED = (*STRING_COLUMNS, *INT_COLUMNS)


def canonical(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def canonical_attack(raw: str) -> str:
    return canonical(raw) or "unknown"


@dataclass
class NFIngestReport:
    source: str
    member: str
    sha1_ok: bool
    rows_written: int
    days: dict[str, int]
    attack_counts: dict[str, int]
    utc_offset_hours: float
    absent_columns: list[str] = field(default_factory=list)
    empty_values: dict[str, int] = field(default_factory=dict)  # empty cells read as null
    columns: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _member(z: zipfile.ZipFile) -> tuple[str, str | None, str]:
    names = z.namelist()
    csvs = [n for n in names if n.endswith(".csv") and "/data/" in n and "Features" not in n]
    if len(csvs) != 1:
        raise ValueError(f"expected one data CSV in archive, found {csvs}")
    prefix = csvs[0].split("/data/")[0]
    manifest = f"{prefix}/manifest-sha1.txt"
    expected = None
    if manifest in names:
        for line in z.read(manifest).decode("utf-8").splitlines():
            digest, _, path = line.partition(" ")
            if path.strip() == csvs[0][len(prefix) + 1 :]:
                expected = digest.strip()
    return csvs[0], expected, prefix


def sha1_of_member(z: zipfile.ZipFile, name: str) -> str:
    h = hashlib.sha1()
    with z.open(name) as fh:
        while block := fh.read(1 << 22):
            h.update(block)
    return h.hexdigest()


TCP_BITS = (("fin", 1), ("syn", 2), ("rst", 4), ("psh", 8), ("ack", 16), ("urg", 32))


def add_nf_aliases(df: pl.DataFrame, offset_h: float) -> pl.DataFrame:
    """Derived columns shared by NF ingestion, PCAP flows and Zeek logs (one definition):
    local timestamp, IDS2018-named aliases used by the context code, TCP flag bits."""
    start = pl.from_epoch(pl.col("flow_start_milliseconds"), time_unit="ms") + pl.duration(
        minutes=int(round(offset_h * 60))
    )
    client = pl.col("client_tcp_flags")
    server = pl.col("server_tcp_flags")
    return df.with_columns(
        start.cast(pl.Datetime("us")).alias("timestamp"),
        (pl.col("flow_duration_milliseconds").clip(0) * 1000).alias("flow_duration"),
        pl.col("l4_dst_port").alias("dst_port"),
        pl.col("in_pkts").cast(pl.Float32).alias("tot_fwd_pkts"),
        pl.col("out_pkts").cast(pl.Float32).alias("tot_bwd_pkts"),
        pl.col("in_bytes").cast(pl.Float32).alias("totlen_fwd_pkts"),
        pl.col("out_bytes").cast(pl.Float32).alias("totlen_bwd_pkts"),
        ((client & 2) > 0).cast(pl.Float32).alias("syn_flag_cnt"),
        *[((client & bit) > 0).cast(pl.Int8).alias(f"cli_{nm}") for nm, bit in TCP_BITS],
        *[((server & bit) > 0).cast(pl.Int8).alias(f"srv_{nm}") for nm, bit in TCP_BITS],
    )


def _absent_feature_columns(columns: list[str]) -> list[str]:
    from netsentinel.features.nf_schema import NF_FLOW_COLUMNS

    have = {canonical(c) for c in columns}
    return [c for c in NF_FLOW_COLUMNS if c not in have and not c.startswith(("cli_", "srv_"))]


def _typed(chunk: pl.DataFrame, columns: list[str], offset_h: float) -> pl.DataFrame:
    exprs = []
    for c in columns:
        name = canonical(c)
        if c in STRING_COLUMNS:
            exprs.append(pl.col(c).alias(name))
        elif c in INT_COLUMNS:
            exprs.append(pl.col(c).cast(pl.Float64, strict=True).cast(pl.Int64).alias(name))
        else:
            # Non-core float fields may be empty in the source CSV (e.g. rate fields of
            # zero-duration flows): empty -> null (counted in the report); anything else
            # malformed still fails the strict cast.
            col = pl.when(pl.col(c) == "").then(None).otherwise(pl.col(c))
            exprs.append(col.cast(pl.Float64, strict=True).cast(pl.Float32).alias(name))
    df = chunk.select(exprs)
    # Feature columns absent from this source become explicit nulls (listed in the report).
    df = df.with_columns(
        [pl.lit(None, pl.Float32).alias(c) for c in _absent_feature_columns(columns)]
    )
    df = add_nf_aliases(df, offset_h)
    return df.with_columns(
        pl.when(pl.col("label") == 0).then(pl.lit("benign"))
        .otherwise(pl.col("attack").replace_strict(
            {a: canonical_attack(a) for a in chunk["Attack"].unique().to_list()},
            return_dtype=pl.Utf8))
        .alias("label_name"),
    )  # fmt: skip


def ingest_nf_zip(
    zip_path: str | Path,
    out_dir: str | Path,
    utc_offset_hours: float,
    family_map: dict[str, str] | None = None,
    block_bytes: int = 64 << 20,
    verify: bool = True,
    label_map: dict[str, str] | None = None,
) -> NFIngestReport:
    """`label_map` renames canonicalised attack names (e.g. `dos_attacks_hulk` -> `dos_hulk`,
    aligning NF-IDS2018 with the CIC labels); `family_map` maps final labels to families."""
    import pyarrow as pa
    import pyarrow.csv as pacsv
    import pyarrow.parquet as pq

    zip_path, out_dir = Path(zip_path), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    family_map = family_map or {}
    label_map = label_map or {}
    with zipfile.ZipFile(zip_path) as z:
        member, expected_sha1, _ = _member(z)
        sha1_ok = True
        if verify and expected_sha1:
            sha1_ok = sha1_of_member(z, member) == expected_sha1
            if not sha1_ok:
                raise ValueError(
                    f"{zip_path.name}: SHA-1 of {member} does not match BagIt manifest"
                )
        with z.open(member) as raw:
            header = io.TextIOWrapper(raw, encoding="utf-8").readline().strip().split(",")
        missing = [c for c in REQUIRED if c not in header]
        if missing:
            raise ValueError(f"{zip_path.name}: missing columns {missing}")
        writers: dict[str, pq.ParquetWriter] = {}
        offsets: dict[str, int] = {}
        attack_counts: dict[str, int] = {}
        empty_values: dict[str, int] = {}
        unknown_families: set[str] = set()
        try:
            with z.open(member) as raw:
                reader = pacsv.open_csv(
                    pa.PythonFile(raw, mode="r"),
                    read_options=pacsv.ReadOptions(block_size=block_bytes),
                    convert_options=pacsv.ConvertOptions(
                        column_types={c: pa.string() for c in header}
                    ),
                )
                float_cols = [c for c in header if c not in STRING_COLUMNS and c not in INT_COLUMNS]
                for batch in reader:
                    chunk = pl.from_arrow(pa.Table.from_batches([batch]))
                    empties = chunk.select([(pl.col(c) == "").sum().alias(c) for c in float_cols])
                    for c, n in empties.row(0, named=True).items():
                        if n:
                            empty_values[canonical(c)] = empty_values.get(canonical(c), 0) + int(n)
                    typed = _typed(chunk, header, utc_offset_hours)
                    typed = (
                        typed.with_columns(
                            pl.col("timestamp").dt.date().cast(pl.Utf8).alias("day"),
                            pl.col("label_name").replace(label_map).alias("label"),
                        )
                        .with_columns(
                            pl.col("label")
                            .replace_strict({**family_map, "benign": "benign"}, default="unmapped")
                            .alias("family"),
                        )
                        .drop("label_name")
                    )
                    unknown_families |= set(
                        typed.filter(pl.col("family") == "unmapped")["label"].unique()
                    )
                    for r in typed.group_by("label").len().iter_rows():
                        attack_counts[r[0]] = attack_counts.get(r[0], 0) + int(r[1])
                    for (day,), part in typed.group_by("day", maintain_order=True):
                        start = offsets.get(day, 0)
                        part = part.with_row_index("row_id", offset=start)
                        offsets[day] = start + part.height
                        table = part.to_arrow()
                        if day not in writers:
                            writers[day] = pq.ParquetWriter(
                                out_dir / f"{day}.parquet.partial", table.schema, compression="zstd"
                            )
                        writers[day].write_table(table)
        finally:
            for w in writers.values():
                w.close()
        for day in writers:
            (out_dir / f"{day}.parquet.partial").replace(out_dir / f"{day}.parquet")
    if unknown_families:
        log.warning("labels without family mapping: %s", sorted(unknown_families))
    report = NFIngestReport(
        source=str(zip_path), member=member, sha1_ok=sha1_ok, rows_written=sum(offsets.values()),
        days=dict(sorted(offsets.items())), attack_counts=dict(sorted(attack_counts.items())),
        utc_offset_hours=utc_offset_hours, absent_columns=_absent_feature_columns(header),
        empty_values=dict(sorted(empty_values.items())), columns=header,
    )  # fmt: skip
    if report.absent_columns:
        log.warning("feature columns absent from source (null): %s", report.absent_columns)
    (out_dir / "ingest_report.json").write_text(json.dumps(report.as_dict(), indent=2), "utf-8")
    log.info("ingested %s: %d rows over %d days", zip_path.name, report.rows_written, len(offsets))
    return report


def local_time(epoch_ms: int, utc_offset_hours: float) -> datetime:
    """Helper for docs/tests: epoch ms -> naive local time."""
    return (datetime.fromtimestamp(epoch_ms / 1000, UTC) + timedelta(hours=utc_offset_hours)
            ).replace(tzinfo=None)  # fmt: skip
