"""Diagnose the 12-hour clock in IDS2018 timestamps: per day and hour-of-clock, where do the
rows sit in file order? If hours 1-7 occur after hours 8-12 in file order, they are PM."""

import sys
from pathlib import Path

import polars as pl

interim = Path(sys.argv[1] if len(sys.argv) > 1 else "data/interim/ids2018")
for p in sorted(interim.glob("2018-*.parquet")):
    lf = pl.scan_parquet(p).filter(pl.col("timestamp").dt.year() == 2018)
    n = lf.select(pl.len()).collect().item()
    stats = (
        lf.group_by(pl.col("timestamp").dt.hour().alias("h"))
        .agg(
            pl.len().alias("rows"),
            (pl.col("row_id").quantile(0.05) / n).alias("q05"),
            (pl.col("row_id").median() / n).alias("q50"),
            (pl.col("row_id").quantile(0.95) / n).alias("q95"),
        )
        .sort("h")
        .collect()
    )
    print(f"== {p.stem} rows={n:,}")
    for r in stats.iter_rows(named=True):
        print(f"   h={r['h']:2d} rows={r['rows']:>9,} pos q05={r['q05']:.2f} "
              f"q50={r['q50']:.2f} q95={r['q95']:.2f}")  # fmt: skip
