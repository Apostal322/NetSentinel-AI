"""Cross-checks after NetFlow v3 ingestion.

1. 12-hour-clock correction (CIC CSVs): compare each attack label's first/last LOCAL time per
   day from NF-IDS2018-v3 (epoch timestamps -> UTC-4) with the corrected CIC CSV times
   (reports/eda/eda.json). Agreement within minutes independently confirms the +12 h fix.
2. Truncation: per day and label, NF (nProbe, full pcaps) vs CIC CSV flow counts.
3. UNSW-NB15 time zone sanity: hour-of-day histogram of flow starts under the assumed offset.

Usage: uv run python scripts/audit/audit_nf_vs_cic.py -> reports/audit/nf_vs_cic.json
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
NF = ROOT / "data/interim/nf_cicids2018_v3"
UNSW = ROOT / "data/interim/nf_unsw_nb15_v3"


def nf_label_times() -> pl.DataFrame:
    parts = []
    for p in sorted(NF.glob("[0-9]*.parquet")):
        parts.append(
            pl.scan_parquet(p)
            .group_by("day", "label")
            .agg(pl.len().alias("nf_rows"), pl.col("timestamp").min().alias("nf_first"),
                 pl.col("timestamp").max().alias("nf_last"))
            .collect()
        )  # fmt: skip
    return pl.concat(parts)


def cic_label_times() -> pl.DataFrame:
    eda = json.loads((ROOT / "reports/eda/eda.json").read_text("utf-8"))
    rows = []
    for d in eda["days"]:
        for r in d["labels"]:
            rows.append({"day": d["day"], "label": r["label"], "cic_rows": r["rows"],
                         "cic_first": datetime.fromisoformat(r["first"]),
                         "cic_last": datetime.fromisoformat(r["last"])})  # fmt: skip
    return pl.DataFrame(rows)


def main() -> None:
    out: dict = {}
    if NF.exists():
        j = cic_label_times().join(nf_label_times(), on=["day", "label"], how="full",
                                   coalesce=True)  # fmt: skip
        j = j.with_columns(
            ((pl.col("nf_first") - pl.col("cic_first")).dt.total_minutes()).alias("first_diff_min"),
            ((pl.col("nf_last") - pl.col("cic_last")).dt.total_minutes()).alias("last_diff_min"),
            (pl.col("cic_rows") / pl.col("nf_rows")).alias("cic_to_nf_row_ratio"),
        ).sort("day", "label")
        out["ids2018_label_times"] = j.with_columns(
            [pl.col(c).cast(pl.Utf8) for c in ("cic_first", "cic_last", "nf_first", "nf_last")]
        ).to_dicts()
        attacks = j.filter(pl.col("label") != "benign")
        out["attack_first_diff_minutes_abs_median"] = float(
            attacks["first_diff_min"].abs().median()
        )
        with pl.Config(tbl_rows=60, tbl_cols=12, tbl_width_chars=200):
            print(j.select("day", "label", "cic_rows", "nf_rows", "cic_first", "nf_first",
                           "first_diff_min", "last_diff_min"))  # fmt: skip
    if UNSW.exists():
        h = (
            pl.concat(
                [
                    pl.scan_parquet(p)
                    .select(pl.col("timestamp").dt.hour().alias("h"), "label")
                    .collect()
                    for p in sorted(UNSW.glob("[0-9]*.parquet"))
                ]
            )  # fmt: skip
            .group_by("h")
            .agg(pl.len().alias("flows"), (pl.col("label") != "benign").sum().alias("attacks"))
            .sort("h")
        )
        out["unsw_hour_of_day_local"] = h.to_dicts()
        out["unsw_days"] = sorted(p.stem for p in UNSW.glob("[0-9]*.parquet"))
        print(h)
    (ROOT / "reports/audit/nf_vs_cic.json").write_text(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
