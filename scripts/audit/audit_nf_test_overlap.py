"""Mission 5 pre-registration support: which NF-v3 rows were never used for fitting or selection?

Two split protocols have been used on the NF datasets: `episode` (v4 in-domain, open-set and
the source side of transfer/adaptation) and `chronological` (target side of adaptation, v5).
A row may be used for final testing only if it is in the test partition under BOTH protocols.
This script reports the size and label/family composition of that intersection. It reads
labels and split assignments only; it computes no model output.

Usage: uv run python scripts/audit/audit_nf_test_overlap.py
"""

import json
from pathlib import Path

import polars as pl

from netsentinel.training.data import prepare

DATASETS = {
    "nf_cicids2018": {"processed_dir": "data/processed/nf_cicids2018_v3",
                      "drop_labels": ["infiltration"], "clean_labels": 2},
    "nf_unsw_nb15": {"processed_dir": "data/processed/nf_unsw_nb15_v3", "drop_labels": [],
                     "clean_labels": 0},
}  # fmt: skip
SPLITS = {
    "episode": {"protocol": "episode", "block_minutes": 30, "purge_seconds": 150,
                "fractions": [0.6, 0.2, 0.2]},
    "chronological": {"protocol": "chronological", "purge_seconds": 150,
                      "fractions": [0.6, 0.2, 0.2]},
}  # fmt: skip


def main() -> None:
    out = {}
    for name, ds in DATASETS.items():
        frames = {}
        for sname, split in SPLITS.items():
            p = prepare({"seed": 42, "data": ds, "feature_set": "nf_portable", "split": split,
                         "task": "binary"})  # fmt: skip
            frames[sname] = p.frame.select("day", "row_id", "label", "family", "sample_weight",
                                           pl.col("split").alias(f"split_{sname}"))  # fmt: skip
        df = frames["episode"].join(frames["chronological"].select("day", "row_id",
                                                                  "split_chronological"),
                                    on=["day", "row_id"], how="inner")  # fmt: skip
        both = df.filter((pl.col("split_episode") == "test")
                         & (pl.col("split_chronological") == "test"))  # fmt: skip
        cross = df.group_by("split_episode", "split_chronological").len().sort("len")

        def fam(d: pl.DataFrame) -> dict[str, int]:
            rows = d.group_by("family").len().sort("len", descending=True).to_dicts()
            return {r["family"]: int(r["len"]) for r in rows}

        out[name] = {
            "rows_non_purged_in_both": df.height,
            "cross_tab": cross.to_dicts(),
            "intersection_rows": both.height,
            "intersection_families_sampled_rows": fam(both),
            "episode_test_families_sampled_rows": fam(df.filter(pl.col("split_episode") == "test")),
            "intersection_days": sorted(both["day"].unique().to_list()),
        }
        print(name, json.dumps(out[name]["intersection_families_sampled_rows"]), flush=True)
    path = Path("reports/audit/nf_test_overlap.json")
    path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
