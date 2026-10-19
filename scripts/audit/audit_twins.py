"""Cross-label exact-duplicate audit: for every pair of attack labels, the share of each label's
rows whose exact flow feature vector (schema flow features + dst_port + protocol) also occurs
under the other label. High overlap = twin classes that break leave-one-family-out protocols.
Full ingested data (not the sample); labels only, no model.

Usage: uv run python scripts/audit/audit_twins.py -> reports/audit/twins.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.features.schema import raw_flow_columns  # noqa: E402

FEATS = [*raw_flow_columns(), "dst_port", "protocol"]


def main() -> None:
    parts = []
    for p in sorted((ROOT / "data/interim/ids2018").glob("2018-*.parquet")):
        parts.append(
            pl.scan_parquet(p)
            .filter(pl.col("label") != "benign")
            .select(pl.struct(FEATS).hash(seed=0).alias("h"), "label")
            .collect()
        )
    df = pl.concat(parts)
    sets = {lab: set(g["h"].unique().to_list()) for (lab,), g in df.group_by("label")}
    counts = {lab: g for (lab,), g in df.group_by("label")}
    out = []
    for a in sorted(sets):
        for b in sorted(sets):
            if a == b:
                continue
            shared = sets[a] & sets[b]
            if not shared:
                continue
            rows_a = counts[a]["h"].is_in(list(shared)).sum()
            out.append({"label": a, "other": b, "shared_vectors": len(shared),
                        "share_of_label_rows": float(rows_a / counts[a].height)})  # fmt: skip
    out.sort(key=lambda r: -r["share_of_label_rows"])
    (ROOT / "reports/audit/twins.json").write_text(json.dumps(out, indent=2), "utf-8")
    for r in out[:20]:
        print(
            f"{r['label']:18s} <- {r['other']:18s} shared={r['shared_vectors']:>6} "
            f"rows={r['share_of_label_rows']:.4f}"
        )


if __name__ == "__main__":
    main()
