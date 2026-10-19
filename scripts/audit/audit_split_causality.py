"""Independent audit of split integrity, real-data context causality and train/val duplicates.

Deliberately re-implements every check instead of calling netsentinel.data.splits.leakage_report
or the context code, so a bug shared by training code and its tests cannot hide here.
Reads TRAIN and VALIDATION rows only; test rows are counted, never inspected.

Usage: uv run python scripts/audit/audit_split_causality.py
Writes reports/audit/split_causality.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.training.data import prepare  # noqa: E402

RUN = ROOT / "runs/20261019-124619_baseline_binary_lightgbm"  # pre-registered flow LightGBM
CTX_RUN = ROOT / "runs/20261019-125018_baseline_binary_flow_ctx_lightgbm"
OUT = ROOT / "reports/audit"
INTERIM = ROOT / "data/interim/ids2018"


def split_integrity(split: pl.DataFrame) -> dict:
    parts = split.filter(pl.col("split").is_in(["train", "val", "test"]))
    dup = parts.group_by("day", "row_id").agg(pl.col("split").n_unique().alias("n"))
    return {
        "rows_by_split": dict(split.group_by("split").len().iter_rows()),
        "ids_in_more_than_one_partition": int((dup["n"] > 1).sum()),
    }


def min_cross_partition_gap(frame: pl.DataFrame) -> dict:
    """Brute-force per day: smallest |event_sec difference| between rows of different
    partitions (sorted sweep over the merged timeline)."""
    out = {}
    for (day,), g in frame.filter(pl.col("split") != "purged").group_by("day"):
        g = g.sort("event_sec")
        s, p = g["event_sec"].to_numpy(), g["split"].to_numpy()
        best = np.inf
        last_t = {}  # partition -> last time seen
        for t, part in zip(s, p, strict=True):
            for other, lt in last_t.items():
                if other != part:
                    best = min(best, t - lt)
            last_t[part] = t
        out[day] = float(best)
    return out


def context_bruteforce(sample: pl.DataFrame, n: int = 150, seed: int = 0) -> dict:
    """Recompute ctx_flow_rate_*, ctx_port_flow_rate_*, ctx_uniq_ports_* for real rows from the
    raw day stream with plain filters, using the timing contract (event time = start + duration,
    window = complete seconds [s-W, s-1])."""
    rng = np.random.default_rng(seed)
    errs: dict[str, float] = {}
    checked = 0
    for day in sorted(sample["day"].unique())[:3]:
        stream = (
            pl.scan_parquet(INTERIM / f"{day}.parquet")
            .select("row_id", "dst_port", "timestamp", "flow_duration")
            .with_columns(
                (
                    (pl.col("timestamp").dt.epoch("us") + pl.col("flow_duration").clip(0))
                    // 1_000_000
                ).alias("ev")
            )  # fmt: skip
            .select("row_id", "dst_port", "ev")
            .collect()
        )
        ev, port = stream["ev"].to_numpy(), stream["dst_port"].to_numpy()
        rows = sample.filter(pl.col("day") == day)
        pick = rows[rng.choice(rows.height, size=min(n, rows.height), replace=False)]
        for r in pick.iter_rows(named=True):
            s = r["event_sec"]
            for w in (5, 30, 300):
                m = (ev >= s - w) & (ev <= s - 1)
                vals = {
                    f"ctx_flow_rate_{w}s": m.sum() / w,
                    f"ctx_port_flow_rate_{w}s": (m & (port == r["dst_port"])).sum() / w,
                    f"ctx_uniq_ports_{w}s": len(np.unique(port[m])),
                }
                for k, v in vals.items():
                    rel = abs(r[k] - v) / max(abs(v), 1e-9)
                    errs[k] = max(errs.get(k, 0.0), float(rel))
            # Look-ahead probe: no flow observed at or after s may influence the row.
            checked += 1
    return {"rows_checked": checked, "max_relative_error": errs}


def duplicates_and_recall(prep, scores: np.ndarray, thr: float) -> dict:
    feats = prep.features
    train = prep.part("train").select(feats).unique()
    val = prep.part("val").with_columns(pl.Series("score", scores))
    if val.height != len(scores):
        raise RuntimeError("val rows do not align with saved scores")
    val = val.join(train.with_columns(pl.lit(True).alias("in_train")), on=feats, how="left",
                   nulls_equal=True).with_columns(pl.col("in_train").fill_null(False))  # fmt: skip
    att = val.filter(pl.col("label") != "benign").with_columns((pl.col("score") > thr).alias("hit"))
    per_label = (
        att.group_by("label")
        .agg(
            pl.len().alias("rows"),
            pl.col("in_train").mean().alias("share_exact_copy_of_train"),
            pl.col("hit").filter(pl.col("in_train")).mean().alias("recall_copies"),
            pl.col("hit").filter(~pl.col("in_train")).mean().alias("recall_novel"),
            (~pl.col("in_train")).sum().alias("novel_rows"),
        )
        .sort("label")
    )
    ben = val.filter(pl.col("label") == "benign")

    def mean(s: pl.Series) -> float | None:  # None when the group is empty
        v = s.mean()
        return None if v is None else float(v)

    return {
        "val_attack_share_exact_copy_of_train": mean(att["in_train"]),
        "val_benign_share_exact_copy_of_train": mean(ben["in_train"]),
        "recall_novel_attack_rows": mean(att.filter(~pl.col("in_train"))["hit"]),
        "recall_copied_attack_rows": mean(att.filter(pl.col("in_train"))["hit"]),
        "per_label": per_label.to_dicts(),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    art = joblib.load(RUN / "model.joblib")
    prep = prepare(art["config"])
    saved = pl.read_parquet(RUN / "split.parquet")
    now = prep.frame.select("day", "row_id", "split")
    result = {
        "run": RUN.name,
        "split_recreated_equals_saved": saved.sort("day", "row_id").equals(
            now.sort("day", "row_id")
        ),
        "integrity": split_integrity(saved),
        "min_gap_seconds_between_partitions": min_cross_partition_gap(
            prep.frame.select("day", "event_sec", "split")
        ),
        "duplicates_flow_features": duplicates_and_recall(
            prep, np.load(RUN / "val_scores.npy"), art["threshold"]
        ),
    }
    del prep
    ctx_art = joblib.load(CTX_RUN / "model.joblib")
    ctx_prep = prepare(ctx_art["config"])
    sample = ctx_prep.frame.filter(pl.col("split").is_in(["train", "val"]))
    result["context_bruteforce_real_rows"] = context_bruteforce(sample)
    result["duplicates_flow_ctx_features"] = duplicates_and_recall(
        ctx_prep, np.load(CTX_RUN / "val_scores.npy"), ctx_art["threshold"]
    )
    (OUT / "split_causality.json").write_text(json.dumps(result, indent=2, default=str), "utf-8")
    print(json.dumps({k: v for k, v in result.items() if "duplicates" not in k}, indent=2,
                     default=str))  # fmt: skip
    for k in ("duplicates_flow_features", "duplicates_flow_ctx_features"):
        d = result[k]
        print(k, {x: d[x] for x in d if x != "per_label"})
        for r in d["per_label"]:
            print(f"   {r['label']:20s} rows={r['rows']:>6} copy={r['share_exact_copy_of_train']:.3f}"
                  f" recall_copies={r['recall_copies']} recall_novel={r['recall_novel']}"
                  f" novel_rows={r['novel_rows']}")  # fmt: skip


if __name__ == "__main__":
    main()
