"""Reproducible EDA and leakage audit over the ingested per-day Parquet files.

Writes `reports/eda/eda.json`, `reports/eda/EDA.md` and figures. Works day-by-day with lazy
scans so peak memory stays bounded (the 2018-02-20 day alone has ~8M flows)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from netsentinel.features.context import event_seconds

log = logging.getLogger(__name__)
EXCEL_ROW_LIMIT = 1_048_575  # 2**20 - 1 data rows under one header
NON_FEATURES = {"row_id", "timestamp", "label", "family", "day", "flow_id", "src_ip", "dst_ip",
                "src_port"}  # fmt: skip


def hash_sample(lf: pl.LazyFrame, n_target: int, seed: int) -> pl.LazyFrame:
    """Deterministic ~uniform sample of about `n_target` rows without materialising the frame."""
    n = lf.select(pl.len()).collect().item()
    if n <= n_target:
        return lf
    modulus = 1_000_000
    keep = int(modulus * n_target / n)
    return lf.filter(pl.col("row_id").hash(seed=seed) % modulus < keep)


def _numeric_cols(schema: pl.Schema) -> list[str]:
    return [c for c, t in schema.items() if c not in NON_FEATURES and t.is_numeric()]


def day_profile(path: Path) -> dict[str, Any]:
    lf = pl.scan_parquet(path)
    schema = lf.collect_schema()
    num = _numeric_cols(schema)
    day = path.stem
    basic = lf.select(
        pl.len().alias("rows"),
        pl.col("timestamp").min().alias("ts_min"),
        pl.col("timestamp").max().alias("ts_max"),
        (pl.col("timestamp").dt.date().cast(pl.Utf8) != pl.lit(day)).sum().alias("rows_off_day"),
        (pl.col("flow_duration") < 0).sum().alias("negative_duration"),
        pl.col("src_ip").is_not_null().any().alias("has_ips"),
    ).collect()
    row = basic.row(0, named=True)
    nonfinite = (
        lf.select(
            [pl.col(c).cast(pl.Float64).is_nan().sum().alias(f"nan::{c}") for c in num]
            + [pl.col(c).cast(pl.Float64).is_infinite().sum().alias(f"inf::{c}") for c in num]
            + [(pl.col(c) < 0).sum().alias(f"neg::{c}") for c in num]
        )
        .collect()
        .row(0, named=True)
    )
    labels = lf.group_by("label").agg(
        pl.len().alias("rows"),
        pl.col("timestamp").min().alias("first"),
        pl.col("timestamp").max().alias("last"),
        pl.col("dst_port").mode().first().alias("top_dst_port"),
        (pl.col("dst_port").value_counts(sort=True).first().struct.field("count") / pl.len()).alias(
            "top_port_share"
        ),
        pl.col("protocol").mode().first().alias("top_protocol"),
    )
    labels = labels.collect().sort("rows", descending=True)
    # Exact duplicates over all feature columns: count and label conflicts. A 64-bit row hash
    # keeps memory at 8 bytes/row instead of hashing 76 columns in the group-by table.
    dup = (
        lf.select(pl.struct(num).hash(seed=0).alias("h"), "label")
        .group_by("h")
        .agg(pl.len().alias("n"), pl.col("label").n_unique().alias("n_labels"))
        .filter(pl.col("n") > 1)
        .select(
            (pl.col("n") - 1).sum().alias("duplicate_rows"),
            (pl.col("n_labels") > 1).sum().alias("conflicting_groups"),
        )
        .collect()
        .row(0, named=True)
    )
    return {
        "day": day,
        "rows": row["rows"],
        "excel_truncated": row["rows"] == EXCEL_ROW_LIMIT,
        "ts_min": str(row["ts_min"]),
        "ts_max": str(row["ts_max"]),
        "rows_off_day": row["rows_off_day"],
        "negative_duration": row["negative_duration"],
        "has_ips": row["has_ips"],
        "nonfinite": {k: v for k, v in nonfinite.items() if v},
        "labels": [
            {**r, "first": str(r["first"]), "last": str(r["last"])}
            for r in labels.iter_rows(named=True)
        ],
        "duplicates": dup,
    }


def constant_columns(paths: list[Path]) -> list[str]:
    lf = pl.concat([pl.scan_parquet(p) for p in paths], how="vertical_relaxed")
    num = _numeric_cols(lf.collect_schema())
    stats = (
        lf.select([(pl.col(c).max() == pl.col(c).min()).alias(c) for c in num])
        .collect()
        .row(0, named=True)
    )
    return sorted(c for c, is_const in stats.items() if is_const)


def _auc(score: np.ndarray, y: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score

    score = np.nan_to_num(score.astype(np.float64), nan=0.0, posinf=1e12, neginf=-1e12)
    return float(roc_auc_score(y, score))


def univariate_auc(paths: list[Path], per_day: int, seed: int) -> list[dict[str, Any]]:
    """Benign-vs-attack ROC-AUC of each single feature on a uniform per-day sample.

    |AUC - 0.5| close to 0.5 for a single raw field is a red flag for shortcut features."""
    df = pl.concat(
        [hash_sample(pl.scan_parquet(p), per_day, seed).collect() for p in paths],
        how="vertical_relaxed",
    )
    y = (df["label"] != "benign").to_numpy().astype(int)
    out = []
    for c in _numeric_cols(df.schema):
        col = df[c].to_numpy()
        if np.nanmin(col) == np.nanmax(col):
            continue
        auc = _auc(col, y)
        out.append({"feature": c, "auc": auc, "separation": abs(auc - 0.5) * 2})
    return sorted(out, key=lambda r: -r["separation"])


def ip_leakage(path: Path) -> dict[str, Any] | None:
    """On the only day with IPs: how well does the source IP alone identify attacks?"""
    lf = pl.scan_parquet(path)
    if not lf.select(pl.col("src_ip").is_not_null().any()).collect().item():
        return None
    by_ip = (
        lf.group_by("src_ip")
        .agg(pl.len().alias("rows"), (pl.col("label") != "benign").mean().alias("attack_frac"))
        .collect()
    )
    attack_ips = by_ip.filter(pl.col("attack_frac") > 0).sort("rows", descending=True)
    pure = attack_ips.filter(pl.col("attack_frac") > 0.99)
    totals = lf.select((pl.col("label") != "benign").sum().alias("attacks")).collect().item()
    pure_rows = (
        lf.join(pure.lazy().select("src_ip"), on="src_ip", how="semi")
        .select((pl.col("label") != "benign").sum())
        .collect()
        .item()
    )
    return {
        "day": path.stem,
        "distinct_src_ips": by_ip.height,
        "src_ips_with_attacks": attack_ips.height,
        "src_ips_99pct_attack": pure.height,
        "attack_rows_from_99pct_ips": int(pure_rows),
        "attack_rows_total": int(totals),
    }


def attack_timeline_figure(paths: list[Path], out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(len(paths), 1, figsize=(11, 1.25 * len(paths)), sharex=False)
    axes = np.atleast_1d(axes)
    for ax, p in zip(axes, paths, strict=True):
        per_min = (
            pl.scan_parquet(p)
            .with_columns(event_seconds())
            .with_columns(((pl.col("event_sec") // 60) * 60).alias("minute"))
            .group_by("minute", "label")
            .agg(pl.len().alias("n"))
            .collect()
            .sort("minute")
        )
        t0 = per_min["minute"].min()
        for lab in sorted(per_min["label"].unique()):
            sub = per_min.filter(pl.col("label") == lab)
            hours = (sub["minute"].to_numpy() - t0) / 3600
            ax.plot(hours, sub["n"].to_numpy(), lw=0.8, label=lab)
        ax.set_yscale("log")
        ax.set_ylabel(p.stem, rotation=0, ha="right", fontsize=8)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=6, loc="upper right", ncol=4, frameon=False)
    axes[-1].set_xlabel("hours since first flow of the day (event time)")
    fig.suptitle("Flows per minute by label (log scale) - CSE-CIC-IDS2018", fontsize=10)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def class_distribution_figure(profiles: list[dict], out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    totals: dict[str, int] = {}
    for p in profiles:
        for r in p["labels"]:
            totals[r["label"]] = totals.get(r["label"], 0) + r["rows"]
    items = sorted(totals.items(), key=lambda kv: kv[1])
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh([k for k, _ in items], [v for _, v in items], color="#4C72B0")
    ax.set_xscale("log")
    ax.set_xlabel("flows (log scale)")
    ax.set_title("Label distribution, all 10 days")
    for i, (_, v) in enumerate(items):
        ax.text(v, i, f" {v:,}", va="center", fontsize=7)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def run_eda(interim_dir: str | Path, out_dir: str | Path, auc_per_day: int, seed: int) -> dict:
    interim_dir, out_dir = Path(interim_dir), Path(out_dir)
    paths = sorted(interim_dir.glob("2018-*.parquet"))
    if not paths:
        raise FileNotFoundError(f"no ingested days in {interim_dir}; run `netsentinel data ingest`")
    out_dir.mkdir(parents=True, exist_ok=True)
    profiles = []
    for p in paths:
        log.info("profiling %s", p.name)
        profiles.append(day_profile(p))
    result = {
        "days": profiles,
        "constant_columns": constant_columns(paths),
        "univariate_auc": univariate_auc(paths, auc_per_day, seed),
        "ip_leakage": [r for p in paths if (r := ip_leakage(p))],
        "auc_sample_per_day": auc_per_day,
        "seed": seed,
    }
    (out_dir / "eda.json").write_text(json.dumps(result, indent=2, default=str), "utf-8")
    class_distribution_figure(profiles, out_dir / "label_distribution.png")
    attack_timeline_figure(paths, out_dir / "attack_timeline.png")
    return result
