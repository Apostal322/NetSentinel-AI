"""Shared data preparation for all training stages: load -> derive -> split -> matrices."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import polars as pl

from netsentinel.data.splits import SplitConfig, leakage_report, make_split, split_coverage
from netsentinel.features.build import load_dataset
from netsentinel.features.schema import add_derived, feature_set

log = logging.getLogger(__name__)
META_COLS = ["day", "row_id", "event_sec", "label", "family", "sample_weight", "dst_port",
             "protocol"]  # fmt: skip


@dataclass
class Prepared:
    frame: pl.DataFrame  # all non-purged rows with `split`
    features: list[str]
    split_cfg: SplitConfig
    leakage: dict[str, Any]
    coverage: pl.DataFrame

    def part(self, name: str) -> pl.DataFrame:
        return self.frame.filter(pl.col("split") == name)

    def xy(self, name: str, target: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        df = self.part(name)
        X = df.select(self.features).to_numpy().astype(np.float32)  # noqa: N806
        if target == "binary":
            y = (df["label"] != "benign").to_numpy().astype(int)
        else:
            y = df[target].to_numpy()
        return X, y, df["sample_weight"].to_numpy()


def split_config(cfg: dict[str, Any]) -> SplitConfig:
    s = dict(cfg.get("split", {}))
    if "fractions" in s:
        s["fractions"] = tuple(s["fractions"])
    for k in ("test_days", "val_days"):
        if k in s:
            s[k] = tuple(s[k] or ())
    return SplitConfig(seed=cfg.get("seed", 42), **s)


def prepare(cfg: dict[str, Any]) -> Prepared:
    features = feature_set(cfg["feature_set"])
    cols = list(dict.fromkeys(META_COLS + [c for c in features if c not in
                                           ("proto_tcp", "proto_udp", "proto_other",
                                            "port_class")]))  # fmt: skip
    df = load_dataset(cfg["data"]["processed_dir"], columns=cols)
    days = cfg["data"].get("days")
    if days:
        df = df.filter(pl.col("day").is_in(list(days)))
    labels = cfg["data"].get("drop_labels") or []
    if labels:
        df = df.filter(~pl.col("label").is_in(list(labels)))
    df = add_derived(df)
    scfg = split_config(cfg)
    df = df.join(make_split(df, scfg), on=["day", "row_id"], how="left")
    rep = leakage_report(
        df, block_minutes=scfg.block_minutes if scfg.protocol == "blocked" else None
    )
    if scfg.protocol in ("blocked", "chronological") and not rep.ok(scfg.purge_seconds):
        raise RuntimeError(f"leakage check failed: {rep}")
    coverage = split_coverage(df)
    kept = df.filter(pl.col("split") != "purged")
    log.info(
        "prepared %d rows (%d purged), %d features, protocol=%s",
        kept.height, df.height - kept.height, len(features), scfg.protocol,
    )  # fmt: skip
    return Prepared(kept, features, scfg, asdict(rep), coverage)
