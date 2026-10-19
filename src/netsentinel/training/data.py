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


# Label cleaning v1 (see docs/datasets/cse_cic_ids2018.md, "Label quality"): attack labels that
# by definition are HTTP over TCP/80 but sit on other protocols/ports are documented labelling
# errors (e.g. 151/362 web brute-force flows on 2018-02-23 are UDP/500, DHCP, protocol 0).
HTTP_ATTACKS = ("web_bruteforce", "web_xss", "web_sql_injection", "ddos_loic_http")
# FTP-BruteForce (02-14) and DoS-SlowHTTPTest (02-16) share 52 distinct feature vectors covering
# >99.99 % of both classes: both are failed connections to closed port 21. For attack-type tasks
# they are one class.
MERGED_LABELS = {"ftp_bruteforce": "port21_failed_conn", "dos_slowhttptest": "port21_failed_conn"}


def clean_labels(df: pl.DataFrame) -> tuple[pl.DataFrame, dict[str, int]]:
    bad = pl.col("label").is_in(list(HTTP_ATTACKS)) & ~(
        (pl.col("protocol") == 6) & (pl.col("dst_port") == 80)
    )
    dropped = df.filter(bad).group_by("label").agg(pl.len()).to_dicts()
    return df.filter(~bad), {r["label"]: int(r["len"]) for r in dropped}


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
    cleaning: dict[str, int] = {}
    if cfg["data"].get("clean_labels", True):
        df, cleaning = clean_labels(df)
        log.info("label cleaning v1 dropped (sampled rows): %s", cleaning)
    if cfg.get("task") in ("label", "attack_type"):
        df = df.with_columns(pl.col("label").replace(MERGED_LABELS))
    df = add_derived(df)
    scfg = split_config(cfg)
    df = df.join(make_split(df, scfg), on=["day", "row_id"], how="left")
    rep = leakage_report(
        df, block_minutes=scfg.block_minutes if scfg.protocol == "blocked" else None
    )
    if scfg.protocol in ("blocked", "chronological", "episode") and not rep.ok(scfg.purge_seconds):
        raise RuntimeError(f"leakage check failed: {rep}")
    coverage = split_coverage(df)
    kept = df.filter(pl.col("split") != "purged")
    log.info(
        "prepared %d rows (%d purged), %d features, protocol=%s",
        kept.height, df.height - kept.height, len(features), scfg.protocol,
    )  # fmt: skip
    leakage = {**asdict(rep), "label_cleaning_dropped_sampled_rows": cleaning}
    return Prepared(kept, features, scfg, leakage, coverage)
