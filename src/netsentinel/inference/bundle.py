"""Deployable model bundle: threat (binary) + attack-type (multiclass) + anomaly models,
an evidence model (robust per-feature baselines of benign train traffic), decision thresholds
and version metadata, with SHA-256 integrity checks on load.

Layout:  models/<bundle_id>/bundle.joblib + manifest.json (hashes, versions, source runs)
Loading verifies the file hash against the manifest and the feature-schema version against
the running code; any mismatch refuses to load (tampering / incompatible artifact).
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import polars as pl

from netsentinel import __version__
from netsentinel.features.schema import FEATURE_SCHEMA_VERSION
from netsentinel.ledger import file_sha256, git_sha
from netsentinel.models.anomaly import RobustZ
from netsentinel.models.decision import DecisionThresholds
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


def _load_run(run_dir: str | Path, expect_task: set[str]) -> dict[str, Any]:
    run_dir = Path(run_dir)
    art = joblib.load(run_dir / "model.joblib")
    if art["task"] not in expect_task:
        raise ValueError(f"{run_dir}: task {art['task']!r}, expected one of {sorted(expect_task)}")
    if art["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
        raise ValueError(f"{run_dir}: feature schema {art['feature_schema_version']} != code")
    art["source_run"] = run_dir.name
    return art


def build_bundle(
    out_dir: str | Path,
    threat_run: str | Path,
    anomaly_run: str | Path,
    type_run: str | Path | None = None,
    attack_type_threshold: float = 0.6,
    evidence_rows: int = 50_000,
) -> Path:
    threat = _load_run(threat_run, {"binary"})
    anomaly = _load_run(anomaly_run, {"anomaly"})
    attack_type = _load_run(type_run, {"label", "family"}) if type_run else None

    # Evidence baselines: robust median/MAD of BENIGN TRAIN flows from the threat run's split.
    prep = prepare(threat["config"])
    benign = prep.part("train").filter(pl.col("label") == "benign")
    benign = benign.sample(n=min(evidence_rows, benign.height), seed=threat["config"]["seed"])
    ev_features = [f for f in threat["features"] if not f.startswith(("proto_", "port_class"))]
    evidence = RobustZ().fit(benign.select(ev_features).to_numpy().astype(np.float32))

    # Probability calibration: isotonic map raw score -> P(malicious), fit on the threat run's
    # VALIDATION rows with prevalence weights (training used balanced class weights, so raw
    # scores are not probabilities). Judged on the untouched test split in the final report.
    from sklearn.isotonic import IsotonicRegression

    val = prep.part("val")
    raw_val = threat["model"].predict_proba(
        val.select(threat["features"]).to_numpy().astype(np.float32)
    )[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(
        raw_val, (val["label"] != "benign").to_numpy().astype(float),
        sample_weight=val["sample_weight"].to_numpy(),
    )  # fmt: skip
    threat["calibrator"] = calibrator
    threat["calibration"] = "isotonic on validation, prevalence-weighted"

    thresholds = DecisionThresholds(
        threat=float(threat["threshold"]),
        attack_type=attack_type_threshold,
        anomaly=float(anomaly["threshold"]),
    )
    bundle_id = f"bundle-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    out = Path(out_dir) / bundle_id
    out.mkdir(parents=True, exist_ok=False)
    payload = {
        "threat": threat,
        "anomaly": anomaly,
        "attack_type": attack_type,
        "evidence": {"model": evidence, "features": ev_features},
        "thresholds": asdict(thresholds),
    }
    joblib.dump(payload, out / "bundle.joblib", compress=3)
    manifest = {
        "bundle_id": bundle_id,
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "netsentinel_version": __version__,
        "git": git_sha(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "sha256": {"bundle.joblib": file_sha256(out / "bundle.joblib")},
        "components": {
            "threat": {
                "run": threat["source_run"],
                "features": threat["config"]["feature_set"],
                "threshold_rule": threat.get("threshold_rule"),
            },
            "anomaly": {
                "run": anomaly["source_run"],
                "threshold_rule": anomaly.get("threshold_rule"),
            },
            "attack_type": {"run": attack_type["source_run"]} if attack_type else None,
        },  # fmt: skip
        "thresholds": asdict(thresholds),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), "utf-8")
    log.info("built %s", out)
    return out


def load_bundle(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (payload, manifest) after integrity and compatibility checks."""
    path = Path(path)
    manifest_path = path / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"no manifest.json in {path}")
    manifest = json.loads(manifest_path.read_text("utf-8"))
    actual = file_sha256(path / "bundle.joblib")
    if actual != manifest["sha256"]["bundle.joblib"]:
        raise RuntimeError(f"{path}: bundle.joblib hash mismatch (tampered or corrupted)")
    if manifest["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
        raise RuntimeError(
            f"{path}: built for feature schema {manifest['feature_schema_version']}, "
            f"code has {FEATURE_SCHEMA_VERSION}"
        )
    # joblib/pickle executes code on load: only bundles whose hash matched a manifest written
    # by `build_bundle` in a trusted location should ever be loaded (see docs/security).
    return joblib.load(path / "bundle.joblib"), manifest
