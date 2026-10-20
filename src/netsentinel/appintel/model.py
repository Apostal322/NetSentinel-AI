"""Application intelligence: a versioned, abstaining flow classifier for the nDPI master
protocol, plus explicitly separated label semantics.

Output fields (never conflated):
* transport          - IP protocol (tcp / udp / icmp / other), observed.
* app_protocol       - ML prediction of the nDPI *master* protocol (e.g. dns, http, tls), or
                       null with an `app_status` reason. A PROXY label: the model learned to
                       reproduce nDPI's DPI output on NF-v3 training traffic (nDPI version of
                       the training labels undocumented; names from nDPI 4.8).
* service_category   - IANA-port heuristic (`models.service`), labelled `port_heuristic`.
* application_identity - always null: no validated source of application identity (e.g.
                       which browser or SaaS product inside TLS) exists in this system.

`app_status`: predicted | low_confidence | out_of_distribution | missing_features |
unsupported_protocol. The confidence threshold is chosen on validation data (target accepted
accuracy); `app_confidence` is the model's top-class probability, NOT a calibrated
probability of correctness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import polars as pl

from netsentinel.features.schema import add_derived
from netsentinel.ledger import file_sha256, git_sha

APP_SCHEMA_VERSION = "appintel-1.0.0"
TRANSPORT = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}
SUPPORTED_PROTOCOLS = (6, 17)


@dataclass
class AppClassifier:
    model: Any
    features: list[str]
    classes: list[str]
    feature_set: str
    confidence_threshold: float
    ood_low: np.ndarray
    ood_high: np.ndarray
    ood_max_fraction: float = 0.3
    metadata: dict[str, Any] = field(default_factory=dict)

    def predict(self, df: pl.DataFrame) -> pl.DataFrame:
        """Canonical flow frame -> app columns (same row order)."""
        if "protocol" not in df.columns:
            raise ValueError("flow frame lacks 'protocol'")
        need_derived = any(f in ("proto_tcp", "proto_udp", "proto_other", "port_class")
                           for f in self.features) and "port_class" not in df.columns  # fmt: skip
        if need_derived:
            df = add_derived(df)
        proto = df["protocol"].cast(pl.Int64).to_numpy()
        absent = [f for f in self.features if f not in df.columns]
        X = np.full((df.height, len(self.features)), np.nan, dtype=np.float32)  # noqa: N806
        present = [i for i, f in enumerate(self.features) if f not in absent]
        if present:
            cols = [pl.col(self.features[i]).cast(pl.Float32) for i in present]
            X[:, present] = df.select(cols).to_numpy()
        missing_row = np.isnan(X).any(axis=1)
        proba = self.model.predict_proba(X)  # LightGBM handles NaN as in training
        top = proba.argmax(axis=1)
        conf = proba.max(axis=1)
        out_frac = ((X < self.ood_low) | (X > self.ood_high)).mean(axis=1)
        status = np.full(df.height, "predicted", dtype=object)
        status[conf < self.confidence_threshold] = "low_confidence"
        status[out_frac > self.ood_max_fraction] = "out_of_distribution"
        status[missing_row] = "missing_features"
        status[~np.isin(proto, SUPPORTED_PROTOCOLS)] = "unsupported_protocol"
        label = np.asarray(self.classes, dtype=object)[top]
        label = np.where(status == "predicted", label, None)
        return pl.DataFrame({
            "transport": [TRANSPORT.get(int(p), "other") for p in proto],
            "app_protocol": label.tolist(),
            "app_confidence": conf.astype(float),
            "app_status": status.tolist(),
            # top class regardless of abstention: evaluation only, never shown as a prediction
            "app_top_class": np.asarray(self.classes, dtype=object)[top].tolist(),
        })  # fmt: skip


def save_classifier(clf: AppClassifier, out_dir: str | Path, *, extra: dict | None = None) -> Path:
    cid = f"appid-{clf.feature_set}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    out = Path(out_dir) / cid
    out.mkdir(parents=True, exist_ok=False)
    joblib.dump(clf, out / "classifier.joblib", compress=3)
    manifest = {
        "classifier_id": cid,
        "schema_version": APP_SCHEMA_VERSION,
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "feature_set": clf.feature_set,
        "features": clf.features,
        "classes": clf.classes,
        "confidence_threshold": clf.confidence_threshold,
        "label_semantics": "nDPI master protocol (proxy label from NF-v3 L7_PROTO; nDPI "
                           "version undocumented; names from nDPI 4.8)",
        "application_identity": "not provided (no validated source)",
        "git": git_sha(),
        **clf.metadata,
        **(extra or {}),
        "sha256": {"classifier.joblib": file_sha256(out / "classifier.joblib")},
    }  # fmt: skip
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str), "utf-8")
    return out


def load_classifier(path: str | Path) -> tuple[AppClassifier, dict]:
    path = Path(path)
    mf = path / "manifest.json"
    if not mf.exists():
        raise FileNotFoundError(f"{mf} missing: not an application classifier artifact")
    manifest = json.loads(mf.read_text("utf-8"))
    if manifest.get("schema_version") != APP_SCHEMA_VERSION:
        raise ValueError(f"classifier schema {manifest.get('schema_version')} != "
                         f"{APP_SCHEMA_VERSION}")  # fmt: skip
    if file_sha256(path / "classifier.joblib") != manifest["sha256"]["classifier.joblib"]:
        raise ValueError("classifier artifact hash mismatch (corrupted or modified); refusing")
    clf = joblib.load(path / "classifier.joblib")
    if not isinstance(clf, AppClassifier) or clf.features != manifest["features"]:
        raise ValueError("classifier artifact content does not match its manifest")
    return clf, manifest
