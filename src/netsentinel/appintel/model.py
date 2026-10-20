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
unsupported_protocol | port_ml_conflict. The confidence threshold is chosen on validation data
(target accepted accuracy); `app_confidence` is the model's top-class probability, NOT a
calibrated probability of correctness.

Phase 7 conservative policy (schema 1.1, `resolve_policy`): a (protocol, port) pair is
"port-supported" when the TRAINING data map it to one protocol label with purity >=
`min_purity` and support >= `min_support`. Then:
  ML agrees with the port label        -> that label, `app_method = ml_port_agree`
  ML disagrees / abstains, conflict=port -> the port label, `app_method = port_estimate`
  ML disagrees / abstains, conflict=unknown -> no label, status `port_ml_conflict`
Without port support the ML label is used only if the ML itself did not abstain
(`app_method = ml`). Motivation: the portable model only sees a coarse port class, so on CTU
it called long HTTP-on-port-80 flows TLS with ~0.97 confidence (docs/phase7/RELIABILITY.md).
Policy parameters are selected on NF development validation data, never on CTU.
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

APP_SCHEMA_VERSION = "appintel-1.1.0"  # 1.1: port table + conservative policy
COMPATIBLE_SCHEMAS = ("appintel-1.0.0", APP_SCHEMA_VERSION)
NON_INFORMATIVE = ("other", "unknown")
DEFAULT_POLICY = {"min_purity": 0.95, "min_support": 50, "conflict": "port"}
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
    port_table: dict[int, dict] = field(default_factory=dict)  # proto*65536+port -> stats
    policy: dict[str, Any] = field(default_factory=dict)

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
        top_label = np.asarray(self.classes, dtype=object)[top]
        ml_label = np.where(status == "predicted", top_label, None)
        port = df["dst_port"].cast(pl.Int64).to_numpy() if "dst_port" in df.columns else (
            np.full(df.height, -1))  # fmt: skip
        table = getattr(self, "port_table", None) or {}
        policy = {**DEFAULT_POLICY, **(getattr(self, "policy", None) or {})}
        label, method, status2, evidence = resolve_policy(
            ml_label, top_label, conf, status, proto, port, table, policy)  # fmt: skip
        return pl.DataFrame({
            "transport": [TRANSPORT.get(int(p), "other") for p in proto],
            "app_protocol": label,
            "app_confidence": conf.astype(float),
            "app_status": status2,
            "app_method": method,
            "app_ml_class": ml_label.tolist(),
            "app_evidence": evidence,
            # top class regardless of abstention: evaluation only, never shown as a prediction
            "app_top_class": top_label.tolist(),
        }, schema_overrides={"app_evidence": pl.List(pl.Utf8)})  # fmt: skip


def port_support(table: dict[int, dict], proto: int, port: int, policy: dict) -> str | None:
    e = table.get(int(proto) * 65536 + int(port))
    if not e or e["label"] in NON_INFORMATIVE:
        return None
    if e["support"] >= policy["min_support"] and e["purity"] >= policy["min_purity"]:
        return e["label"]
    return None


def resolve_policy(ml_label, top_label, conf, ml_status, proto, port, table, policy):
    """Combine the ML prediction with training-data port evidence (see module docstring).
    Returns (label, method, status, evidence) lists, one entry per flow."""
    labels, methods, statuses, evidence = [], [], [], []
    for ml, top, c, st, pr, po in zip(ml_label, top_label, conf, ml_status, proto, port,
                                      strict=True):  # fmt: skip
        ev = [f"ml:{top}@{c:.2f}" + ("" if st == "predicted" else f" ({st})")]
        if st == "unsupported_protocol":
            labels.append(None), methods.append(None), statuses.append(st), evidence.append(ev)
            continue
        pl_ = port_support(table, pr, po, policy) if table and po >= 0 else None
        if pl_ is not None:
            e = table[int(pr) * 65536 + int(po)]
            ev.append(f"port:{int(pr)}/{int(po)}->{pl_} purity={e['purity']:.3f} n={e['support']}")
            if ml == pl_:
                labels.append(pl_), methods.append("ml_port_agree"), statuses.append("predicted")
            elif policy["conflict"] == "port":
                labels.append(pl_), methods.append("port_estimate"), statuses.append("predicted")
            else:
                labels.append(None), methods.append(None), statuses.append("port_ml_conflict")
        elif ml is not None:
            labels.append(ml), methods.append("ml"), statuses.append("predicted")
        else:
            labels.append(None), methods.append(None), statuses.append(st)
        evidence.append(ev)
    return labels, methods, statuses, evidence


def build_port_table(proto: np.ndarray, port: np.ndarray, labels: np.ndarray,
                     weights: np.ndarray | None = None) -> dict[int, dict]:  # fmt: skip
    """Per (protocol, dst port): majority label, its (weighted) purity and the row support."""
    w = np.ones(len(labels)) if weights is None else np.asarray(weights, dtype=float)
    agg: dict[int, dict[str, float]] = {}
    cnt: dict[int, int] = {}
    for pr, po, lab, wt in zip(proto.tolist(), port.tolist(), labels.tolist(), w.tolist(),
                               strict=True):  # fmt: skip
        k = int(pr) * 65536 + int(po)
        d = agg.setdefault(k, {})
        d[lab] = d.get(lab, 0.0) + wt
        cnt[k] = cnt.get(k, 0) + 1
    out = {}
    for k, d in agg.items():
        lab, top = max(d.items(), key=lambda kv: kv[1])
        out[k] = {"label": str(lab), "purity": top / sum(d.values()), "support": cnt[k]}
    return out


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
        "policy": {**DEFAULT_POLICY, **(clf.policy or {})} if clf.port_table else None,
        "port_table_entries": len(clf.port_table),
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
    if manifest.get("schema_version") not in COMPATIBLE_SCHEMAS:
        raise ValueError(f"classifier schema {manifest.get('schema_version')} not in "
                         f"{COMPATIBLE_SCHEMAS}")  # fmt: skip
    if file_sha256(path / "classifier.joblib") != manifest["sha256"]["classifier.joblib"]:
        raise ValueError("classifier artifact hash mismatch (corrupted or modified); refusing")
    clf = joblib.load(path / "classifier.joblib")
    if not isinstance(clf, AppClassifier) or clf.features != manifest["features"]:
        raise ValueError("classifier artifact content does not match its manifest")
    return clf, manifest
