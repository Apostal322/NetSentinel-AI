"""Unified inference: canonical flow records -> `Prediction` (see inference/schema.py).

Context features (`ctx_*`) need traffic history. `context="compute"` derives them causally from
the frame itself (for replay of a contiguous stream: identical to training); `context="none"`
leaves them missing (single API calls without history) and reports them in `missing_features`.
Evidence strings are generated only from measured per-feature robust z-scores against the
benign training baseline stored in the bundle.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from netsentinel.features.context import compute_context
from netsentinel.features.schema import add_derived
from netsentinel.inference.bundle import load_bundle
from netsentinel.inference.schema import AnomalyOut, Prediction, ServiceOut, ThreatOut
from netsentinel.models.anomaly import FiniteSignedLog
from netsentinel.models.decision import DecisionThresholds, decide
from netsentinel.models.service import service_category_expr

log = logging.getLogger(__name__)
EVIDENCE_Z = 4.0
EVIDENCE_TOP = 3


def observation_id(row: dict[str, Any], source: str) -> str:
    key = "|".join(str(row.get(k)) for k in ("timestamp", "dst_port", "protocol", "flow_duration",
                                             "row_id", "day"))  # fmt: skip
    return hashlib.sha1(f"{source}|{key}".encode()).hexdigest()[:16]


class Engine:
    def __init__(self, bundle_dir: str | Path):
        self.payload, self.manifest = load_bundle(bundle_dir)
        self.bundle_id = self.manifest["bundle_id"]
        self.thresholds = DecisionThresholds(**self.payload["thresholds"])
        self.threat = self.payload["threat"]
        self.anomaly = self.payload["anomaly"]
        self.attack_type = self.payload["attack_type"]
        self.evidence = self.payload["evidence"]
        self.required = sorted(
            set(self.threat["features"]) | set(self.anomaly["features"])
            | set(self.attack_type["features"] if self.attack_type else [])
        )  # fmt: skip
        self.needs_context = any(f.startswith("ctx_") for f in self.required)
        self.model_versions = {
            "bundle": self.bundle_id,
            "threat": self.threat["source_run"],
            "anomaly": self.anomaly["source_run"],
            **({"attack_type": self.attack_type["source_run"]} if self.attack_type else {}),
        }

    # ------------------------------------------------------------------ feature assembly
    def _frame(self, df: pl.DataFrame, context: str) -> tuple[pl.DataFrame, list[str]]:
        for col in ("timestamp", "dst_port", "protocol", "flow_duration"):
            if col not in df.columns:
                raise ValueError(f"input lacks required column {col!r}")
        df = add_derived(df).with_columns(service_category_expr())
        if self.needs_context and not any(c.startswith("ctx_") for c in df.columns):
            need = ["timestamp", "flow_duration", "dst_port", "tot_fwd_pkts", "tot_bwd_pkts",
                    "totlen_fwd_pkts", "totlen_bwd_pkts", "syn_flag_cnt"]  # fmt: skip
            if context == "compute" and all(c in df.columns for c in need):
                if "row_id" not in df.columns:
                    df = df.with_row_index("row_id")
                numeric = [pl.col(c).fill_null(0) for c in need if c != "timestamp"]
                ctx = compute_context(df.select("row_id", "timestamp", *numeric))
                df = df.join(ctx.drop("event_sec"), on="row_id", how="left")
        missing = [f for f in self.required if f not in df.columns]
        if missing:
            df = df.with_columns([pl.lit(None, dtype=pl.Float32).alias(f) for f in missing])
        return df, missing

    @staticmethod
    def _x(df: pl.DataFrame, features: list[str]) -> np.ndarray:
        return df.select([pl.col(f).cast(pl.Float32) for f in features]).to_numpy()

    # ------------------------------------------------------------------ prediction
    def score(self, df: pl.DataFrame, context: str = "compute") -> tuple[pl.DataFrame, list[str]]:
        """Vectorised scoring. Returns the frame with score columns and the missing features."""
        df, missing = self._frame(df, context)
        p = self.threat["model"].predict_proba(self._x(df, self.threat["features"]))[:, 1]
        a, used = self.anomaly["model"].score(
            self._x(df, self.anomaly["features"]), df["service"].to_numpy()
        )
        type_label = type_conf = None
        if self.attack_type:
            proba = self.attack_type["model"].predict_proba(
                self._x(df, self.attack_type["features"])
            )
            classes = np.asarray(self.attack_type["classes"])
            # Exclude 'benign' from the attack-type choice: P(type | malicious).
            mal = classes != "benign"
            sub = proba[:, mal]
            sub = sub / np.clip(sub.sum(axis=1, keepdims=True), 1e-12, None)
            type_label = classes[mal][np.argmax(sub, axis=1)]
            type_conf = sub.max(axis=1)
        verdict = decide(p, type_conf, a, self.thresholds)  # raw score vs raw val threshold
        cal = self.threat.get("calibrator")
        p_cal = cal.predict(p) if cal is not None else np.full(len(p), np.nan)
        out = df.with_columns(
            pl.Series("p_raw", p),
            pl.Series("p_malicious", p_cal),
            pl.Series("anomaly_score", a),
            pl.Series("anomaly_context", used),
            pl.Series("verdict", verdict),
        )
        if type_label is not None:
            out = out.with_columns(
                pl.Series("attack_type", type_label), pl.Series("attack_type_conf", type_conf)
            )
        return out, missing

    def evidence_for(self, df: pl.DataFrame) -> list[list[str]]:
        rz = self.evidence["model"]
        feats = self.evidence["features"]
        Z = FiniteSignedLog().transform(self._x(df, feats))  # noqa: N806
        signed = np.nan_to_num((Z - rz.median_) / rz.scale_, nan=0.0)
        out = []
        for row in signed:
            idx = [i for i in np.argsort(-np.abs(row)) if abs(row[i]) >= EVIDENCE_Z][:EVIDENCE_TOP]
            out.append([
                f"{feats[i]} {'above' if row[i] > 0 else 'below'} benign training baseline "
                f"(robust z={row[i]:+.1f})" for i in idx
            ])  # fmt: skip
        return out

    def predict(self, df: pl.DataFrame, source: str, context: str = "compute") -> list[Prediction]:
        scored, missing = self.score(df, context)
        evidence = self.evidence_for(scored)
        t = self.thresholds
        preds = []
        cal = self.threat.get("calibrator")
        # The decision uses the RAW score threshold from validation; the calibrated probability
        # is reported separately (an isotonic map can be flat around the threshold).
        rule = f"raw score >= {t.threat:.3g} ({self.threat.get('threshold_rule', 'validation')})"
        for row, ev in zip(scored.iter_rows(named=True), evidence, strict=True):
            is_mal = row["p_raw"] >= t.threat
            attack_cat = None
            conf = None
            if self.attack_type and is_mal:
                conf = float(row["attack_type_conf"])
                attack_cat = row["attack_type"] if conf >= t.attack_type else "unknown"
            preds.append(Prediction(
                observation_id=observation_id(row, source),
                timestamp=row["timestamp"],
                source=source,
                verdict=row["verdict"],
                service=ServiceOut(category=row["service"]),
                anomaly=AnomalyOut(score=float(row["anomaly_score"]), threshold=t.anomaly,
                                   is_anomalous=row["anomaly_score"] >= t.anomaly,
                                   context=row["anomaly_context"]),
                threat=ThreatOut(probability=None if cal is None else float(row["p_malicious"]),
                                 decision_rule=rule, is_suspicious=bool(is_mal),
                                 attack_category=attack_cat, classification_confidence=conf,
                                 calibration=self.threat.get("calibration")),
                evidence=ev,
                missing_features=missing,
                model_versions=self.model_versions,
            ))  # fmt: skip
        return preds
