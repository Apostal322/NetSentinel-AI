"""The inference contract shared by the engine, API, event store and dashboard.

Field semantics are deliberately distinct:
* `threat.probability`      - calibrated P(malicious | features) under the TRAINING prevalence
                              (calibration method recorded in `threat.calibration`); null if the
                              threat model is unavailable.
* `threat.classification_confidence` - top softmax probability of the attack-type model given
                              that the flow is malicious; a model confidence, not calibrated.
* `anomaly.score`           - 0-100 benign-tail rank (see netsentinel.models.anomaly); NOT a
                              probability of attack.
* `service`                 - port-derived service category (heuristic, `method` says so).
* `verdict`                 - decision layer output; `unusual` means anomalous without enough
                              malicious evidence, `suspicious` means malicious evidence without
                              a supported attack type.
Phase 6 additions (optional, so older events stay valid):
* `application`             - transport / ML app protocol (proxy nDPI label, may abstain) /
                              port-heuristic service / application identity (always null).
* `behavior`                - deviation of this flow's entity-window from the LOCAL calibrated
                              baseline; `anomaly_score` is a normalized non-probability.
* `threat_status`           - supervised evidence: not_assessed | unverified_domain (DEFAULT on
                              any network not verified to match the training data) |
                              unsupported_domain | no_evidence | suspicious |
                              known_attack_category. An anomaly never becomes `suspicious`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Verdict = Literal["benign", "unusual", "suspicious", "attack", "insufficient_data"]
ThreatStatus = Literal["not_assessed", "unverified_domain", "unsupported_domain", "no_evidence",
                       "suspicious", "known_attack_category"]  # fmt: skip
BehaviorStatus = Literal["normal", "anomalous", "insufficient_history", "not_calibrated"]
AppStatus = Literal["predicted", "low_confidence", "out_of_distribution", "missing_features",
                    "unsupported_protocol", "port_ml_conflict", "class_transport_mismatch",
                    "class_port_mismatch", "no_classifier"]  # fmt: skip
AppMethod = Literal["ml", "ml_port_agree", "port_estimate"]


class FlowRecord(BaseModel):
    """One flow in canonical (snake_case CICFlowMeter-V3) form. Unknown keys are rejected so a
    typo cannot silently become a missing feature."""

    model_config = ConfigDict(extra="forbid")
    timestamp: datetime
    dst_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    flow_duration: int = Field(ge=0)
    features: dict[str, float | None] = Field(
        description="raw flow features by canonical name; null/absent = missing"
    )
    source: str = Field(default="api", max_length=128)

    @field_validator("features")
    @classmethod
    def _bounded(cls, v: dict[str, float | None]) -> dict[str, float | None]:
        if len(v) > 200:
            raise ValueError("too many feature keys")
        return v


class ServiceOut(BaseModel):
    category: str
    method: Literal["port_heuristic"] = "port_heuristic"


class AnomalyOut(BaseModel):
    score: float = Field(ge=0, le=100)
    threshold: float = Field(ge=0, le=100)
    is_anomalous: bool
    context: str = Field(description="service context whose reference was used, or __global__")
    calibrated_probability: Literal[False] = False


class ThreatOut(BaseModel):
    probability: float | None = Field(default=None, ge=0, le=1)
    decision_rule: str = Field(description="how is_suspicious is decided (raw score threshold)")
    is_suspicious: bool
    attack_category: str | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    calibration: str | None = None


class ApplicationOut(BaseModel):
    transport: str
    app_protocol: str | None = None
    app_status: AppStatus = "no_classifier"
    app_method: AppMethod | None = None  # which evidence produced app_protocol
    app_ml_class: str | None = None  # the ML model's own (non-abstained) class
    app_evidence: list[str] = Field(default_factory=list)
    app_confidence: float | None = Field(default=None, ge=0, le=1)
    confidence_semantics: str = "model top-class probability; not a calibrated probability"
    label_semantics: str = "nDPI master protocol proxy label"
    service_category: str
    service_method: Literal["port_heuristic"] = "port_heuristic"
    application_identity: None = None
    classifier: str | None = None


class BehaviorOut(BaseModel):
    behavior_status: BehaviorStatus
    anomaly_score: float | None = Field(default=None, ge=0, le=100)
    anomaly_score_type: Literal["normalized_non_probability"] = "normalized_non_probability"
    raw_score: float | None = None
    threshold: float | None = None
    # Phase 8 uncertainty: 95% upper bound of the false-alert rate of `threshold`, from the
    # number of held-out calibration windows (sampling only; drift not included)
    threshold_fpr_upper95: float | None = None
    model_scope: str | None = None
    level: str | None = None  # Phase 8: entity level of the window that decided the status
    entity: str | None = None  # device address or service category of that window
    window_s: int | None = None
    window_end: datetime | None = None
    baseline_status: str
    calibration: str | None = None
    explanation: list[str] = Field(default_factory=list)


class Prediction(BaseModel):
    observation_id: str
    timestamp: datetime
    source: str
    verdict: Verdict
    service: ServiceOut
    anomaly: AnomalyOut | None
    threat: ThreatOut | None
    evidence: list[str]
    missing_features: list[str]
    model_versions: dict[str, str]
    application: ApplicationOut | None = None
    behavior: BehaviorOut | None = None
    threat_status: ThreatStatus | None = None
