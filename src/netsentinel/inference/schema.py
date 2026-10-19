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
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Verdict = Literal["benign", "unusual", "suspicious", "attack", "insufficient_data"]


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
    threshold: float | None = None
    is_suspicious: bool
    attack_category: str | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    calibration: str | None = None


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
