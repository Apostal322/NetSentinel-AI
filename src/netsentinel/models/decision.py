"""Decision layer: combine independent signals into a verdict without overclaiming.

    attack       p_malicious >= t_threat and attack-type confidence >= t_type
    suspicious   p_malicious >= t_threat, attack type not confidently supported
    unusual      anomaly score >= t_anomaly but p_malicious < t_threat
    benign       otherwise
    insufficient_data  required inputs missing (no threat model output and no anomaly score)

An anomaly alone never yields `attack` or `suspicious`: unusual is not malicious.
The threat and anomaly thresholds are chosen on validation data and stored with the models.
The attack-type confidence threshold is a fixed default (0.6), NOT tuned on data; the
portable PCAP/Zeek bundle has no attack-type model, so it never emits `attack`.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class DecisionThresholds:
    threat: float
    attack_type: float = 0.6
    anomaly: float = 99.5


def decide(
    p_malicious: np.ndarray | None,
    type_confidence: np.ndarray | None,
    anomaly_score: np.ndarray | None,
    t: DecisionThresholds,
) -> np.ndarray:
    n = next(len(a) for a in (p_malicious, anomaly_score, type_confidence) if a is not None)
    verdict = np.full(n, "benign", dtype=object)
    have_threat = p_malicious is not None
    if anomaly_score is not None:
        verdict[np.asarray(anomaly_score) >= t.anomaly] = "unusual"
    if have_threat:
        p = np.asarray(p_malicious)
        mal = p >= t.threat
        verdict[mal] = "suspicious"
        if type_confidence is not None:
            verdict[mal & (np.asarray(type_confidence) >= t.attack_type)] = "attack"
    if not have_threat and anomaly_score is None:
        verdict[:] = "insufficient_data"
    return verdict.astype(str)
