import numpy as np

from netsentinel.models.decision import DecisionThresholds, decide

T = DecisionThresholds(threat=0.5, attack_type=0.6, anomaly=99.0)


def test_verdict_table():
    p = np.array([0.1, 0.1, 0.9, 0.9, 0.9])
    conf = np.array([0.9, 0.9, 0.9, 0.3, 0.9])
    anom = np.array([10.0, 99.5, 10.0, 99.9, 99.9])
    assert list(decide(p, conf, anom, T)) == ["benign", "unusual", "attack", "suspicious",
                                               "attack"]  # fmt: skip


def test_anomaly_alone_is_never_malicious():
    anom = np.array([100.0, 100.0])
    assert set(decide(None, None, anom, T)) == {"unusual"}


def test_missing_everything_is_insufficient():
    assert list(decide(None, np.array([0.9]), None, T)) == ["insufficient_data"]


def test_without_type_model_malicious_is_suspicious_not_attack():
    assert list(decide(np.array([0.99]), None, None, T)) == ["suspicious"]
