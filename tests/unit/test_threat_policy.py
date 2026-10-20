"""Phase 7 safe defaults: supervised verdicts never escalate on unverified networks."""

from types import SimpleNamespace

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.calibrate import threat_domain_check
from netsentinel.inference.pipeline import (
    DEFAULT_THREAT_POLICY,
    decide_verdict,
    threat_mode_for,
    threat_status_for,
)

OK_CHECK = {"version": 2, "bundle": "b1", "supported": True}
V1_CHECK = {"bundle": "b1", "supported": True}  # Phase 6 lenient check (no version)


def test_default_policy_is_unverified():
    assert DEFAULT_THREAT_POLICY == "unverified"
    assert threat_mode_for("unverified", "b1", OK_CHECK) == "unverified_domain"


@pytest.mark.parametrize(
    ("policy", "check", "mode"),
    [
        ("auto", OK_CHECK, "assessed"),
        ("auto", V1_CHECK, "unverified_domain"),  # old lenient checks are not trusted
        ("auto", {**OK_CHECK, "bundle": "other"}, "unverified_domain"),  # other bundle
        ("auto", None, "unverified_domain"),  # no calibration
        ("auto", {"version": 2, "bundle": "b1", "supported": False,
                  "reason": "insufficient_flows"}, "unverified_domain"),
        ("auto", {"version": 2, "bundle": "b1", "supported": False,
                  "reason": "flag_rate_above_validation_fpr"}, "unsupported_domain"),
        ("auto", {"version": 2, "bundle": "b1", "supported": False,
                  "reason": "not_vetted_benign"}, "unverified_domain"),
        ("trust", None, "assessed"),
        ("unsupported", OK_CHECK, "unsupported_domain"),
    ],
)  # fmt: skip
def test_threat_mode_resolution(policy, check, mode):
    assert threat_mode_for(policy, "b1", check) == mode


def test_no_bundle_and_bad_policy():
    assert threat_mode_for("trust", None, None) == "not_assessed"
    with pytest.raises(ValueError):
        threat_mode_for("yolo", "b1", None)


def test_unverified_threat_never_escalates():
    hit = SimpleNamespace(is_suspicious=True, attack_category="bruteforce")
    for mode in ("unverified_domain", "unsupported_domain"):
        ts = threat_status_for(mode, hit)
        assert ts == mode
        cases = [("normal", False), ("anomalous", False), ("not_calibrated", True),
                 ("not_calibrated", False), ("insufficient_history", False)]  # fmt: skip
        for beh, legacy in cases:
            assert decide_verdict(ts, beh, legacy) not in ("attack", "suspicious")
    assert threat_status_for("assessed", hit) == "known_attack_category"
    assert decide_verdict("known_attack_category", "normal", False) == "attack"


def test_no_baseline_and_no_trusted_model_is_not_benign():
    assert decide_verdict("unverified_domain", "not_calibrated", False) == "insufficient_data"
    assert decide_verdict("unverified_domain", "normal", False) == "benign"  # local baseline
    assert decide_verdict("no_evidence", "not_calibrated", False) == "benign"  # trusted model
    assert decide_verdict("unverified_domain", "anomalous", False) == "unusual"  # kept apart


class StubEngine:
    bundle_id = "b1"
    thresholds = SimpleNamespace(threat=0.5)
    threat = {"threshold_rule": "val weighted FPR <= 0.001"}

    def __init__(self, n: int, flags: int):
        self.p = np.r_[np.ones(flags), np.zeros(n - flags)]

    def score(self, frame, context="compute"):
        return pl.DataFrame({"p_raw": self.p}), []


def test_domain_check_v2_rejects_the_phase6_ctu_case():
    # CTU-26 PCAP calibration: 6,835 flows, 0.54% flagged (validation FPR 0.1%).
    chk = threat_domain_check(StubEngine(6835, 37), None)
    assert chk["version"] == 2 and chk["supported"] is False
    assert chk["reason"] == "insufficient_flows" and chk["flows_needed"] == 10_000
    big = threat_domain_check(StubEngine(20_000, 108), None)  # same rate, enough flows
    assert big["supported"] is False and big["reason"] == "flag_rate_above_validation_fpr"


def test_domain_check_v2_accepts_in_domain_rate_and_requires_vetted_mode():
    ok = threat_domain_check(StubEngine(20_000, 22), None)  # 0.11% ~ validation FPR
    assert ok["supported"] is True
    un = threat_domain_check(StubEngine(20_000, 22), None, mode="unlabelled")
    assert un["supported"] is False and un["reason"] == "not_vetted_benign"


def test_cli_resolves_active_calibration_from_registry(tmp_path, monkeypatch):
    from netsentinel.behavior.registry import resolve_calibration

    monkeypatch.chdir(tmp_path)
    root = tmp_path / "models" / "calibrations"
    root.mkdir(parents=True)
    (root / "registry.json").write_text('{"active": "calibration-x", "history": []}')
    assert resolve_calibration("active") == root.relative_to(tmp_path) / "calibration-x"
    assert str(resolve_calibration("some/dir")) == str(
        tmp_path.joinpath("some/dir").relative_to(tmp_path)
    )
