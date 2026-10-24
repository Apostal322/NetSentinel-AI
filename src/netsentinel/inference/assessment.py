"""Phase 8e: explicit uncertainty states (docs/phase8e/UNCERTAINTY_STATES.md).

Every prediction carries an `assessment` that says what NetSentinel can and cannot claim:
* `state`       - one primary state (below);
* `qualifiers`  - every other condition that applies (nothing is hidden by the precedence);
* `normality_supported` - true ONLY for `normal_valid_baseline`: the absence of an alert is a
                  claim of normality only under a valid, fresh baseline with healthy telemetry;
* `evidence_present` - anomalous behaviour or supervised suspicion was observed.

Precedence: evidence first, so drift, expiry or degraded telemetry never silence it (they
become qualifiers of the evidence); otherwise the most severe uncertainty; otherwise normal.

States:
* suspicious_evidence      - trusted supervised evidence (threat_status suspicious /
                             known_attack_category);
* anomalous_behavior       - the flow's device/service window deviates from the local baseline;
* model_unavailable        - neither a behaviour calibration nor a supervised model is loaded;
* telemetry_degraded       - the input is not trustworthy enough (clock anomaly / reset,
                             quarantined or evicted records, buffer pressure, parse errors);
* insufficient_calibration - no local baseline, too little history, a provisional or
                             statistically unreliable threshold, or a threshold dominated by
                             transient sources (Phase 8c);
* calibration_expired      - the flow is more than `max_age_h` after the calibration period;
* drift_detected           - the scored period is inconsistent with the calibration
                             (baseline_state drift_suspected / stale);
* unsupported_network      - the supervised model's domain check failed (unsupported_domain);
* normal_valid_baseline    - no alert, valid fresh baseline, healthy telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

STATES = ("suspicious_evidence", "anomalous_behavior", "model_unavailable", "telemetry_degraded",
          "insufficient_calibration", "calibration_expired", "drift_detected",
          "unsupported_network", "normal_valid_baseline")  # fmt: skip
UNCERTAINTY_ORDER = ("model_unavailable", "telemetry_degraded", "insufficient_calibration",
                     "calibration_expired", "drift_detected", "unsupported_network")  # fmt: skip
DEFAULT_MAX_AGE_H = 24.0  # Phase 8d: development FPR roughly doubled within 2-16 h of calibration


@dataclass
class Context:
    """Pipeline-level facts the per-flow assessment needs."""

    has_profile: bool
    has_model: bool
    profile_status: str | None = (
        None  # baseline_ready | baseline_provisional | insufficient_history
    )
    threshold_reliable: bool | None = None
    tail_dominated: bool = False
    calibration_end_ms: int | None = None
    max_age_h: float = DEFAULT_MAX_AGE_H
    threat_mode: str | None = None
    telemetry_health: str | None = None  # "ok" or a degrading reason
    reasons: list[str] = field(default_factory=list)


def conditions(ctx: Context, behavior_status: str | None, baseline_state: str | None,
               flow_time_ms: int | None) -> dict[str, str]:  # fmt: skip
    """Uncertainty conditions that hold for one flow -> {state: reason}."""
    c: dict[str, str] = {}
    if not ctx.has_profile and not ctx.has_model:
        c["model_unavailable"] = "no behaviour calibration and no supervised model loaded"
    if ctx.telemetry_health not in (None, "ok"):
        c["telemetry_degraded"] = f"telemetry health: {ctx.telemetry_health}"
    if not ctx.has_profile or behavior_status in ("not_calibrated", "insufficient_history"):
        c["insufficient_calibration"] = "no usable local baseline for this flow"
    elif ctx.profile_status == "baseline_provisional" or ctx.threshold_reliable is False:
        c["insufficient_calibration"] = "baseline thresholds are statistically unreliable"
    elif ctx.tail_dominated:
        c["insufficient_calibration"] = ("device threshold is set by transient sources; local "
                                         "devices may be undetectable (Phase 8c)")  # fmt: skip
    if (ctx.calibration_end_ms is not None and flow_time_ms is not None
            and flow_time_ms - ctx.calibration_end_ms > ctx.max_age_h * 3.6e6):  # fmt: skip
        age = (flow_time_ms - ctx.calibration_end_ms) / 3.6e6
        c["calibration_expired"] = f"calibration is {age:.1f} h old (limit {ctx.max_age_h:g} h)"
    if baseline_state in ("drift_suspected", "stale"):
        c["drift_detected"] = f"baseline state: {baseline_state}"
    if ctx.threat_mode == "unsupported_domain":
        c["unsupported_network"] = "supervised model's domain check failed for this network"
    return c


def assess(ctx: Context, verdict: str, threat_status: str | None, behavior_status: str | None,
           baseline_state: str | None, flow_time_ms: int | None) -> dict:  # fmt: skip
    cond = conditions(ctx, behavior_status, baseline_state, flow_time_ms)
    evidence = None
    if threat_status in ("suspicious", "known_attack_category") or verdict in (
        "suspicious",
        "attack",
    ):
        evidence = "suspicious_evidence"
    elif verdict == "unusual" or behavior_status == "anomalous":
        evidence = "anomalous_behavior"
    if evidence:
        state, qualifiers = evidence, [s for s in UNCERTAINTY_ORDER if s in cond]
    else:
        unc = [s for s in UNCERTAINTY_ORDER if s in cond]
        state = unc[0] if unc else "normal_valid_baseline"
        qualifiers = unc[1:]
    return {"state": state, "qualifiers": qualifiers,
            "normality_supported": state == "normal_valid_baseline",
            "evidence_present": evidence is not None,
            "reasons": [cond[s] for s in UNCERTAINTY_ORDER if s in cond]}  # fmt: skip
