# Explicit uncertainty states (Phase 8e, Mission 3)

- Code: `src/netsentinel/inference/assessment.py` (rules), `AnalysisPipeline.assess`
  (per-flow), `schema.AssessmentOut`.
- Tests: `tests/unit/test_assessment.py`, plus assertions in `test_serving.py`,
  `test_offline_app.py` and `test_dashboard.py`.

## Why

Before Phase 8e, a flow without an alert was shown as `benign`, whether or not NetSentinel
could see anything at that point. Phases 8c and 8d showed when it could not:

- local devices are undetectable when transient sources set the device threshold;
- the false-positive rate doubles within hours of calibration;
- forged or reset clocks corrupt windows.

`verdict` keeps its old meaning, for API and event-store compatibility. Every prediction now
also carries an `assessment` that says what the system can and cannot claim.

## Fields

| field | meaning |
|---|---|
| `state` | one primary state (below) |
| `qualifiers` | every other condition that also applies; precedence hides nothing |
| `normality_supported` | `true` only for `normal_valid_baseline` |
| `evidence_present` | anomalous behaviour or trusted supervised suspicion was observed |
| `reasons` | one human-readable reason per uncertainty condition |

## States and triggers

| state | trigger (first match in this order for non-evidence flows) |
|---|---|
| `suspicious_evidence` | `threat_status` is `suspicious` or `known_attack_category`, or `verdict` is `suspicious` / `attack` |
| `anomalous_behavior` | `verdict` is `unusual`, or `behavior_status` is `anomalous` |
| `model_unavailable` | no behaviour calibration **and** no supervised model |
| `telemetry_degraded` | stream health is not `ok` (`clock_anomaly`, `clock_reset`, `integrity_degraded`, `buffer_pressure`; see STREAMING_ROBUSTNESS.md), or offline parse errors above 1% (benign skips such as non-IP frames excluded) |
| `insufficient_calibration` | no calibration; the flow's entity has `not_calibrated` / `insufficient_history`; profile `baseline_provisional`; device threshold flagged unreliable; or device threshold tail-dominated (`tail_fallback_share` > 0.5, Phase 8c) |
| `calibration_expired` | the flow ends more than `max_age_h` (default **24 h**) after the calibration period |
| `drift_detected` | `baseline_state` is `drift_suspected` or `stale` |
| `unsupported_network` | threat mode `unsupported_domain` (the supervised model's domain check failed) |
| `normal_valid_baseline` | none of the above |

## Rules

1. **Evidence takes precedence.**
   - Drift, expiry, degraded telemetry or an unsupported network never turn evidence into
     silence. They become `qualifiers` of the evidence.
   - Nothing is suppressed: Phase 8e changes no verdict and no alert.
2. **No alert ≠ normal.**
   - Only `normal_valid_baseline` has `normality_supported = true`.
   - Every summary reports `normality_supported_share`.
   - The dashboard shows a warning whenever quiet flows are in an uncertainty state.
3. **API flow records** (`/predict/flow`, `/predict/batch`) have no endpoints, so they cannot be
   windowed into behaviour. They are never `normal_valid_baseline`.
4. **Replay** of labelled research data has no local calibration. Quiet flows are
   `insufficient_calibration`.
5. **Supervised domain check.** `unsupported_network` follows the threat mode.
   - Under the default `unverified` policy, the supervised model never contributes to a
     verdict, so its domain check does not change the state. Normality then rests on the local
     behaviour baseline alone.
   - With `--threat-policy auto` and a failed check, or with `unsupported`, quiet flows are
     `unsupported_network`.
6. **Behaviour-only monitoring** (`monitor` without a bundle) reports one `assessment` for the
   whole monitored period.
7. **Pre-8e events** have no state. The summary counts them as `not_recorded`, and the
   dashboard says that their absence of alerts is not evidence of normality.

## Where it is exposed

| surface | what |
|---|---|
| `Prediction.assessment` | per flow: API responses, the event-store payload, CLI `--out` JSON |
| event store | `assessment_state` column, added to older databases on open (migration test); `query(states=...)`; `summary()["assessment_states"]` |
| API | `GET /events?state=...` (422 on unknown states); `/metrics/summary` → `assessment_states` |
| CLI `analyze` | `telemetry_health`, `assessment_states`, `normality_supported_share` |
| CLI `monitor` | `assessment_states`; stream `health` / `health_flags` in `stats` |
| dashboard | Live traffic: banner and state counts. Analyze capture: telemetry error, normality share and states |

## Defaults and limits (what is NOT claimed)

- **`max_age_h = 24`** is a pre-declared operational default.
  - Phase 8d: the development FPR roughly doubled 2–16 h after calibration.
  - It was not tuned on any capture.
  - Most research captures span more than 24 h after their calibration window, so most of
    their flows are `calibration_expired`. That is the intended reading.
- **`normal_valid_baseline` is not a guarantee of benignity.**
  - It says that the conditions under which the detector was validated hold.
  - Recall under those conditions is still limited (Phase 8b/8c: local-device recall near
    zero on IoT-23).
- **The state does not change thresholds.** Selective prediction (abstaining to cut false
  alarms) is evaluated separately in M4 and is not the default.
- **The 1% parse-error limit is a heuristic**, not a validated one.
