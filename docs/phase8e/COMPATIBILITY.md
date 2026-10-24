# Product hardening and compatibility (Phase 8e, Mission 6)

- Check script: `scripts/phase8e/compat_check.py`.
- Result: `reports/phase8e/compat_check.json`.
- The script runs on the artifacts that already exist locally. Event stores are copied first;
  the originals are opened read-only.

## Results

| surface | check | result |
|---|---|---|
| model bundles | both local bundles (`bundle-20261019T101720Z`, `bundle-20261019T202605Z`) load | ok |
| behaviour calibrations | the two local Phase 6 calibrations (schema `behavior-1.0.0`) | **refused** with "calibration schema behavior-1.0.0 != behavior-1.1.0; recalibrate". Fail-closed policy since Phase 7 (RELEASE_READINESS.md), not a Phase 8e change. |
| current calibration | a fresh calibration of the CTU-Normal-26 capture, analysed end to end (in-sample engineering check, not a claim) | 17,268 flows; telemetry `ok`; 17,170 `normal_valid_baseline`, 98 `anomalous_behavior`; peak RSS 511 MB |
| event store migration | `artifacts/events.sqlite` (134,633 rows), `artifacts/ctu26_phase6.sqlite` (10,433 rows) | `assessment_state` column added on open; row counts unchanged; all old rows reported as `not_recorded` |
| old event payloads | 200 stored payloads per store validated against the current `Prediction` schema | 0 failures (`assessment` is optional) |
| API | `Prediction.assessment` is an additive optional field; `/events` adds an optional `state` filter; `/metrics/summary` adds `assessment_states` | old clients unaffected (test_serving) |
| CLI | no argument changes. `analyze` adds `telemetry_health`, `assessment_states`, `normality_supported_share`. `monitor` adds `assessment_states` and a period `assessment`. | test_offline_app, test_monitor_cli |
| dashboard | reads `assessment_state` only if the column exists; pre-8e stores show the "not evidence of normality" caption | AppTest (test_dashboard) |
| Docker / GitHub Actions | no Dockerfile or workflow change needed (no new dependency or package) | the CI run of the push builds the image and runs the demo and API smoke tests |
| detection only | no code path blocks, drops or rewrites traffic; assessment changes no verdict | by construction; tests assert verdicts unchanged |

## Fixes made during the check

- `analyze_capture` now closes its event store. Windows kept the SQLite file locked, which broke
  temporary-directory cleanup in callers.
- Behaviour-only `monitor` (no model bundle) produced no flow predictions, so it reported no
  assessment. It now reports one assessment of the whole monitored period (`assessment`),
  driven by stream health, calibration validity and anomalous windows.

## Regression tests added in Phase 8e

| test | covers |
|---|---|
| `tests/unit/test_assessment.py` | every state reachable; evidence never silenced (4 cases); no condition hidden by precedence; parse health; pre-8e event-store migration and state filter |
| `tests/integration/test_stream_robustness.py` | 10 adversarial clock scenarios (loss, leak, memory, health flags), idle `advance`, IDLE marker |
| `tests/integration/test_streaming.py` | resync and forged-timestamp outcomes |
| `test_serving.py`, `test_offline_app.py`, `test_monitor_cli.py`, `test_dashboard.py` | assessment through API, CLI, replay, monitor and dashboard; degraded parse health on the malformed-packet fixture |

## Not verified locally

- **Docker build:** no Docker on this machine; CI builds the image.
- **CPU-only environment (no torch extra):** CI runs it; the new code imports no torch.
- **The behaviour of `calibration_expired` on long real deployments.** The 24 h default is
  pre-declared, not validated (UNCERTAINTY_STATES.md).
