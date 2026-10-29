# Release readiness after Phase 8g (2026-10-28)

**Scope.** Whether the Phase 8g changes can be released as part of the research prototype.
- Not an assessment of production fitness.
- NetSentinel AI stays a local, **detection-only** tool: nothing blocks or isolates traffic.
- Legend as in [../RELEASE_READINESS.md](../RELEASE_READINESS.md): **Verified**,
  **Unverified**, **Blocked**, **Incomplete**.

## Verification matrix

| area | status | evidence |
|---|---|---|
| full default test suite (gpu / slow / data excluded) | **Verified locally**: see "Final validation" | `reports/phase8g_post/logs/pytest_full.log` |
| ruff check, ruff format --check | **Verified locally**: clean (278 files) | this phase |
| lockfile unchanged; no dependency added, removed or upgraded | **Verified** (`uv lock --check`) | this phase |
| streaming exactness on real data | **Verified [R]**: scenario 9 exact; scenario 10 exact at 3,700 s, 90 late records at 600 s | [REAL_DATA_STREAMING_AUDIT.md](REAL_DATA_STREAMING_AUDIT.md) |
| spill edge cases (budget, disk full, interrupted write, corrupt or truncated files, stale directories, restart, conservation; lazy flush: memory, consumer interruption and resume, abandonment, file lost mid-flush) | **Verified** (17 synthetic tests) and hard kill on real data | `test_spill_hardening.py`, `interrupt_check.json` |
| `monitor` CLI | **Verified** (tests; real-data replay through `WindowStream`) | `test_monitor_cli.py`, audit |
| `analyze` CLI, offline pipeline | **Verified** (tests) | `test_offline_app.py` |
| replay path, API (`/health`, `/ready`, `/events`, `/behavior`) | **Verified** (TestClient). `/behavior` returns `telemetry_health` per window | `test_serving.py`, `test_offline_app.py`, `test_telemetry_health_store.py` |
| event store migration (`behavior_events.telemetry_health`) | **Verified**: an old database gains the column and keeps its rows (NULL = written before Phase 8g) | `test_old_database_gains_the_column_and_keeps_its_rows` |
| dashboard | **Verified** (Streamlit AppTest): the Behavior page shows "Telemetry degraded … windows without an alert are not evidence of normality" | `test_dashboard.py` |
| failures never yield `normal_valid_baseline` | **Verified**: degraded telemetry (behaviour-only monitor, `buffer_pressure`), replay without calibration, every assessment state | `test_behaviour_only_monitor_stores_degraded_health`, `test_serving.py`, `test_assessment.py` |
| health indicators `buffer_spill`, `buffer_pressure`, `clock_anomaly`, `spill_failed`, `integrity_degraded` | **Verified** in stream stats, monitor summary and stored per window | `test_streaming.py`, `test_stream_robustness.py`, `test_spill_hardening.py` |
| model and calibration loading, schema versions, integrity refusal | **Verified** (unchanged since v0.7.0; tests pass) | unit / integration tests |
| update gate: per-entity review trigger | **Verified**: regression test; development data 0/12 new clean reviews, 8/12 scans caught | [V4_FAILURE_ANALYSIS.md](V4_FAILURE_ANALYSIS.md) §5 |
| Docker image, container smoke tests, pip-audit, gitleaks | **Verified in CI** on bf47e28 (jobs `docker` and `security` passed). No Docker locally. | https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525 |
| GitHub Actions for the Phase 8g finalization commits | **Verified**: run 40817259525 on bf47e28 (push to `main`), all three jobs passed: `test`, `docker`, `security` | https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525 |

## Backward compatibility

- **Event store.** Additive migration only: a new nullable column. Old rows read as NULL.
- **Stream statistics.** New counters are added: `spill_lost`, `spill_invalid`,
  `spill_error`, `invalid_time`, `emitted`. Consumers that ignore unknown keys are
  unaffected.
- **`WindowStream.flush()`** still returns a list. `flush_iter()` is new.
- **Records ending before they start** are now rejected (`invalid_time`,
  `integrity_degraded`). They used to be windowed.
- **`update_check`** returns `excess_entities` and `excess_entity_count`. It can now require
  review where it did not before, so `calibrate --activate` refuses such a period until
  `--reviewed`.
- **No artifact schema version changed.**

## Open issues (not blocking a prototype release)

1. **Late records** are counted, but they do not change `health`. Scenario 10 had 90 late
   records at 600 s, which cost 10 alerts while health stayed `ok`.
2. **Spilling is about 10× slower than in-memory streaming** (13–40k records/s).
3. **A crashed process's spill directory** is reclaimed only by the next spilling run.
4. **Alert burden on unlabelled background traffic** is about 2,563/h on CTU-13 scenario 9.
   It is not triageable as a raw stream.
5. **Any data-driven baseline refresh can learn a gradual attack.** Refresh is manual and
   review-gated, and should stay so.

## Final validation (local, 2026-10-29, final working tree)

| check | result |
|---|---|
| pytest, default selection (`-m 'not slow and not gpu and not data'`), torch and dashboard extras | **260 passed, 2 deselected**, 0 failed, 6 warnings (third-party deprecation and sklearn sample-size notices); 15 min 39 s |
| ruff check | All checks passed |
| ruff format --check | 278 files already formatted |
| dependency gate (`scripts/release/check_dependency_exceptions.py`, offline) | OK; only the documented Pillow 13 exception |
| lockfile | `uv lock --check` consistent; `pyproject.toml` and `uv.lock` unchanged since the last CI-verified commit |
| backward compatibility | old event store migrates (test); no artifact schema change |
| frozen Phase 8g outputs | unchanged: `reports/phase8g/`, `configs/phase8g/`, `scripts/phase8g/` have no diff; the 157 frozen window parts were last written by the frozen run |
| GitHub Actions on the final commit | **passed** on bf47e28, the last code commit: [run 40817259525](https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525). Jobs: [test](https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525/job/123261135775), [docker](https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525/job/123261135536), [security](https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525/job/123261135645). The later commit that records this result changes documentation only. |
