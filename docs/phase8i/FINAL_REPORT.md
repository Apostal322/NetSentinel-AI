# Phase 8i final report (draft: results pending)

**Status labels:**
- **[E]:** development, exploratory.
- **[C]:** the single confirmatory evaluation on NF-BoT-IoT-v3.
- Hypotheses, protocols and amendments: [PREREGISTRATION.md](PREREGISTRATION.md).
- Chronology and incidents: [AUDIT_TRAIL.md](AUDIT_TRAIL.md).

## 1. Question

Phase 8h found that supervised flow-window detectors rank attacks almost perfectly within one
network but collapse on another (recall about 1.0 vs 0.03 at a 1%-FPR threshold). Phase 8i asks
whether three remedies help on an unseen network while keeping false alerts near a 1% budget:
- a few labelled target windows (I1);
- a shift score that withdraws unsupported false-alert claims (I2);
- a representation that carries less network identity (I3).

## 2. Data

- **Development** (inspected; [DATASET_AUDIT.md](DATASET_AUDIT.md)):
  - N1 NF-CIC-IDS2018-v3: 11 days, development part.
  - N2 NF-UNSW-NB15-v3: development part.
  - N3 NF-ToN-IoT-v3: 27.5M flows, new to this project's window pipeline. Its network was
    inspected in Phase 8c.
- **Protected test:** N4 NF-BoT-IoT-v3, never opened before the freeze.
- **Windows:** the Phase 8h windows (30 s, per source, 12 features). The NF-CIC and NF-UNSW
  windows are identical to Phases 8h/8b.

## 3. Engineering fix: late records now degrade telemetry health

- **Before:** a record arriving after its window had closed was counted and dropped, but health
  stayed `ok`. In CTU-13 scenario 10, 90 such records (0.0008% of 11.6M) removed 10 alerts
  while the monitor reported healthy telemetry.
- **Now:** the first late record sets the `late_records` flag (severity 1, as
  `buffer_pressure`), and `late_windows` counts the affected windows. The flag reaches the
  assessment ("normality not supported"), the event store, the CLI and the dashboard through
  the existing health path.
- **No rate threshold:** the only measured case shows harm at 0.0008%, and clean replays at an
  adequate lateness produce zero late records.
- **Limitation:** assessments already emitted for the affected windows are not rewritten.
- **Tests:** `test_late_records_degrade_health`, `test_late_flag_ranks_below_integrity_faults`,
  the monitor CLI JSON test, and the pre-8f forgery test, where the loss is now visible.
