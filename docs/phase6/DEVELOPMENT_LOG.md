# Phase 6 development log

## 2026-10-20

- **6A audit.**
  - Baseline: default test suite green (190 s), `ruff check` clean.
  - CI defect found: `ruff format --check` failed on 6 files written in Phase 5. Fixed by
    formatting them (plus one E731 lambda turned into a def).
- **Independent data** (user-authorised download, about 77 MB):
  - CTU-Normal-20..25, 27..32 Zeek conn logs;
  - 9 IoT-23 labelled conn logs.
  - SHA-256 hashes: `reports/audit/phase6_external_data_sha256.txt`.
- **Composition:**
  - Most CTU-Normal captures are the same lab host (10.0.2.15) as CTU-26, so they are a
    different day but the same environment.
  - CTU-Normal-21 and -22 are a different network (192.168.1.x).
  - IoT-23 20-1, 21-1, 42-1 and 44-1 are mostly benign with rare C&C.
  - IoT-23 3-1, 8-1 and 34-1 are dominated by malicious traffic.
  - IoT-23 data lines separate the last three fields by spaces, not tabs, and need a
    dedicated loader.
- **Plan and frozen hypotheses:** `docs/phase6/IMPLEMENTATION_PLAN.md`.
- **Criterion clarification (before any evaluation).** H1 compared window false alerts with
  the bundle's per-flow "unusual" rate, which are different units. The uncalibrated
  comparator is now defined at window level: a window alerts if any of its flows gets the
  Phase-5 bundle verdict "unusual" or "suspicious".
- **6B/6C core implemented.**
  - `behavior/windows.py`: causal tumbling windows. A flow is assigned by its end time. Global
    silent windows are kept, with only the flow count defined.
  - `behavior/profile.py`: robust median/MAD per entity, device -> pooled fallback,
    split-conformal thresholds, percentile severity, explanations. Trimming in unlabelled
    mode.
  - `behavior/calibrate.py`: versioned artifact with SHA-256, schema and feature-list checks,
    cold start, and the threat-model domain check.
  - `behavior/monitor.py`: scoring against a frozen profile; baseline state (monitoring /
    drift_suspected / stale). No online learning.
  - CLI `netsentinel calibrate`; vetted-benign mode requires `--assert-benign`.
- **Decisions.**
  - Window score = mean of the top-2 |z|.
  - Scale floors: 0.25 for log features, 0.15 for fractions. A floor of 0.05 made fraction
    features saturate at z = 20; seen on CTU-26 before any evaluation.
  - Silent global windows have undefined (NaN) non-count features rather than 0, which had
    made the distributions bimodal.
- **Smoke run, CTU-26 Zeek log.** 12 s; 778 global windows; status baseline_ready. Threat
  domain check: the bundle flags 1.48% of asserted-benign flows against a limit of 1%, so it
  is marked unsupported.
- **Tests.** `tests/unit/test_behavior.py`: 8 tests (causality, end-time assignment, burst
  detection, cold start, trimming, artifact tamper/schema refusal, empty input, drift), all
  passing.

### H1 (benign CTU captures, `scripts/phase6/eval_h1_ctu.py` -> `reports/phase6/h1_ctu.json`)

- Setup: 13 captures; CTU-21 (0.3 h) is correctly `insufficient_history`. Each capture's
  first 50% of time calibrates, the last 50% is evaluated. Window 30 s, target FPR 0.01.
  29 s runtime, 0.59 GB peak.
- **Vetted mode (pre-registered primary):**
  - Median global false-alert windows per hour: **2.3**, vs **120** for the uncalibrated
    Phase-5 bundle (any flow unusual/suspicious; window FPR 0.54–1.00). Ratio criterion met
    (52x).
  - Global-window FPR <= 0.03 in only **7/12** captures; five captures reach 0.033–0.042.
  - **H1 not supported** as pre-specified: the FPR criterion fails. Thresholds come from
    about 100–230 held-out windows of the same capture's first half, and the second half
    drifts.
  - Device and service levels: median 1.1 and 0.5 false alerts/h.
- **Post-hoc revision of unlabelled mode (exploratory on CTU from here on).**
  - Run 1, fixed-quantile trimming of fit and held-out windows: median 10.7 FA/h.
  - Run 2, robust-outlier trimming of both: 23.7 FA/h. Trimming held-out windows always
    lowers the threshold.
  - Final design: trim only fit windows and set the threshold from all held-out windows, so
    contamination costs recall (to be measured in H5 on unused data), not false alerts.
    Run 3: median 1.4 FA/h on clean captures.
  - H1's vetted-mode result is unaffected by these changes.
- Comparator bug (window count allowed FPR > 1) fixed; conclusions unchanged.
