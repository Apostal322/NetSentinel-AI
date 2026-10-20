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

### IoT-23 (`scripts/phase6/eval_iot23.py` -> `reports/phase6/iot23.json`), exploratory

- Setup: 9 scenarios; the first 50% of each scenario's time calibrates. Labels come from the
  dataset authors. 28 s, 0.73 GB.
- **Oracle-clean calibration** (dataset-labelled benign flows only):
  - global recall 0.97 (3-1, 8-1); Isolation Forest recall 1.00 on 34-1, at FPR <= 0.04.
- **Unlabelled calibration** where 72–97% of calibration flows are malicious (3-1, 8-1,
  34-1): recall 0.00–0.02. Dominant malicious behaviour is learned as normal, the expected
  failure.
- Low-contamination scenarios (20-1, 21-1, 44-1) have only 1–2 attack windows each; recall
  is 1.0 in both variants, which is too few to support anything.
- **Device vs global** on single-device IoT captures: device is worse (3-1: 0.71 vs 0.97;
  8-1: 0.03 vs 0.97).
- **Detection delay:** Zeek logs a connection when it ends, so long-lived C&C flows are only
  visible hours later (median delay up to 12 h in 20-1). This is a limitation of
  connection-log monitoring.
- **Bug fixed:** IoT-23 headers and data join the last columns with spaces. Labels were
  silently missing in the first run, which was discarded. Regression test added.

### NF development data (`scripts/phase6/eval_nf_dev.py` -> `reports/phase6/nf_dev_{unsw,ids}.json`), exploratory

- **Leakage guard.** The chronological split is per day (`data/splits.py`), so consumed test
  rows sit at the end of every day. Only flows in the first 78% of each day's span are used.
  - A first UNSW run with a global 80% cut was discarded: it ended the dev period before any
    18 February attack.
  - Silent global windows are dropped, because excluded day-ends would look like silence.
- **Cost.** UNSW: 22 s, 0.96 GB. IDS: 1,184 s, **4.56 GB peak, over the 3.5 GB budget**.
  Cause: device windows for 5 variants held at once (1.25M windows each). Not repeated;
  future runs must process variants one at a time.
- **H2 (service vs global FPR at matched recall).**
  - IDS: robust-z 0.0006 vs 0.0996; Isolation Forest 0.116 vs 0.311. Met.
  - UNSW: degenerate (global operating recall 0).
  - Secondary, not pre-specified (FPR at recall 0.5): service 0.14–0.31 vs global 0.47–1.0
    on both datasets.
  - **Verdict: partially supported**; exploratory on development data.
- **H3 (device recall >= global + 0.05, FPR <= 1.5x).**
  - IDS Isolation Forest: 0.603 vs 0.223, at FPR 0.067 vs 0.311. Met.
  - Robust-z: 0 vs 0.004. Not met.
  - UNSW: the FPR clause is unattainable (global FPR 0).
  - IoT-23: device is worse.
  - **Verdict: not supported** as specified. Ranking evidence still favours device context:
    FPR at recall 0.5 is 0.05–0.09 vs 0.47–1.0 for global, on both NF datasets.
- **H4 (Isolation Forest ROC >= robust-z + 0.05 on >= 1 dataset).**
  - IDS service +0.069; IoT-23 34-1 global +0.092; UNSW device +0.038.
  - **Verdict: weakly supported.**
  - But Isolation Forest thresholds did not hold the FPR on IDS (0.31 global, 0.17
    service, against a 0.01 target).
- **H5 (contamination <= 5%: unlabelled recall >= 0.8x clean, FPR <= 2x).**
  - Isolation Forest device: IDS 0.603 clean -> 0.137 natural / 0.142 inj1 / 0.555 inj5 /
    0.153 inj10 (non-monotonic: single seed, unstable). UNSW 0.332 -> 0.023 (inj1) / 0.052
    (natural 1.9%).
  - UNSW inj5/inj10 are capped at the available attack flows (identical to natural).
  - **Verdict: not supported.**
- **Robust-z** ranks devices well (ROC 0.86–0.91) but its operating recall is about 0: the
  conformal threshold sits in the heavy benign tail.

### 6D application classification: pre-stated choices (before any 6D run)

- **Feature sets** (LightGBM, NF-v3 nDPI master label, benign flows, episode train/val):
  - `full` (nf_flow);
  - `full_noport`;
  - `noshortcut` (no TTL/TCP window);
  - `pcap_safe` (noshortcut minus `*_SECOND_BYTES`, whose nProbe semantics our extractor
    does not reproduce);
  - `portable` (15 Zeek/PCAP-common fields + protocol + port class);
  - `portable_noport`.
- **Product model:** the most portable set whose NF-IDS2018 validation macro-F1 is >= 0.9x
  `full`. Order of preference: portable > pcap_safe > noshortcut.
- **H6** is tested with `noshortcut` vs `full`, as pre-registered.
- **Abstention.**
  - Confidence threshold chosen on validation A for 95% accepted accuracy.
  - OOD = more than 30% of features outside the training [0.5%, 99.5%] range.
  - `missing_features` when a required field is null.
- **External check (H7):** CTU Zeek logs, with Zeek `service` as an independent reference
  for dns/ssl/http only.

### 6D/6F integration and an app-ID reliability problem

- **Implemented.**
  - `appintel/model.py`: abstaining classifier artifact (SHA-256 manifest, schema check);
    four separate fields (transport, app protocol, port-heuristic service, application
    identity = null).
  - `inference/pipeline.py`: evidence-aware decisions.
    - Supervised verdicts are suppressed (`unsupported_domain`) when calibration's domain
      check failed.
    - An anomaly alone is never `suspicious`.
    - Cold start gives `insufficient_data`, never `benign`.
  - `analyze --calibration --appid --threat-policy`; API `/behavior`, `/models` (calibration
    and classifier manifests); serve options and env fallbacks.
  - Event store: `behavior_events` table, plus v2 columns with automatic migration of old
    databases.
  - Dashboard: Network behaviour, Application intelligence and Model management pages.
    Historical research metrics are explicitly labelled as such.
  - docker-compose: optional read-only calibration/classifier mounts (**unverified**: no
    Docker here).
- **Tests.** End-to-end integration test extended: calibrate (refused without
  `--assert-benign`) -> analyze with calibration + classifier -> injected scan detected at
  device level -> forced unsupported domain -> API `/models`, `/behavior`, `/analyze` ->
  cold start -> corrupted calibration refused by CLI and API (`/ready` 503).
  **Full default suite: 83 passed.**
- **App-ID ablation run 1 (`reports/phase6/appid_v2.json`, 20 min, 1.0 GB) is NOT reliable.**
  - Several fits collapsed to near-majority predictions: NF-IDS `full_noport` 0.27,
    `noshortcut` 0.36, `pcap_safe` 0.51; NF-UNSW `full` 0.34. Other sets reached 0.70–0.95.
    The same configuration reached 0.94 in Phase 5.
  - Diagnosis:
    - (a) `training/appid._load` sorted by (day, event_sec) only. Tied rows came out of the
      join in arbitrary order, so the seeded subsample and the val A/B split differed
      between runs. Fixed by adding `row_id` to the sort.
    - (b) A collapsed fit did not reproduce in isolation: 8/8 repeated fits were identical
      and healthy (0.835 val acc). A repeat of the batch for UNSW failed on a different set
      (`pcap_safe`), and a third repeat had no failures.
    - Root cause of the collapses not yet identified. Each fit's training-sample accuracy is
      now recorded so a collapsed model is visible.
  - Run 1's H6 verdict ("not supported") and product selection are therefore discarded. The
    portable artifact it saved was not degenerate (0.945 macro-F1), but it is superseded by
    the re-run.
