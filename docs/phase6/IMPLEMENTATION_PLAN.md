# Phase 6 implementation plan

Written 2026-10-20, after the repository audit and **before** any Phase 6 model was fitted or
evaluated. Sections 4–5 (hypotheses, criteria, data roles) are frozen from this commit on.
Changes go into `DEVELOPMENT_LOG.md` with a reason.

## 1. Audit of the starting point (commit 9d742ec)

| Area | State | Reuse |
|---|---|---|
| Tests | baseline green: default suite passes (`uv run --extra torch --extra dashboard pytest`, 190 s), `ruff check` clean | keep |
| CI | `ruff format --check` would have **failed** on 6 Phase-5 files. **Fixed** in the first Phase 6 commit. CI installs base deps only; torch tests are guarded by `importorskip` | keep, re-check at 6G |
| Telemetry | PCAP/pcapng reader, flow assembler (validated vs Zeek), Zeek TSV/JSON reader, `records_to_frame` | reuse unchanged |
| Inference contract | `Prediction` (verdict, port-heuristic service, anomaly 0–100, threat), `Engine` (bundle-based, per flow) | extend: application block, behaviour block, evidence-aware statuses; keep `verdict` for backward compatibility |
| Bundle | threat model (NF-IDS2018, `nf_portable_ctx`), IForest anomaly reference, evidence RobustZ, SHA-256 manifest | keep as the "supervised evidence source"; restricted by a domain-support check |
| Event store | SQLite `events` (flow predictions), idempotent ids, retention | add a `behavior_events` table |
| CLI | data/features/train/bundle/replay/analyze/serve/evaluate | add `calibrate`, `behavior` scoring in `analyze`, `appid` bundle build |
| API | /predict, /events, /analyze, /replay, /models | add calibration info, behaviour events, application output |
| Dashboard | Streamlit pages over the event store | add Network Behaviour, Application Intelligence and Model Management pages, and calibration provenance |
| Docker | Dockerfile + compose written, never built (no Docker here) | review only; cannot verify locally |
| Unfinished | no calibration step; app-ID model research-only; anomaly reference transfers badly (CTU-26: 99% "unusual") | Phase 6 core |

**Compatibility constraints.**
- Zeek logs provide only the 15 portable fields plus ports, IPs and the Zeek `service`.
- PCAP flows provide all NF fields, but `*_SECOND_BYTES` semantics differ from nProbe, and
  TTL/window are host-stack shortcut candidates.
- Behaviour models must therefore be built on fields that **both** sources provide: counts,
  bytes, packets, duration, TCP flags, endpoints, ports, timestamps.

## 2. Minimum viable end-to-end path (built first)

`capture (PCAP/pcapng/Zeek)` -> flows -> **causal window aggregation** (global / device /
service) -> `netsentinel calibrate` (versioned behaviour profile with robust statistics and
validation-chosen thresholds, or a cold-start status) -> `netsentinel analyze --calibration`
-> behaviour events + per-flow assessments -> event store -> API/dashboard.

## 3. Design decisions

- **Windows.** Tumbling windows of 30 s and 300 s, with 5 s as an option. A flow belongs to
  the window containing its **end** time (the moment its record exists). A window's features
  become available at window end; detection delay is the window length plus the flow's own
  duration. No window uses data from a later window.
- **Entities.**
  - global: the whole capture;
  - device: the originating host (`src` of the flow);
  - service: the port category, or the ML application class when confident.
  - Hierarchical fallback is device -> pooled-device -> global. Profiles need at least
    `min_windows` observations (default 30) at their level.
- **Window features.** These are computable from Zeek and PCAP alike: flow count, log
  bytes out/in, packets, distinct destination hosts and ports, failed-connection fraction (no
  reply / RST / unanswered SYN), TCP/UDP/ICMP share, median log duration, upload share, and
  the fraction of destinations unseen in the calibration period.
- **Scores.**
  - Robust median/MAD z per feature on log1p values; the window score is the mean of the 2
    largest |z|.
  - The score is reported as an empirical tail percentile of held-out calibration windows,
    0–100, type `normalized_non_probability`.
  - Isolation Forest on the same features is the comparison model. A small autoencoder or
    temporal model is added only if the statistical baselines leave a clear gap.
- **Calibration.**
  - The calibration period is split chronologically: the first 70% fits profiles, the last
    30% sets thresholds at a target window FPR (default 1e-2 per entity-window).
  - Mode A, vetted benign: as above, and the operator assertion is recorded.
  - Mode B, unlabelled: iterative trimming (fit, drop windows above the 90th score
    percentile, refit; 2 passes) and threshold from trimmed held-out windows. Warnings are
    issued when trimming removes strongly clustered behaviour.
  - Mode C, cold start: fewer than `min_windows` global windows means no thresholds; status
    is `insufficient_history`, with diagnostics and a statement of the data still needed.
- **Supervised threat model.** During calibration its flag rate on calibration flows is
  measured. If it exceeds 10x its validation FPR (and 1%), threat verdicts are
  `unsupported_domain` and are never escalated to `suspicious`. Phase 5's CTU-26 run would
  have tripped this check.
- **Application intelligence.** Four separate fields:
  - `transport` (protocol number);
  - `app_protocol` (ML prediction of the nDPI master label, or an abstention reason);
  - `service_category` (port heuristic, labelled as such);
  - `application_identity` (always `null` unless a validated source exists; it never infers
    Chrome/Gmail from TLS).
  - Abstention reasons: `low_confidence`, `out_of_distribution`, `missing_features`,
    `unsupported_protocol`.
- **Adaptation policy.** Explicit periodic recalibration with rollback, rather than online
  learning. Profiles are immutable versioned artifacts. A drift check compares a recent
  period's window-score distribution to the calibration period's. The status is one of
  `collecting_baseline`, `baseline_ready`, `drift_suspected` or `stale`.
  - A new profile is produced only by an explicit `calibrate` call.
  - Windows above threshold are excluded from that call's fit in unlabelled mode.

## 4. Hypotheses and pre-specified criteria (frozen)

Evaluation unit: entity-windows. "FA/h" = false-alert windows per hour of evaluation time.
"Operating FPR" = window FPR on benign evaluation windows at the threshold chosen on
calibration data only.

| ID | Hypothesis | Data (role) | Supported if |
|---|---|---|---|
| H1 | Local calibration reduces false alerts on unfamiliar benign traffic | CTU-Normal-20..32 + CTU-26 (benign; each capture split in time: first 50% calibration, last 50% evaluation) | median over captures of evaluation FA/h with the local profile is <= 1/10 of the uncalibrated Phase-5 bundle's "unusual" flow rate, expressed per hour on the same captures, AND global-window FPR <= 3x the target in >= 75% of captures |
| H2 | Application/service-conditioned baselines lower false positives vs global | NF-UNSW + NF-IDS2018 interim, **only the first 80% of time** (dev); CTU logs | at matched evaluation recall on dev attack windows, service-conditioned FPR <= 0.8x global FPR on both NF datasets |
| H3 | Device-specific context improves detection of unusual behaviour | NF dev period; IoT-23 (labelled) | device-conditioned recall at the operating threshold >= global recall + 0.05 on both NF datasets, with FPR within 1.5x |
| H4 | A temporal or learned model beats robust statistics under some controlled condition | NF dev, IoT-23 | IForest (or AE) evaluation ROC-AUC exceeds robust-z by >= 0.05 on at least one dataset with the same windows |
| H5 | Calibration stays useful under modest contamination | NF dev with 1%, 5% and 10% injected attack windows in the calibration period; IoT-23 natural contamination | with <= 5% contamination, unlabelled-mode evaluation recall >= 0.8x the clean-mode recall AND FPR <= 2x |
| H6 | Application classification retains useful performance without host-stack shortcuts | NF-IDS2018 dev validation; IDS->UNSW shared classes | no-shortcut macro-F1 >= 0.9x full-feature macro-F1 on validation |
| H7 | Selective prediction improves reliability under distribution shift | CTU-Normal Zeek logs (Zeek `service` as an *independent* reference for dns/ssl/http); NF-UNSW | accuracy on accepted predictions exceeds accuracy without abstention by >= 0.05 on CTU, at coverage >= 0.5 |

Rules:
- H1, H5 and H7 use data never used before in this project (CTU-Normal-20..32, IoT-23).
- H2–H4 and H6 use NF data **for development only**: the consumed test rows (last 20% of
  time) are excluded, and results are labelled exploratory.
- IoT-23 per-flow labels come from the dataset authors; we do not verify them.

## 5. Data roles and provenance

| Data | Role | Licence / provenance |
|---|---|---|
| NF-IDS2018 / NF-UNSW interim (full flows with IPs) | development; first 80% of time only | UQ NetFlow v3, BagIt-verified |
| CTU-Normal-26 (PCAP + Zeek) | pipeline validation, H1 | Stratosphere, citation licence |
| CTU-Normal-20..25, 27..32 Zeek logs (47 MB) | H1, H7 (independent environments; most are the same lab host 10.0.2.15 on different days; 21 and 22 are a different network) | Stratosphere, citation licence; SHA-256 in `reports/audit/phase6_external_data_sha256.txt` |
| IoT-23 labelled Zeek logs, 9 scenarios (30 MB) | H3–H5 with labels (independent environment) | Stratosphere IoT-23 (Garcia, Parmisano, Erquiaga 2020), citation licence |

## 6. Execution order and resource rules

6A audit/plan -> 6B windows + profiles -> 6C calibrate -> 6D application model -> 6E
context experiments -> 6F end-to-end (analyze/API/dashboard/store) -> 6G hardening -> 6H
reports and audit.
- One ML process at a time.
- Anything expected to exceed 2 min, 2 GB or GPU 3 GB is estimated and run only after
  approval.
- Synthetic fixtures test software behaviour only.
