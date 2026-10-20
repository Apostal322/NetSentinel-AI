# Final technical audit (v0.1, 2026-10-19)

Reviewer stance: an external senior ML engineer checking whether every claim in the
repository is supported by artifacts in it. Severity: **Critical** (invalidates a headline
claim), **High** (materially misleading or a missing core capability), **Medium**, **Low**,
**Research limitation** (a property of the data or scope, not a defect).

## Answers to the audit questions

| Question | Answer |
|---|---|
| Does the project solve the stated problem? | Partly. Flow-level threat detection, attack typing with abstention, anomaly scoring, replay, API and dashboard work end to end on real data. Application identification and per-device baselines were **not** achievable with IDS2018 (no application labels, no host ids) and are not claimed. |
| Are the datasets appropriate? | IDS2018 is standard but flawed (truncated files, label errors, 12-h clock); all flaws we found are documented and handled. A second dataset is needed for external validity. |
| Are the labels reliable? | No, not fully. Measured: 84.5 % of 02-28 Infiltration rows duplicate benign rows; 41.7 % of 02-23 web brute force is non-HTTP; FTP-BF and SlowHTTPTest are the same traffic. Mitigated by exclusion, cleaning and merging, not by relabelling. |
| Is the evaluation leakage-resistant? | Yes for the protocol (episode split, purge >= longest window, train-only preprocessing, test used once after pre-registration, automated checks). The report states that within-episode evaluation remains "seen attack" evaluation. |
| Do temporal models outperform baselines? | Context features: no gain on seen attacks (saturated), large gain on unseen families. Temporal DL (GRU over per-port sequences): marginal gain over an MLP control on seen attacks (5 seeds), below LightGBM; on unseen families better than flow-only models but far below LightGBM with explicit context (report 3.6-3.7, n=1). |
| Are results reproducible? | Configs, seeds, git SHA, package versions and split indices are recorded per run; the data pipeline is scripted and checksum-verified. Single seed only. |
| Are false positives adequately assessed? | FPR at fixed thresholds, per-day benign FPR, prevalence-weighted false-alert flows/hour on test. Incident-level alert counting exists in the dashboard but is not evaluated. |
| Are unknown threats honestly represented? | Yes: leave-one-family-out results are reported as development estimates; anomaly detection is reported as failing; verdict `unusual` is never presented as an attack. |
| Is application identification overclaimed? | No: outputs say `method: port_heuristic`. |
| Does the dashboard show real inference outputs? | Yes: it reads the event store written by the engine during replay, with a banner stating it is a replay of recorded data. Screenshots in the README are from the running app. |
| Are model versions tracked? | Yes: every prediction carries bundle and run ids; bundles have SHA-256 manifests. |
| Are the APIs functional? | Yes, covered by integration tests (TestClient) including validation and auth failures. Not load-tested. |
| Does offline replay work? | Yes: 120,000 recorded flows replayed at ~900 flows/s (measured, CPU, including persistence), idempotent ids. |
| Does the project handle invalid inputs? | Ingest fails loudly on malformed numerics, unknown labels and missing columns; the API rejects unknown fields, out-of-range ports, oversized batches and path traversal (tested). |
| Are trained models available or reproducible? | Reproducible by the documented commands; model files are not committed (size, pickle safety). |
| Are all README claims supported by evidence? | Checked line by line on 2026-10-19; numbers trace to `reports/experiments/` and `runs/` ids. |
| Would an experienced ML engineer trust the results? | The *negative and diagnostic* findings (artefact dependence, label issues, anomaly failure, split effects) are well supported. The absolute detection numbers should not be trusted beyond IDS2018. |

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| A1 | Critical (fixed) | Raw timestamps use a 12-h clock without AM/PM; temporal features and splits would have mixed morning and afternoon | Fixed at ingest, documented, unit-tested |
| A2 | Critical (fixed) | First split design (random 15-min blocks) put whole attacks in one partition; validation contained no HOIC-in-train | Replaced by episode split; kept as H5 comparison |
| A3 | High (fixed) | Initial ingest used >7 GB RAM on the 4 GB CSV | Rewritten as a streaming block reader |
| A4 | High (fixed) | Anomaly score saturated at 100 under drift, making thresholds ties | Continuous tail extension, tested |
| A5 | High (partly fixed) | Single seed in v1 | 5 seeds (model + split) for the main validation comparisons in batch v2: context and shortcut findings stable, flow-only open-set results seed-sensitive (std up to 0.24). Test, anomaly variants and GRU open-set remain n=1 |
| A6 | High (open) | No external dataset; shortcut and context findings may be IDS2018-specific | Roadmap item |
| A7 | Medium (fixed) | Calibrated-threshold field displayed `0` because isotonic is flat near the raw threshold | Replaced by explicit `decision_rule` |
| A8 | Medium (fixed) | Dashboard merged two capture days into one 385 h span; chart axis used a 12-h clock | One source at a time; 24-h labels |
| A9 | Medium (open) | Frozen LightGBM thresholds are ~1e-4; small shifts can move FPR (per-day test FPR 0-0.0016) | Documented; drift monitoring not implemented |
| A10 | Medium (open) | Logistic regression saturates; no usable threshold at FPR 1e-3 | Documented as a baseline limitation |
| A11 | Medium (open) | CI workflow never executed (no remote); Docker not available locally | Documented |
| A12 | Low (open) | `joblib` artifacts are pickles; integrity is hash-checked but not signed | Documented in threat model |
| A13 | Low (open) | Context for `/predict/flow` is unavailable (no history) and reported as missing; the replay path is the supported context path | Documented |
| R1 | Research limitation | No host ids / application labels in IDS2018 -> per-device baselines and application ID not testable | Documented |
| R2 | Research limitation | Attack family confounded with capture day; context gains on the family task partly reflect day identity | Quantified in the report |
| R3 | Research limitation | Seven source files truncated at the Excel row limit | Documented |

## Update 2026-10-19 (second audit cycle)

An independent validity audit (`docs/audit/validity_audit_2026-10-19.md`) found a critical
open-set leak through twin classes (fixed protocol, re-run: the context effect survives), a
robust-z implementation defect (fixed), Isolation Forest insensitivity (documented), fragile
operating points and flood-day false positives (documented). A second dataset family
(NetFlow v3, two datasets, identical features) shows saturated in-domain detection and **no
cross-network transfer** (`docs/experiments/report_v1.md` 3.9). These supersede the
"Do temporal models outperform baselines?" and generalisation answers above where they differ.

## Deliverables status

| Deliverable | Status |
|---|---|
| Functional ML pipeline, real dataset integration | Done, verified |
| Classical baselines | Done (5 models, 6 feature sets) |
| Temporal deep learning model | Done: GRU + MLP control trained on GPU, validation only (null result) |
| Anomaly detection component | Done; negative result reported |
| Application classification | Not achievable on IDS2018; port-derived service category only |
| Attack classification with abstention | Done |
| Unified inference, offline replay, API, dashboard | Done, tested |
| Automated tests, CI | 72 tests pass locally (incl. slow/data); CI (tests, Docker build + smoke, pip-audit, gitleaks) written, **not executed** (no remote) |
| Reports, research and security docs | Done (incl. validity audit, NF dataset card) |
| Second dataset / transfer | Done: NetFlow v3 UNSW-NB15 + IDS2018, in-domain, transfer, open-set (validation) |
| PCAP / Zeek offline analysis | Done (pure-Python readers, flow assembler, CLI, API upload, dashboard page); tested on synthetic captures only; nProbe agreement unverified |
| Docker / deployment | Dockerfile + compose written (non-root, read-only, localhost); **not built** (no local Docker) |
| Live capture, Suricata | Not implemented (out of scope: detection-only offline analysis) |


## Phase 5 addendum (2026-10-20)

Evidence: `docs/experiments/report_phase5.md` and the files it cites.

| # | Severity | Finding | Status |
|---|---|---|---|
| A6 | High | No external dataset | **Closed**: NetFlow v3 IDS2018 + UNSW-NB15 in-domain, transfer, adaptation and a pre-registered final test |
| A11 | Medium (open) | CI and Docker never executed | Still open: no Docker locally, no remote repository |
| P1 | High (fixed) | Flow assembler split every closed TCP connection into the connection plus a spurious 1–2-packet tail flow (found on real traffic against Zeek; 2,161 extra flows on CTU-Normal-26) | 5 s close linger, regression test, re-validated |
| P2 | High (open) | `*_SECOND_BYTES` fields mean bytes/s in our extractor but not in nProbe's NF-v3 export | `nf_flow*` models must not score PCAP-derived flows; the portable bundle does not use these fields |
| P3 | High (open) | The deployed bundle is uninformative on a new network: 99% "unusual", 21–34 false "suspicious" flows/h on real benign traffic | Documented; no product `calibrate` step yet |
| P4 | Medium (documented) | Final-test protocol deviation: the episode split phase depends on the seed, so the test sets of seeds 1 and 2 are not the pre-registered intersection | Primary analysis unchanged, seed-42 sensitivity reported; H3, H5 and H6 differ between the two analyses |
| P5 | Medium (fixed) | Decision-layer docstring claimed all thresholds were validation-tuned; the attack-type threshold is a fixed 0.6 | Docstring corrected |
| P6 | Medium (documented) | Unlabelled calibration with realistic contamination collapses recall even in-domain | Report §2; calibration must use vetted benign data |
| P7 | Research limitation | NF-UNSW autoencoder "detection" depends on attacker TTL / packet-size signatures and is seed-unstable (H5 failed) | No unknown-attack claim |
| P8 | Research limitation | NF-IDS2018 final test contains only botnet and 20 web rows | Stated with every IDS-target result |
| P9 | Research limitation | Application-ID target is nDPI's label (version assumed); host-identifying fields may let the model learn servers rather than applications | Validation-only, not deployed |

Updated answers:
- Unknown threats: still not detected by any label-free method at an operational FPR on
  IDS2018 data (final test).
- Application identification: a learned DPI-label classifier exists (validation only). The
  product still reports `port_heuristic`.
- Production readiness: **not production-ready**. It needs local retraining, a calibration
  workflow, Docker/CI execution and dashboard re-verification.
