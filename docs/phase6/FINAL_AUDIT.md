# Phase 6 final audit (2026-10-20)

Stance: an external ML engineer checking each claim against artifacts in the repository.
Evidence paths are relative to the repository root.

## Answers to the audit questions

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Does local calibration reduce false positives? | **Yes, by about 50x on unfamiliar benign traffic, but its FPR target is not reliably met.** Median false-alert windows/h: 2.3 vs 120 (uncalibrated bundle). The global FPR exceeded 3x target in 5/12 captures (pre-registered H1 fails). Real PCAP: "unusual" 99.0% -> 1.1% | `reports/phase6/h1_ctu.json`, `ctu26_pcap_*.json` |
| 2 | Are calibration and evaluation data separated? | Yes. Chronological splits everywhere: the first 50% of time calibrates (first 70% of that fits, 30% sets thresholds), the later period evaluates. The demo uses `--until/--since` at the same cut | `behavior/calibrate.py`, `scripts/phase6/*`, `demo_ctu26_pcap.sh` |
| 3 | Is future-data leakage avoided? | Yes, for features: a flow counts in the window of its end time; a window's features use no later window (test). Destinations are "new" only relative to earlier windows or a frozen calibration set. NF development data excludes the consumed test rows (per-day 78% cut); one invalid first run was discarded | `tests/unit/test_behavior.py::test_window_features_are_causal`, `DEVELOPMENT_LOG.md` |
| 4 | Are device profiles statistically meaningful? | Only where a device has >= 30 calibration windows; otherwise it falls back to a pooled profile (`model_scope` says which). Device conditioning ranks attacks better on NF data, but did not meet H3; IoT-23 single-device captures gain nothing | `nf_dev_*.json`, `iot23.json` |
| 5 | Does application conditioning help measurably? | Port-heuristic service conditioning lowered FPR at fixed recall on NF development data (exploratory, partially supports H2). Conditioning on the ML application class was **not evaluated** | `REPORT.md` §4, §7 |
| 6 | Is the application classifier truly ML-based? | Yes: LightGBM on flow statistics, compared with a port lookup. Its target is nDPI's label, a proxy, not ground truth | `appintel/model.py`, `appid_v2.json` |
| 7 | Can it abstain when uncertain? | Mechanically yes (low_confidence / OOD / missing_features / unsupported_protocol; tested). **In practice it rarely abstains under real shift** (CTU coverage 0.9996, HTTP recall 0.42–0.72): H7 not supported | `tests/unit/test_appintel.py`, `h7_ctu_appid.json` |
| 8 | Are previous dataset shortcuts controlled? | For app ID: without TTL/window, macro-F1 is 0.944 vs 0.952 (H6). For behaviour baselines: only Zeek/PCAP-common fields are used; no TTL/window. The supervised bundle keeps its Phase 5 limitations | `appid_v2.json`, `behavior/windows.py` |
| 9 | Can unknown traffic be handled safely? | An anomaly is never "suspicious" by itself. Cold start gives `insufficient_data` (never benign). Unsupported protocols abstain. Supervised verdicts are suppressed when the domain check fails, **but the check passed on CTU-26 PCAP flows and 102 false "suspicious" remained** | `inference/pipeline.py`, integration test, `ctu26_pcap_phase6.json` |
| 10 | Does the system distinguish anomaly from attack? | Yes. Separate fields: `behavior` (normalized non-probability), `threat_status` (supervised evidence), `application`; verdict rules are documented and tested | `inference/schema.py`, `pipeline.py` |
| 11 | Can it process a real PCAP end to end? | Yes: CTU-26, 199,279 packets -> flows -> calibration -> analysis -> SQLite -> dashboard, through the CLI | `demo_ctu26_pcap.sh`, `DEVELOPMENT_LOG.md` |
| 12 | Is the dashboard showing genuine outputs? | Yes, verified in a browser against the CTU-26 event store. Counts equal the analysis summary. Historical research figures are labelled as such. One crash bug was found and fixed during the check | `docs/images/phase6_*`, `DEVELOPMENT_LOG.md` |
| 13 | Are model artifacts reproducible? | Calibration and classifier artifacts carry SHA-256 hashes, schema versions, hyper-parameters, periods, git SHA and library versions; tampering is refused (tested). App-ID training is now deterministic (tie-order fix). Exact re-derivation needs the local datasets, which are not distributed | `behavior/calibrate.py`, `appintel/model.py` |
| 14 | Are unsupported deployment claims removed? | Yes. README and dashboard state: detection-only, offline-first, not production-ready, supervised model does not transfer, calibration does not restore detection, proxy application labels | `README.md` |
| 15 | Could an independent ML engineer reproduce the results? | Yes, with the public datasets (download scripts and hashes recorded) and the scripts in `scripts/phase6/`. Runtimes and memory are recorded. Docker and CI have never been executed | `IMPLEMENTATION_PLAN.md` §5, `reports/audit/phase6_external_data_sha256.txt` |

## Deliverables

| Deliverable | Status |
|---|---|
| Functional `netsentinel calibrate` | Implemented and verified (tests; real CTU Zeek and PCAP) |
| Versioned behavioural profiles | Implemented and verified (hash/schema refusal tested) |
| Causal time-window processing | Implemented and verified (causality, end-time, out-of-order tests) |
| Statistical anomaly baseline (median/MAD) | Implemented and verified; evaluated (H1, NF development, IoT-23) |
| Evaluated ML anomaly detector | Research-only (Isolation Forest on windows in experiment scripts; not in the product) |
| Device-conditioned modelling | Implemented (device level with pooled fallback); evaluated; H3 not supported |
| Application-conditioned modelling | Port-heuristic service level implemented and evaluated; ML-application conditioning not implemented |
| Integrated application classifier | Implemented and verified (CLI/API/store/dashboard); quality limits in REPORT §5 |
| Unknown-category handling | Implemented and verified (abstention reasons; cold start; unsupported protocol) |
| Explicitly uncalibrated output semantics | Implemented (`normalized_non_probability`; confidence semantics fields) |
| Evidence-aware threat decisions | Implemented and verified |
| Updated CLI / API | Implemented and verified (integration tests) |
| Updated dashboard | Implemented and verified (browser smoke test on real events) |
| Live/streaming monitoring mode | Not implemented (offline only; deliberate, disabled-by-default requirement not exercised) |
| Docker | Implemented but not verified (Docker unavailable locally) |
| GitHub Actions CI | Implemented but not verified. The format-check failure it would have hit was fixed; it has never run (no remote, push needs authorisation) |
| Reproducible experiments | Implemented and verified (scripts + recorded outputs) |
| Research documentation / README | Done (`docs/phase6/REPORT.md`, `DEVELOPMENT_LOG.md`, README) |

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | High (fixed) | CI `ruff format --check` would fail (Phase 5 files) | Fixed in 6A |
| F2 | High (fixed) | Multiclass LightGBM (balanced class weights) diverged silently in app-ID training (training accuracy 0.25–0.56, raw scores about 2e7) | `max_delta_step=2.0` + divergence guard; runs 1–2 discarded |
| F3 | High (open) | The supervised domain check (10x validation FPR, 1% floor) is too lenient: it passed on CTU-26 PCAP flows and left about 31 false "suspicious" flows/h | Documented; `--threat-policy unsupported`; not retuned on the evaluation capture |
| F4 | High (open) | Calibration FPR not reliable under within-capture drift (H1 FPR criterion failed) | Documented; baseline state reports drift |
| F5 | High (open) | Contaminated (unlabelled) calibration destroys recall (H5; IoT-23) | Documented; vetted calibration required for detection use |
| F6 | Medium (fixed) | IoT-23 label columns not parsed (labels silently missing in a first run) | Reader fixed; regression test |
| F7 | Medium (fixed) | Non-deterministic sampling order in app-ID data loading | Tie order fixed |
| F8 | Medium (fixed) | Dashboard crashed on mixed ISO timestamps | Fixed; browser-verified |
| F9 | Medium (open) | NF-IDS development run peaked at 4.56 GB (over the 3.5 GB budget) | Documented; not repeated |
| F10 | Medium (open) | Unlabelled-mode design changed after seeing CTU results | Labelled exploratory |
| F11 | Medium (open) | Connection logs report long-lived connections only when they end, so delays can reach hours | Documented limitation |
| F12 | Low (open) | Isolation Forest thresholds miss their FPR target on NF-IDS development data | Research-only model; not in product |
