# Results at a glance

Every number links to its source. **Data role:**
- **C**: confirmatory (pre-registered, untouched data, one shot);
- **E**: exploratory (development data, or data already inspected);
- **V**: validation split of the training dataset.

## Supervised detection (benchmarks)

| Setting | Data | Result | Role | Source |
|---|---|---|---|---|
| In-domain, CIC-IDS2018 (LightGBM, flow features) | CIC test, once | recall 0.983 [0.93, 1.00] at FPR 0.0009; 0.735 without 4 artefact fields | C | `reports/experiments/test_v1/` |
| In-domain, NF-UNSW / NF-IDS2018 | NF final test (both-protocol intersection), 3 seeds | recall 1.000 at FPR 0.0006–0.0010 | C | `reports/experiments/results_final_nf.md` |
| Cross-network transfer IDS <-> UNSW | NF final test | ROC 0.37–0.66; source thresholds flag 35–99% of benign flows | C | same |
| Label-free target calibration of the transferred model | NF final test | 23–183 false flows/h, recall <= 0.005 | C | same |
| Unseen attack groups with causal context (CIC) | validation, 5 seeds | e.g. DoS-HTTP 0.05 -> 0.95, SSH 0.60 -> 0.998; web 0.015 | V | `reports/experiments/results_v3.md` |

## Local behaviour baselines (Phases 6–7)

| Setting | Data | Result | Role | Source |
|---|---|---|---|---|
| Uncalibrated bundle on unfamiliar benign traffic | 13 CTU Zeek logs | about 120 false-alert windows/h (window FPR 0.54–1.00) | C | `reports/phase6/h1_ctu.json` |
| Local calibration, split thresholds (Phase 6 H1) | same | 2.3 false-alert windows/h; FPR <= 3x target in 7/12 captures: **H1 not supported** | C | same |
| Same, cross-fitted thresholds (Phase 7) | same captures, re-used | FPR <= 3x target in 12/12; median FPR 0 | E | `reports/phase7/calibration_drift.json` |
| Cross-fit vs split recall on labelled IoT-23 | 9 scenarios | lower recall in 3-1, 34-1, 44-1; higher in 8-1 | E | `reports/phase7/threshold_methods_iot23.json` |
| Contaminated (unlabelled) calibration | IoT-23, NF development | recall collapses (e.g. 0.60 -> 0.14): **H5 not supported** | E | `docs/phase6/REPORT.md` §3–4 |
| Device / service conditioning vs global | NF development | better ranking (FPR at recall 0.5: device 0.05–0.09, service 0.14–0.31, global 0.47–1.0); H2 partial, H3 not supported | E | same |
| Real PCAP end to end (CTU-26), Phase 7 defaults | inspected | unusual 99.0% -> 1.2% of flows; 0 false suspicious (102 in Phase 6) | E | `reports/phase7/ctu26_pcap_phase7.json` |

## Application protocol identification (nDPI proxy labels)

| Setting | Data | Result | Role | Source |
|---|---|---|---|---|
| ML, portable fields, NF-IDS2018 | validation | macro-F1 0.945 (port lookup 0.840) | V | `reports/phase6/appid_v2.json` |
| Without TTL/window shortcuts | validation | 0.944 vs 0.952 full: **H6 supported** | V | same |
| ML vs Zeek service on real traffic | 13 CTU logs | accuracy 0.925 vs port rule 0.999; abstains on 0.04%: **H7 not supported** | C | `reports/phase6/h7_ctu_appid.json` |
| Conservative ML + port policy (Phase 7) | NF development; CTU descriptive | see `docs/phase7/RELIABILITY.md` P3 | V / E | `reports/phase7/app_policy_selection.json` |

## Phase 8 (temporal models, incidents, streaming)

- Development (exploratory): [`docs/phase8/DEVELOPMENT_LOG.md`](phase8/DEVELOPMENT_LOG.md).
- Confirmatory (pre-registered, IoT-23 49-1, fresh):
  [`docs/phase8/CONFIRMATORY_RESULTS.md`](phase8/CONFIRMATORY_RESULTS.md).

| Question | Data | Result |
|---|---|---|
| Do temporal scorers beat robust median/MAD? | IoT-23 + NF-UNSW dev (3 eligible units) | No: mean PR-AUC 0.846 (robust) vs <= 0.723 (EWMA, GRU, TCN, lag-IForest) |
| Same, fresh capture, clean calibration (H1a) | 49-1 | Supported: 0.928 vs 0.676 (EWMA), delta CI [0.22, 0.29] |
| Does EWMA cope better with contaminated calibration (H1b)? | 49-1 | Refuted: 0.638 vs 0.723; both lose the attacker (recall < 0.02) |
| Product FPR on a fresh network (H2) | 49-1 | Supported: 1.09% (CI 0.5-2.1%) at a 1% target, recall 1.00 |
| Incidents (H3) | 49-1 | Refuted: 45x alert reduction, but purity 0.10 (9 benign single-window incidents) |
| App-ID consistency abstention | NF dev | Unknown-protocol abstention 1% -> 41%, IDS accepted accuracy 0.992 -> 0.996; the port table alone wins across datasets (UNSW 0.990 at 0.856 coverage) |
| Streaming exactness and cost (H6, H7) | 49-1, 5.4M records | Identical windows and incidents under jitter and duplicates; 24.8k records/s, 2.99 GB |
| Update gate vs a 60 s scan | 12 CTU-Normal (dev) | Rate-only gate: 0/12 flagged; v2 (strong-outlier rule): 7/12, 0 false |

## Telemetry

| Check | Result | Source |
|---|---|---|
| PCAP flow assembler vs Zeek on CTU-26 (199,279 packets) | TCP flow count equal; 99.8% packet/byte agreement; close-linger bug found and fixed | `reports/audit/pcap_vs_zeek.json` |
