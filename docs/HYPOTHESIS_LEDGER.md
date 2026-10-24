# Hypothesis ledger (Phases 5-8)

One row per research claim, with the strongest evidence that exists for it. Status:

- **confirmed**: pre-registered, evaluated once on data not used for any choice, criterion
  met;
- **refuted**: same, criterion failed;
- **not testable**: pre-registered, but the fresh data did not meet the testability rule;
- **exploratory only**: evidence comes from development or already-inspected data;
- **open**: no evaluation yet.

"Independent replications" counts fresh captures or datasets with a confirmatory result.
One capture is n = 1.

## Supervised detection (Phase 5)

| Claim | Status | Evidence | Replications |
|---|---|---|---|
| LightGBM detects attacks in-domain at FPR about 1e-3 | **confirmed** | CIC test once (recall 0.983); NF final test, 3 seeds (1.000) | 2 datasets |
| Supervised models transfer across networks (IDS <-> UNSW) | **refuted** | NF final test: ROC 0.37-0.66 | 1 pair |
| Label-free target calibration rescues transfer | **refuted** | NF final test: recall <= 0.005 | 1 pair |

## Local behaviour baselines (Phases 6-8)

| ID | Claim | Status | Evidence | Open question |
|---|---|---|---|---|
| P6-H1 | Local calibration keeps FPR <= 3x target on unfamiliar benign traffic | **refuted** (split thresholds, 7/12); cross-fit 12/12 is *exploratory* (same captures) | CTU-Normal x13 | Cross-fit FPR on fresh benign traffic is only partly re-tested (P8-H2, 1 capture) |
| P8-H2 | Product calibration (cross-fit, vetted) FPR <= 3x target on a fresh capture | **confirmed, n = 1** | 49-1: 1.09%, CI [0.5, 2.1]% | more captures/families |
| P6-H2 | Service conditioning lowers FPR vs global | exploratory only (partial) | NF dev | — |
| P6-H3 | Device context improves detection | exploratory only (not supported as specified) | NF dev, IoT-23 inspected | — |
| P6-H4 | A learned model (IForest) beats robust statistics somewhere | exploratory only (weak) | NF dev, IoT-23 34-1 | — |
| P8-H1a | Robust median/MAD ranks windows better than the dev-selected temporal model (guarded EWMA), clean calibration | **confirmed, n = 1** | 49-1: PR-AUC 0.928 vs 0.676; 4 bootstrap blocks | GRU/TCN/lag-IForest **never tested on fresh data**; more captures |
| P8-H1b | Guarded EWMA beats robust_z under contaminated calibration | **refuted, n = 1** | 49-1: 0.638 vs 0.723 | — |
| P6-H5 | Calibration tolerates <= 5% contamination | exploratory only (not supported) | NF dev, IoT-23 | No confirmatory test at low contamination exists |
| — | Detection works under realistic (unlabelled) calibration when the attacker is present during calibration | **refuted in every exploratory setting**; 49-1 consistent (recall < 0.02) | | Fundamental limit, not a tuning issue |
| P8b-B1/B2 | Cross-capture supervised window LightGBM ranks better than local robust baselines (clean and contaminated calibration) | **replicated** (2 supported, 1 inconclusive, 0 refuted) | IoT-23 1-1, 60-1, 9-1: e.g. +0.082 / +0.018 (ns) / +0.063 | cross-network (non-IoT-23) test |
| P8b-B3 | GRU / TCN do not beat robust statistics | **replicated** (3/3) | robust ahead by 0.35-0.5 | |
| P8b-B4 | Product FPR <= 3x target on fresh traffic | **replicated** (3/3; 4/4 with 49-1) | 0.0-1.5% | |
| P8b-B5 | A transferred (source) threshold breaks the FPR target | **mixed** | 5.5% / 1.3% / 0.0% | |
| P8b-B6 | Incidents concentrate attack evidence (window-weighted purity >= 0.8, reduction >= 5) | **refuted** (2 refuted, 1 not testable) | product had no true detections | |
| — | The deployed baseline detects attacking devices on fresh captures | **contradicted (secondary metric)** | 0/4 attackers on 1-1, 60-1, 9-1 (49-1: 1/1) | root cause found (Phase 8c, below) |
| P8c | Why 0/4: the single device-level threshold is set by transient sources scored against the pooled fallback (100% of the tail on 1-1 and 9-1); 60-1: insufficient calibration | **explained retrospectively** (no coding defect; design defect in threshold pooling) | `docs/phase8c/ROOT_CAUSE.md` | does a corrected threshold policy work? Pre-registered as X2 (ToN_IoT) |
| P8c | LightGBM's advantage reflects a recurring scanning signature (a single feature matches it) | exploratory on IoT-23/UNSW; **not the whole story externally** | lgbm_audit.json; X4 | |
| P8c-X1 | Deployed FPR <= 3x target on an external network (ToN_IoT) | **refuted, n = 1** | FPR 8.9% [7.4, 10.5]; 19-day gap between calibration and evaluation | drift vs model failure not separable |
| P8c-X2 | Root-cause prediction (no tail warning, so the address-class threshold changes nothing) | **supported, n = 1** | diagnostic silent; recall 0.317 vs 0.314 | |
| P8c-X3 | Cross-network supervised LightGBM (no UNSW in training) ranks better than robust_z | **supported, n = 1** | ToN_IoT: 0.973 vs 0.695; 4 bootstrap blocks only | |
| P8c-X4 | LightGBM adds ranking beyond the scan signature | **supported, n = 1** | delta 0.147 [0.035, 0.262] | |
| P8c-X5 | Incidents: window-weighted purity >= 0.8 and reduction >= 5 | **refuted, n = 1** (0.779, 11x) | | |
| — | Detection delay on Zeek logs | exploratory only | IoT-23 20-1: up to about 12 h for long C&C | not measured confirmatorily |

## Incidents (Phase 8)

| ID | Claim | Status | Evidence | Open question |
|---|---|---|---|---|
| P8-H3 | Incidents reduce load >= 5x with mean purity >= 0.8 | **refuted, n = 1** | 49-1: 45x reduction, purity 0.10 (9 single-window benign incidents) | Why, and can a rule chosen on development data fix it on fresh data? (Phase 8b) |
| — | Each attacking entity forms one incident (no fragmentation) | exploratory only | demo 1/1; IoT-23 3-1 up to 10 per device; 49-1: 1 (not pre-registered) | |

## Application intelligence

| ID | Claim | Status | Evidence |
|---|---|---|---|
| P6-H6 | App classification works without host-stack shortcuts | exploratory only (supported) | NF dev validation |
| P6-H7 | Selective prediction improves app ID under shift | **refuted** | CTU x13, Zeek reference |
| P8-H5 | Class-consistency abstention raises unknown-protocol abstention without losing accuracy | **not testable** on 49-1 (25 reference flows); exploratory support on NF dev (1% -> 41%) | open |
| — | ML protocol ID beats the port table across networks | **contradicted** in exploratory data (UNSW: port 0.990 vs hybrid 0.779) | |

## Engineering claims (pre-registered, deterministic)

| ID | Claim | Status |
|---|---|---|
| P8-H6 | Streaming == offline under jitter and duplicates | **confirmed** (5.4M real records) |
| P8-H7 | < 3.5 GB peak and >= 20k records/s | **confirmed** (2.99 GB, 24.8k/s) |

## Summary of the evidence gaps

1. Every Phase 8 behavioural confirmation rests on **one** fresh capture, one malware family
   (Mirai) and 3.7 h of evaluation.
2. GRU, TCN and lag-IForest were rejected on development data only. Supervised window-level
   LightGBM was never compared on the same features.
3. Operational metrics (false alerts/h, detection delay, incidents/h) exist confirmatorily
   only for 49-1.
4. The incident failure (P8-H3) has not been explained or addressed.
5. Contaminated calibration remains the binding limitation, and nothing tested so far
   changes that.

Phase 8b (docs/phase8b/) addresses gaps 1-4 with fresh IoT-23 captures from other malware
families. Status: 1-1, 60-1 and 9-1 evaluated ([results](phase8b/CONFIRMATORY_RESULTS.md)). Gap 4 is explained (structural single-window false incidents), but
not solved.

## Phase 8d (operating points, drift, streaming; docs/phase8d/REPORT.md)

| Claim | Status | Evidence |
|---|---|---|
| The streaming clock bug changed the ToN_IoT evaluation windows | **refuted (post-hoc)** | identical record membership in all 5,820 windows, incl. 334 force-closed |
| Clock resync is safe against forged future timestamps | **refuted, then fixed** | 97% of genuine records dropped; probation limits loss to about 1,000 |
| A threshold policy is both within the false-alert budget and sensitive (development) | **not found** | only A + abstention is within budget: 4/10 attackers, 11/22 captures covered |
| LightGBM keeps the false-alert budget on benign development captures | **refuted** | max FPR 29% (local), 95% (source); device / hierarchical thresholds do not repair it |
| Window PR-AUC predicts attacker-level detection | **refuted (mechanism measured)** | window weighting, ranking-undetectable attackers (ToN: 26-36 of 40), threshold misplacement |
| Calibration validity decays with time since calibration | **exploratory, supported** | robust-z FPR 1.7% -> about 3% within 2-16 h; aged calibration up to 16% |
| Unlabelled drift alarms separate drift from attack | **refuted (exploratory)** | suspension removes 95% of false alerts and 93% of alerted attack windows |
| ToN_IoT labels follow the documented attacker-IP tagging | **contradicted in files 1-4** | 0 of 40 attack-labelled sources in 192.168.159.30-39 |
| X3/X4 intervals depend on the 4-block bootstrap | **direction robust (post-hoc)** | CIs exclude 0 at 60/15/5 min and iid |

## Phase 8e (evidence integrity, uncertainty, streaming security; docs/phase8e/REPORT.md)

| Claim | Status | Evidence |
|---|---|---|
| ToN_IoT attack labels identify attacking hosts | **refuted (retrospective, files 1-4)** | 3 initiators (192.168.1.30-32) are endpoints of 100% of attack flows; the other 37 labelled sources are responders; labels are flow-level, direction-agnostic and time-bounded |
| Frozen X policies detect the ToN_IoT initiators | **3/3 for every policy (retrospective)** | initiator window recall A 0.42, C2 0.43, E 0.56; frozen X verdicts unchanged |
| The Phase 8d probation resync survives adversarial timestamps | **refuted, then fixed** | before: up to 83% genuine loss, silent loss after a backward reset; quarantine state machine: 0 loss and 0 forged records in 10 scenarios; identical ToN_IoT windows |
| A per-population threshold policy meets FA/h budgets without degenerating (development) | **not found** | no policy passes the pre-declared rule; overruns are driven by shift (NF-UNSW local FPR 39% at 1%); never-alert rejected by the guard |
| Frozen 49-1 and ToN_IoT bootstrap intervals support inference | **reinterpreted as descriptive** | 4 blocks = 35 distinct resamples; verdicts unchanged (EVALUATION_METHODOLOGY.md) |
