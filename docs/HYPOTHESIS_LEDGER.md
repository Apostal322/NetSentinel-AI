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
| — | Supervised window-level LightGBM vs local baselines on the same window features | **open** | — | Phase 8b |
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

Phase 8b (docs/phase8b/) addresses gaps 1-4 with additional fresh IoT-23 captures from
different malware families.
