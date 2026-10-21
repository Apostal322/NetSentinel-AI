# Phase 8b confirmatory results

- Plan: [RESEARCH_PLAN.md](RESEARCH_PLAN.md), frozen in `18c865f` before any fresh content
  was read.
- Code: `scripts/phase8b/confirm.py` at that commit, unchanged.
- Raw output:
  - `reports/phase8b/confirm_all.json`: the pre-registered aggregate over the three captures;
  - `confirm_1-1.json`, `confirm_60-1.json`, `confirm_9-1.json`: single-capture runs.
  - Verdicts and statistics are identical between the single and the joint runs
    (deterministic).
- Deviations from the plan: none.

## Fresh data

| Capture | Family | Bytes | SHA-256 | Run |
|---|---|---|---|---|
| IoT-23 1-1 | Hide and Seek | 148,305,428 | `953e8c27a9b2fcfc...0e63b86e232` | 4.2 min, 1.23 GB |
| IoT-23 60-1 | Gafgyt | 467,559,811 | `4e15902f6c39b1fa...af108ea7c0` | 6.1 min, 2.59 GB |
| IoT-23 9-1 | Hajime | 993,459,767 | `b2749ab394d6a8f9...7d0718de56c918b` | 8.7 min, 1.81 GB |

Data notes (as found, not chosen):

| | evaluation | attack / benign device windows | attackers | median KS shift to dev |
|---|---|---|---|---|
| 1-1 | 56 h, 54% attack flows | 6,715 / 4,116 | 1 | 0.77 |
| 60-1 | 12 h; almost all traffic is one attack burst in the evaluation half (calibration: 361 flows) | 32 / 232 | 2 | 0.68 |
| 9-1 | 12 h, 99.7% attack flows | 1,439 / 1,700 | 1 | 0.84 |

60-1 hit the pre-registered 1.5M-record buffer cap: 24 windows were force-closed (scored
early) during the burst. No capture had late or duplicate records.

## Pre-registered verdicts

| | Hypothesis | 1-1 | 60-1 | 9-1 | **Overall** |
|---|---|---|---|---|---|
| B1 | cross-capture LightGBM PR-AUC > robust_z (clean) | supported: +0.082 [0.053, 0.110] | inconclusive: +0.018 [-0.023, 0.060] | supported: +0.063 [0.034, 0.092] | **replicated** |
| B2 | LightGBM > robust_z_product (unlabelled) | supported: +0.081 [0.047, 0.120] | inconclusive: -0.008 [-0.034, 0.070] | supported: +0.110 [0.072, 0.148] | **replicated** |
| B3 | robust_z >= GRU and TCN | supported | supported | supported | **replicated** |
| B4 | product FPR <= 3x target | 1.53% [1.18, 1.95] | 0.00% [0, 1.58] | 0.82% [0.45, 1.38] | **replicated** |
| B5 | a transferred threshold breaks the 1% FPR target | supported: 5.47% | inconclusive: 1.29% [0.27, 3.73] | refuted: 0.00% | **mixed** |
| B6 | incidents: window-weighted purity >= 0.8 and reduction >= 5 | refuted (purity 0) | not testable (0 alerts) | refuted (purity 0) | **refuted** |

## Operating points (clean calibration; pre-specified secondary metrics)

| scorer | 1-1 recall / FPR | 60-1 recall / FPR | 9-1 recall / FPR | attackers detected |
|---|---|---|---|---|
| **robust_z_product (deployed)** | **0.000** / 0.015 | **0.000** / 0.000 | **0.000** / 0.008 | **0 / 4** |
| robust_z (split threshold) | 0.000 / 0.015 | 0.625 / 0.004 | 0.000 / 0.010 | 1 / 4 |
| guarded_ewma | 0.000 / 0.009 | 0.219 / 0.017 | 0.004 / 0.007 | 2 / 4 |
| lag_iforest | 0.096 / 0.281 | 0.375 / 0.052 | 0.001 / 0.002 | 4 / 4 |
| gru | 0.005 / 0.005 | 0.000 / 0.000 | 0.464 / 0.457 | 2 / 4 |
| tcn | 0.003 / 0.003 | 0.500 / 0.035 | 0.465 / 0.457 | 4 / 4 |
| **lgbm_raw@source** | **1.000** / 0.055 | **1.000** / 0.013 | **1.000** / 0.000 | **4 / 4** |
| lgbm_raw@local | 0.999 / 0.000 | 1.000 / 0.013 | 1.000 / 0.000 | 4 / 4 |
| lgbm_local@source | 0.939 / 0.005 | 1.000 / 0.013 | 0.165 / 0.000 | 4 / 4 |

Observable delay (end of the first attack window -> first alert): 0 s for lgbm_raw on all
three. GRU/TCN alerts on 9-1 are no signal: they flag about 46% of all windows.

## Conclusions (what the evidence now supports)

1. **The deployed local baseline is quiet but blind on fresh IoT malware captures.**
   - It met its false-alert promise on all three (B4 replicated; with 49-1, 4 of 4 fresh
     captures).
   - But it detected **none of the 4 attacking devices** at its operating threshold, although
     its ranking quality is good (PR-AUC 0.92-0.95).
   - On 49-1 (Phase 8) it did detect the attacker; on development data 9 of 10.
   - This is the most important product finding of Phase 8b. It is **not explained yet**.
     Candidate causes, for development-data investigation only:
     - cross-fit thresholds learned from all devices' tails;
     - per-device profiles of the infected device in oracle-clean calibration;
     - attack windows not exceeding the top-2 |z| threshold while still ranking above
       benign windows.
2. **Cross-capture supervised window scoring replicated as the better ranker** (B1/B2,
   2 supported, 1 inconclusive, none refuted).
   - It also detected every attacker, with false-alert rates of 0-5.5% depending on the
     threshold.
   - The training data are other IoT-23 captures, NF-UNSW and CTU-Normal. The fresh captures
     share IoT-23's lab, devices and labelling, so this is **cross-capture/cross-family**,
     not cross-network, evidence.
3. **Deep temporal forecasters lose to robust statistics**, replicated on 3/3 fresh captures
   (plus development data and 49-1 for EWMA). Deep learning is not the missing piece here.
4. **Threshold transfer is unpredictable** (B5 mixed: 5.5%, 1.3%, 0.0% FPR). A fixed source
   threshold is not a reliable operating point on a new network.
5. **Incident aggregation remains refuted.** Here the reason is upstream: the deployed scorer
   produced no true detections, so incidents could only contain false alerts.

**Not changed in the product on this basis.** Adopting supervised window scoring would need:
- a pre-registered test on a non-IoT-23 network;
- a decision on how its threshold is set (local calibration worked best here);
- an explanation of conclusion 1.
