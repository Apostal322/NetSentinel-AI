# Phase 8b confirmatory results

- Plan: [RESEARCH_PLAN.md](RESEARCH_PLAN.md), frozen in `18c865f` before any fresh content
  was read.
- Code: `scripts/phase8b/confirm.py` at that commit.
- Raw output: `reports/phase8b/confirm_<capture>.json`.
- Deviations: none.

## Status of the fresh set

| Capture | Family | Status |
|---|---|---|
| IoT-23 1-1 | Hide and Seek | **evaluated** (`confirm_1-1.json`; 4.2 min, 1.23 GB) |
| IoT-23 60-1 | Gafgyt | not evaluated: download pending approval |
| IoT-23 9-1 | Hajime | not evaluated: download pending approval |

With one evaluated capture, every verdict below is **"supported, n = 1"** at most; none is a
replication yet.

## IoT-23 1-1 (Hide and Seek)

- **Data.** 1,008,748 records; 54% labelled malicious. Evaluation half: 56 h, 6,715 attack
  and 4,116 benign device windows; one attacking device. No late, duplicate or force-closed
  records.
- **Domain shift.** Median per-feature KS against the development benign windows: 0.77
  (development UNSW: 0.70).

| | Prediction | Result | Verdict |
|---|---|---|---|
| **B1** | cross-capture LightGBM PR-AUC > robust_z (clean) | 1.000 vs 0.918; delta 0.082, 95% CI [0.053, 0.110], 56 blocks | supported |
| **B2** | LightGBM > robust_z_product (unlabelled) | delta 0.081, CI [0.047, 0.120] | supported |
| **B3** | robust_z >= GRU and TCN | robust_z ahead by 0.348 [0.278, 0.394] and 0.350 [0.279, 0.395] | supported |
| **B4** | product FPR <= 3x target | 1.53%, CI [1.18, 1.95]%; 1.1 false alerts/h | supported |
| **B5** | transferred LightGBM threshold breaks the 1% target | FPR 5.47%, CI [4.79, 6.21]%; 4.0 false alerts/h | supported |
| **B6** | window-weighted incident purity >= 0.8 and alert reduction >= 5 | purity 0.00, reduction 1.4: all 63 product alerts were on benign devices | **refuted** |

### Operating points (clean calibration; secondary, pre-specified)

| scorer | PR-AUC | recall | FPR | false alerts/h | attacker detected |
|---|---|---|---|---|---|
| robust_z_product (deployed) | 0.918 | **0.000** | 0.015 | 1.13 | no |
| robust_z (split) | 0.918 | 0.000 | 0.015 | 1.13 | no |
| guarded_ewma | 0.586 | 0.000 | 0.009 | 0.64 | no |
| lag_iforest | 0.568 | 0.096 | 0.281 | 20.6 | yes |
| gru / tcn | 0.570 / 0.568 | 0.005 / 0.003 | <= 0.005 | <= 0.36 | yes, after 7.5 h / 13 h |
| lgbm_raw@source | 1.000 | 1.000 | 0.055 | 4.02 | yes, 0 s |
| **lgbm_raw@local** | 1.000 | **0.999** | **0.000** | **0.00** | yes, 0 s |
| lgbm_local@source | 0.993 | 0.939 | 0.005 | 0.36 | yes, 0 s |
| lgbm_local@local | 0.993 | 0.000 | 0.000 | 0.00 | no |

### What this capture adds

1. **Ranking is not detection.**
   - The deployed robust baseline ranks windows well (PR-AUC 0.92).
   - Yet at its calibrated operating point it **detects nothing**: every alert is a benign
     device's false alert. This is why B6 failed.
   - The infected device's attack windows are unusual relative to other windows, but not
     beyond the robust-z threshold learned from its *own* calibration windows. In "clean"
     calibration only attack flows are removed, so the same device's benign behaviour
     remains, and the threshold is set from all devices' tails.
2. **Cross-capture supervision transferred to a new malware family.** It was trained on 22
   development captures and never saw this capture or family. It separated attack windows
   almost perfectly.
   - With a threshold set on the target's own calibration windows, it reached recall 0.999
     at zero false alerts.
   - With the threshold transferred from development data, it exceeded the FPR target 5x
     (B5), which shows domain shift directly.
3. **GRU, TCN and lag-IForest are again far behind** the robust baseline in ranking (third
   independent negative: development, 49-1 (EWMA only), 1-1).
4. These are n = 1 results on a lab dataset whose other captures trained the model (see
   threats to validity in the plan).
   - Cross-family evidence on more captures (60-1, 9-1) is needed before any product change.
   - Supervised window scoring is **not** adopted in the product on this basis.
