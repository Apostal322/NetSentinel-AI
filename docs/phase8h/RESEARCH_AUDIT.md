# Phase 8h research audit: where the ML stands (2026-10-29)

**Scope.** This is a summary of evidence produced in Phases 5–8g. Every number has its
source in the cited document. Roles:
- **C**: confirmatory, data used once;
- **E**: exploratory, development or inspected data;
- **V**: validation split.

## 1. Research baseline table

| Model | Representation | Best in-domain | Cross-domain | Operating point | Role | Source |
|---|---|---|---|---|---|---|
| Flow LightGBM (Phase 5) | CICFlowMeter / nProbe flow features | CIC test: recall 0.983 at FPR 9e-4, PR-AUC 0.991. NF test: recall 1.000 at FPR ≤ 1e-3 | IDS2018 ↔ UNSW: ROC 0.37–0.66; source thresholds flag 35–99% of benign flows | fails out of domain | C | `reports/experiments/results_final_nf.md`, `docs/RESULTS.md` |
| Window LightGBM `lgbm_raw` (Phase 8b) | 12 window features (30 s, per source) | — | IoT-23 1-1 / 60-1 / 9-1: PR-AUC 1.000 / 0.945 / 1.000; 4/4 attackers; FPR 0–5.5% at the source threshold | local threshold: recall 0.999–1.0 at FPR 0–1.3% | C (cross-capture, same lab) | `reports/phase8b/confirm_all.json` |
| Window LightGBM (Phase 8c) | same, trained on IoT-23 + CTU-Normal | — | ToN_IoT: PR-AUC 0.973 vs robust 0.695; source threshold recall 0.856 at FPR 2.7% | local threshold: FPR 0.2%, window recall 0.337 | C (n = 1 network, 4 bootstrap blocks) | `docs/phase8c/EXTERNAL_RESULTS.md` |
| Window LightGBM `lgbm_local` | features standardised by the capture's own calibration median/MAD | — | Phase 8b development (3 eligible units): mean PR-AUC 0.890 vs `lgbm_raw` 0.901 | local threshold: mean recall 0.70 | E | `reports/phase8b/dev_compare.json` |
| LightGBM operating policies (Phase 8d) | — | — | 22 development captures: max FPR 29% (local threshold) and 95% (source threshold) | **never within the false-alert budget** | E | `docs/phase8d/REPORT.md` |
| Robust median/MAD baseline (deployed) | 12 window features, own profile or pooled fallback, top-2 \|z\| | IoT-23 49-1: PR-AUC 0.928, FPR 1.09% | 8b: PR 0.92–0.94 but **0/4 attackers** at its threshold. ToN_IoT: FPR 8.9% at a 1% target. CTU-13 sc. 9: 10/10 initiators, window recall 0.209, 0/803 verified-benign false alerts | threshold set by pooled-fallback transient sources (tail share 0.97) | C | Phase 8 / 8b / 8c / 8g reports |
| Best temporal model: guarded EWMA (GRU, TCN, lag-IForest also tested) | window sequences | development PR 0.723 vs robust 0.846 | 49-1: H1a robust better; H1b EWMA under contamination refuted. 8b: robust ≥ GRU/TCN in 3/3 | GRU/TCN flag about 46% of windows on 9-1 | C / E | Phase 8 / 8b |

## 2. What is already refuted (do not reintroduce without a new mechanism)

- **Supervised transfer across networks without local data** (Phase 5): label-free target
  calibration is refuted too.
- **Temporal deep models over robust statistics** (Phase 8, 8b): refuted three times.
- **Contamination robustness of calibration** (Phase 6 H5, Phase 8 H1b): refuted.
- **Incidents as false-alert reduction** (Phase 8 H3, 8b B6, 8c X5, 8g): refuted four times.
- **Per-population false-alert budgets** (Phase 8e): no policy kept every population within
  budget. Overruns come from the shift between calibration and evaluation, not from how the
  budget is allocated.
- **Drift-triggered or periodic recalibration; gated unvetted refresh** (Phase 8f, 8g V4):
  refuted, because it absorbs attacks.
- **"Window PR-AUC predicts attacker detection"** (Phase 8d): refuted.

## 3. Known shift failures, by mechanism

1. **Pooled-fallback tail.** Transient, mostly external sources without an own profile set
   the threshold and produce most false alerts:
   - 100% of over-threshold windows on IoT-23 1-1 and 9-1;
   - 385 of 428 false alerts in Phase 8f;
   - 98% of the CTU-13 background burden.
2. **Shift between calibration and evaluation.** NF-UNSW: realised FPR 39% at a 1% target.
   ToN_IoT: 8.9% after a 19-day gap.
3. **Feature semantics across telemetry.** nProbe fields (TCP flags) and Zeek fields
   (`conn_state`) produce the same feature names but differ in meaning.

## 4. Leakage and shortcut risks

- **Flow level:**
  - CICFlowMeter artefacts (`fwd_seg_size_min`, `init_fwd_win_byts`, `init_bwd_win_byts`,
    `fwd_header_len`);
  - TTL and TCP window fields, which identify hosts.
- **Window level:**
  - `new_dst_frac` is the top SHAP feature, i.e. a scan signature (Phase 8c audit);
  - absolute volumes (`log_flows`, `log_*_bytes`, `log_pkts`) encode network scale;
  - source identity is never a feature, but per-capture duplicates and heavy single sources
    dominate window counts (e.g. IoT-23 8-1: 1,441 attack windows from one device).

## 5. Label validity

| dataset | limitation |
|---|---|
| ToN_IoT | direction-agnostic flow labels: 37 responders counted as attackers; documented IP range absent |
| CTU-13 | IP-based labels starting about 2 h before infection; background is unknown, not benign |
| CIC-IDS2018 / NF-CIC | 84.5% of infiltration rows on 02-28 are identical to benign; FTP-BF and SlowHTTPTest are identical traffic; 41.7% of web brute force is non-HTTP |
| NF-UNSW | nDPI labels 52% of benign traffic as P2P (affects only application identification) |
| IoT-23 | per-flow `malicious` labels from the capture's design; the benign label is the dataset's, not independently verified |

## 6. Data roles

| status | data |
|---|---|
| **Consumed (confirmatory, never again as confirmation)** | CIC-IDS2018 test; NF final test (NF-UNSW and NF-CIC intersection); 13 CTU-Normal logs for Phase 6 H1/H7; IoT-23 49-1, 1-1, 60-1, 9-1; ToN_IoT Network_dataset_1-4; CTU-13 scenarios 9 and 10 |
| **Development (training and exploratory evaluation)** | 23 Phase 8b development captures (IoT-23 ×9, CTU-Normal ×13 incl. 26, NF-UNSW-NB15-v3 development part); NF-CIC-IDS2018-v3 development part (first 78% of each day; the consumed test starts at 80%), not yet windowed |
| **Not downloaded (possible fresh confirmation)** | further IoT-23 captures; CTU-13 scenarios other than 9/10 (`docs/phase8f/CTU13_ELIGIBILITY.md`) |

## 7. The decisive constraint for Phase 8h

**The development evidence has very few independent attack units.**
- Only **3 eligible attack units**: IoT-23 3-1, 34-1 and 8-1, one attacking device each.
- NF-UNSW adds 4 attackers.
- Three more IoT-23 captures contain 1–2 attack windows each. Everything else is benign.
- Every Phase 8b development comparison therefore rested on 3 units.

The NF-CIC-IDS2018 development part adds about 10 attack-bearing days, one dominant family
each, on one laboratory network. That makes leave-one-family-out within a network possible.
It is **not** evidence of cross-network generalisation.
