# Phase 8b research plan (pre-registration)

Written and committed before any content of the fresh captures was read. At freezing time only
their names, sizes and SHA-256 (where downloaded) are known. Analysis code:
`scripts/phase8b/confirm.py` with `harness.py` and `scorers.py`, frozen in the same commit. It
was dry-run only on development captures. Deviations go in "Deviations".

## Data roles

| Data | Role |
|---|---|
| IoT-23 x9 (Phase 6 set), NF-UNSW-v3 development part, CTU-Normal x12 | development (inspected): all choices below, LightGBM training data |
| IoT-23 49-1 | consumed by Phase 8; **not used** (neither training nor evaluation) |
| CIC / NF test sets | spent; not used |
| **IoT-23 1-1** (Hide and Seek; 148,305,428 B; SHA-256 `953e8c27...b86e232`) | **fresh, confirmatory** |
| **IoT-23 60-1** (Gafgyt; 467,559,811 B) and **9-1** (Hajime; 993,459,767 B) | **fresh, confirmatory, if downloaded** (pending download approval). A capture not downloaded before the run is reported "not evaluated" |

Licence: CC BY 4.0 (Zenodo 10.5281/zenodo.4743746). Labels: authors' per-flow `label`
("Malicious*" = attack). Each capture is a different malware family from 49-1 (Mirai).

## Protocol (identical to development, `scripts/phase8b/harness.py`)

- **Windows.** Device level, 30 s windows by flow end time.
  - Calibration = flows ending before the time midpoint; evaluation = the rest.
  - Calibration variants: clean (benign-labelled flows) and unlabelled (all).
  - Streaming with lateness 3,700 s.
- **Scorers** (`scorers.py`), all on the same 12 window features:
  - robust_z, guarded_ewma, lag_iforest, gru, tcn: split-conformal threshold, 1% target, from
    target calibration;
  - robust_z_product: cross-fit thresholds;
  - lgbm_raw and lgbm_local: LightGBM trained once on **all 22 development captures**
    (clean calibration + evaluation windows; equal weight per capture, balanced classes;
    seed 0). Thresholds `@source` (1% FPR on development benign windows) and `@local`
    (split-conformal on target calibration).
- **Metrics.**
  - PR-AUC, ROC-AUC;
  - recall, FPR and false alerts/h at each scorer's threshold;
  - entity detection and observable delay: end of the first attack window -> first alert;
  - delay from attack start;
  - domain shift: per-feature KS statistic between development benign windows and target
    benign evaluation windows.
- **Uncertainty.**
  - Per capture: moving-block bootstrap over 1 h blocks of evaluation window end time, 2,000
    resamples, seed 0; percentile 95% CIs of PR-AUC differences.
  - Proportions: Clopper-Pearson.
- **Testability** (per capture and variant): >= 60 calibration windows, >= 5 attack and
  >= 30 benign evaluation windows. Otherwise "not testable".
- **Aggregation over captures.**
  - Each hypothesis gets a per-capture verdict: supported / refuted / inconclusive /
    not testable.
  - Overall:
    - **replicated** = supported in >= 2 testable captures and refuted in none;
    - **supported, n = 1** = one testable capture, supported;
    - **refuted** = refuted in a majority of testable captures;
    - otherwise **mixed**.

## Hypotheses (predictions from docs/phase8b/DEVELOPMENT_LOG.md; development is exploratory)

| ID | Statement | Statistic | Supported if | Dev evidence |
|---|---|---|---|---|
| **B1** | Cross-capture supervised LightGBM ranks windows better than the local robust baseline (clean calibration) | PR-AUC(lgbm_raw) - PR-AUC(robust_z) | 95% CI > 0 (refuted if < 0) | 0.901 vs 0.846 (3 units; UNSW 0.80 vs 0.60) |
| **B2** | ... and is more robust to contaminated calibration | PR-AUC(lgbm_raw) - PR-AUC(robust_z_product), unlabelled | CI > 0 | 0.862 vs 0.766 |
| **B3** | Recurrent / convolutional forecasters do not beat robust statistics | PR-AUC(robust_z) - PR-AUC(gru), and the same for tcn, clean | both CIs > 0 (refuted if either < 0) | 0.846 vs 0.682 / 0.682 |
| **B4** | Product calibration keeps its false-alert promise (replication of P8-H2) | realised FPR of robust_z_product on benign evaluation windows, clean | FPR <= 0.03 and CP upper <= 0.05 (refuted if lower > 0.03) | 49-1: 1.09% |
| **B5** | A threshold transferred from development data does NOT keep the FPR promise on a new network | FPR of lgbm_raw@source on benign evaluation windows, clean | CP lower bound > 0.01 (refuted if upper <= 0.01) | dev median FPR low, but UNSW about 41 false alerts/h |
| **B6** | Incidents concentrate attack evidence (replaces P8-H3's incident-mean purity) | window-weighted incident purity and alert reduction, robust_z_product, clean, gap 300 s | ww-purity >= 0.8 AND reduction >= 5 (not testable with < 5 incidents) | dev ww-purity 0.84; reduction about 6x |

**Secondary, pre-specified, no verdict:**
- incident-mean purity: expected low; it shows the P8-H3 mechanism;
- benign-only incidents/h;
- observable delay of robust_z_product (dev median 255 s);
- lgbm_local vs lgbm_raw;
- lag_iforest and guarded_ewma deltas;
- recall at 1% FPR (oracle);
- per-feature domain shift.

**Exploratory, after results:** anything else, labelled as such.

## Threats to validity

- IoT-23 captures share a lab, a labelling procedure and IoT-device benign traffic.
  "Cross-capture" is weaker than cross-network. Development included 9 IoT-23 captures, so
  LightGBM has seen IoT-23-style benign traffic; UNSW is the only cross-dataset source.
- Captures are often attack-dominated (49-1: 99.9% attack flows). PR-AUC then depends on base
  rates; comparisons are within capture only.
- The development evidence for B1/B2 rests on 3 eligible units. B3 replicates a Phase 8
  development finding; H1a tested only EWMA.
- The "clean" variant uses labels (oracle vetting) and is an optimistic upper bound.
- Delay: Zeek logs a connection when it ends, so delays from attack start include logging
  delay.

## Deviations

None at freezing time.
