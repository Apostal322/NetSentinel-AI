# Phase 8n pre-registration

**Written:** 2026-11-03.
- **Seen beforehand:** the Phase 8m results and the first Phase 8n diagnostic (GAP_REGISTER.md).
- **Not yet run:** no Experiment A perturbation, apart from the P_ref reproduction check on
  NF-CIC seed 0.

**Status: REGISTERED DEVELOPMENT DIAGNOSTIC.**
- The four development networks are consumed.
- Nothing here is independent confirmation, and no model is selected by Experiment A.
- **Experiments B and C** (candidate training changes and the GO/NO-GO rule) are registered as an
  amendment *after* Experiment A's results and *before* any candidate is trained. They depend on
  the mechanism A finds, and fixing them first would be guessing.

## Experiment A: isolating refit fragility

**Code:** `scripts/phase8n/fragility.py` (fits) and `scripts/phase8n/analyze_fragility.py`
(metrics).

**Protocol: Phase 8j P1x, unchanged.**
- B-raw LightGBM: 200 trees, 15 leaves, learning rate 0.05, `min_child_samples` 20, `subsample`
  and `colsample_bytree` 0.8, `n_jobs` 2 (`scripts/phase8i/common.py` `LGB`).
- Network-balanced and class-balanced weights; 50,000-window cap per source domain.
- Leave-one-network-out sources; P1x calibration; T0 = conformal rank at α = 1 % on the last 30 %
  of calibration slots.

**Replicates r ∈ {0, 1, 2}.** Each replicate fixes the LightGBM seed and the subsample seed
(P_ref: both = r).

| factor | arm | what changes | information |
|---|---|---|---|
| reference | P_ref | nothing; must reproduce the Phase 8j B0 scores (max \|Δ\| recorded) | — |
| A2 no-op | `A2_reverse_columns`, `A2_constant_column`, `A2_sqrt_new_dst_frac` | column order; an extra constant column; a monotone transform | preserved |
| A3 substitution | Q1 from Phase 8m (reused) | the B0 model; novelty input replaced, no refit | changed input only |
| A4 removal | `A4_drop_<f>` for each of the 12 features | one column removed, then refit | one feature lost |
| A4 control | `A4_shuffle_new_dst_frac` | column kept, values permuted within each training domain | lost, layout kept |
| A5 randomness | `A5_lgb_seed` (LightGBM seed 100 + r, sample 0); `A5_sample_seed` (LightGBM 0, sample 100 + r); `A5_host_bootstrap` (source hosts resampled with replacement, whole hosts) | randomness only | preserved |
| A6 weighting | `A6_double_<net>`: one source network's weight × 2 | domain influence | preserved |

**Measures** (per domain and replicate, from saved scores):
- T0;
- window recall;
- verified-benign FPR and false alerts;
- ROC AUC;
- ranking recall at the benign 99th percentile (an oracle quantity, used only to separate ranking
  from threshold effects);
- entity recall and undetected entities (sources with ≥ 5 attack windows);
- median delay;
- Spearman correlation of the scores with P_ref.

**Definitions, fixed now:**
- **Catastrophic failure:**
  - on one domain and replicate, window recall falls by ≥ 0.5 against P_ref of the same
    replicate; **or**
  - an entity that P_ref detects is not detected at all.
- **Mechanism of a recall failure:** *ranking* if the ranking recall at the benign 99th percentile
  also falls by ≥ 0.5; otherwise *threshold*.

**Diagnostic hypotheses.** Focus cases: NF-CIC 02-14, 02-16 and 02-21, 3 replicates each, so 9
cases per arm.

| hypothesis | statement | reading |
|---|---|---|
| HA1, generic fragility | the information-preserving arms (A2, A5, A6) cause catastrophic failures in ≥ 3 of the 9 focus cases per arm | supported if ≥ 1 such arm reaches 3 |
| HA2, feature-specific | removing `new_dst_frac` (`A4_drop_new_dst_frac` **and** `A4_shuffle_new_dst_frac`) causes catastrophic failure in ≥ 6 of 9 focus cases, while no A2 arm exceeds 2 | supported / not supported |
| HA3, descriptive | which other single-feature removals cause catastrophic focus failures, and the dominant mechanism (ranking or threshold) | descriptive |

**How the results will be used:**
- **HA1 supported:** training stability (seed and sample aggregation, regularisation) is the
  primary target of Experiment B.
- **HA2 supported and HA1 not:** the problem is feature dependence. Experiment B then targets the
  model's reliance on interactions involving that feature, for example feature-bagged ensembles
  or regularisation of split usage.
- **Both, or neither:** reported as found. Experiment B is then designed for the observed
  mechanism.

**Statistical units and their limits:**
- A day with 1 attacker entity is 1 unit, whatever its window count.
- Focus-day results are reported per case (domain × replicate), with no interval.
- Network means are descriptive.

**Resources:**
- 23 arms × 3 replicates × 4 source sets, ≈ 270 LightGBM fits plus scoring;
- measured ≈ 7 s per fit and 1.5 s per scored domain;
- estimate 45–75 min, peak ≈ 1.6–2.2 GiB under `run_capped` (3.4 GiB);
- CPU only, sequential;
- run only after the user authorizes it (CLAUDE.md: training > 2 min).

## Amendments

### Amendment 1: Experiments B and C

**Written:** 2026-11-03.
- **Seen beforehand:** Experiment A's results (TRAINING_STABILITY.md) and B0's entity stability
  across its 6 Experiment A fits, which was computed only to check that the rule below is
  attainable.
- **Not yet trained:** no candidate.

**What Experiment A established:**
- B0's NF-CIC detections depend on information in `new_dst_frac` (HA2).
- Single-attacker days flip as a whole under small changes of the training *data* (HA1, through
  the host bootstrap; 7 of 24 single-attacker-day cases flip under the data-perturbation arms),
  while optimizer randomness alone does not.

The candidates target that data sensitivity. They keep every feature, because removing features
was shown to destroy detection.

| model | definition | justification |
|---|---|---|
| **M0** | B0: the Phase 8i LightGBM, 12 features | reference |
| **M2** | mean probability of 5 B0-configured models, each with its own training-subsample seed and LightGBM seed | averaging over the subsample draws that flipped 02-14 and 02-16 |
| **M1** | mean probability of 5 models, each trained on its own host bootstrap of the training data | bagging over the source *population*: the perturbation that flipped 02-16 in 3 of 3 |
| **M3** | one model with `min_child_samples` 200 and `reg_lambda` 5 (nothing else changed) | a smoother decision boundary, so dense attack clusters are less likely to cross the benign tail |

**Seeds.** Member m of replicate r uses LightGBM seed 1000 + 10r + m. M2's members also use
subsample seed 1000 + 10r + m; M1's inner host bootstrap is drawn with seed (18, r, m, source
domain).

**Feature bagging is not run.** Experiment A showed that removing `new_dst_frac` or `log_flows` is
catastrophic, so random-subspace members would carry that failure into the average.

**Two training regimes,** each with replicates r ∈ {0, 1, 2}, so each model has 6 fits:
- **base:** the Phase 8j training data with subsample seed r (for M0 exactly P_ref);
- **stress:** the source hosts first resampled with replacement, with seed (8, r, source domain),
  exactly as `A5_host_bootstrap`, and then the model is built on that data. For M0, stress =
  `A5_host_bootstrap`.

**Calibration and evaluation are unchanged:** P1x hold-out, T0 at α = 1 %, the evaluation windows
of Phase 8j. No threshold uses evaluation labels, and nothing is tuned on the evaluation.

**Measures.** All of Experiment A's measures, plus false alerts per hour.

The entity measures cover the 75 entities (sources with ≥ 5 attack windows):
- **R:** the number of entities detected in all 6 fits;
- **U:** the number detected in some but not all;
- **N:** never detected.

**Development GO rule for a candidate. All must hold:**
- **G1, detection (non-inferiority).**
  - On every network, its mean window recall over the 6 fits is ≥ M0's − 0.05.
  - Its pooled entity recall (mean over fits) is ≥ M0's − 0.02.
- **G2, workload.** Mean false alerts ≤ 1.25 × M0's on every network.
- **G3, robustness (primary).** U ≤ U(M0) − 3, and R ≥ R(M0).
  - Attainability: on Experiment A's fits, M0 has R = 46, U = 9, N = 20.

**Selection:**
- If several candidates pass, choose the one with the largest R; ties go to the simpler model
  (M3, then M2, then M1).
- If none passes: development NO-GO, and B0 stays.
- A development GO is a candidate for an independent test. It is not deployment.

**Units and limits:**
- The 75 entities are not independent: NF-CIC contributes 52, from 6 days of one network, and
  entities on one day share an attack campaign.
- G3 is a count over correlated units with no interval. It is a development screen, not a test.
- The 4 networks enter G1 and G2 one by one. With 4 units, no cross-network p-value is
  claimed.
- Q1 (Phase 8m) and Experiment A are not reused for selection.

**Resources:**
- 288 LightGBM fits (M0 24, M1 120, M2 120, M3 24) and member scoring;
- estimate 75–110 min, peak ≈ 2 GiB under `run_capped`, sequential;
- run only after the user authorizes it.
