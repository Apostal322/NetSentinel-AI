# Phase 8s pre-registration: active, representative trusted calibration

**Registered:** 2026-11-09, committed before any candidate outcome was computed.

**Seen before registration:**
- the Phase 8r closure checks;
- the Stage 3 estimand analysis (SAMPLING_ESTIMAND.md; oracle description of the populations);
- synthetic unit tests (`tests/unit/test_phase8s.py`);
- dry runs printing timing lines only, whose output files were deleted:
  - three runs on NF-UNSW and NF-CIC 02-22 with 2 draws;
  - two of them stopped on aggregation errors, which were fixed (a missing `draw` column; a
    null-typed column).
- The synthetic test of the expected budget exposed a design defect: `tail` lost budget when
  heavy hosts capped at π = 1. It was fixed before registration (capped PPS on a mixed size).

**Code:**
- `scripts/phase8s/active_calibration.py` (designs, reviewer, estimators);
- `scripts/phase8s/experiments.py` (driver; information boundary, metrics, decision rules).

**Scores:** the frozen M2 construction as Phase 8o F0 (6 fits; K = 5).
- Unlabelled-memory hold-out and evaluation scores (`s_hold_u`, `s_ev_u`).
- Their SHA-256 hashes are checked against `reports/phase8o/experiment_d_scores_sha256.json` at
  run time.

**No model is trained. The memory is not changed** (Phase 8r: no memory candidate justified
refits). Any recall lost to the contaminated destination memory (NF-CIC 02-22, 03-02) stays lost.
It is reported, not attributed to calibration.

## 1. Information boundary

**Designs see a `Pool`:**
- host IDs, window counts, window end times;
- UDP share and destination-port counts;
- unlabelled hold-out scores.

**Labels live only in `Reviewer`,** an ORACLE-SIMULATED host review.
- It returns BENIGN / MALICIOUS / INCONCLUSIVE.
- It logs every request.
- It charges a SIMULATED cost of 1 per host plus 0.01 per window reviewed. This is not a measured
  analyst time.

**Hold-out reviews use `cal_truth`.** A host is malicious if any of its calibration windows is
labelled attack.

**Experiment E's in-period reviews use the audited evaluation categories of the first half of
the evaluation period only.** A host is malicious if any of its windows there is not
historical-benign.

**Evaluation labels enter only the metrics.**

## 2. Designs (expected budget k host reviews; Poisson)

| id | design | role |
|---|---|---|
| A0 | `random_host` (π = k/H) | Phase 8r reference |
| A1 | `random_window` (window rate p; π_h = 1 − (1 − p)^{n_h}) | window-representative control |
| A2 | `pps` (capped π ∝ n_h) | **primary candidate** |
| A3 | `stratified` (3 equal-window-mass strata, k/3 each) | candidate |
| A4 | `diversity` (greedy farthest-point on host features; deterministic, no weights) | control (C0 only) |
| A5 | `tail` (capped PPS on ½ activity share + ½ share of windows above the unlabelled 95th percentile) | candidate |

**Candidates:** A2, A3, A5. A0, A1 and A4 are controls. All designs are evaluated (saved-score
runs are cheap), and all are reported.

**Budgets:** k ∈ {10, 30, 100}. **Primary budget: k = 30.**
- NF-UNSW (21 hold-out hosts) and NF-BoT (15) are census-limited at k = 30. Every design reviews
  all hosts there at k = 30 and k = 100.

## 3. Estimators

Over the windows of verified-benign hosts. For A1 C0, only the drawn windows.

| id | rule |
|---|---|
| C0 | conformal rank, unweighted, capped at n (below 99 windows it is the sample maximum) |
| C1 | Hájek-weighted inverted-CDF (1 − α) quantile, weights 1/π_h |
| C3 | 90th percentile of C1 over 100 host-cluster bootstrap resamples; **abstains** with < 5 hosts at or above the C1 estimate, or a Kish window n_eff < 99 |

**C2** (stratified) equals C1 under these designs and is not separate.

**Empty trusted set:** abstain. Abstention means no alerts, so recall 0 and FPR 0.

## 4. Reviewers

| id | model |
|---|---|
| R0 | perfect |
| R1 | inconclusive 10 %, false benign 10 %, false malicious 2 % (host-level) |
| R2 | missing-not-at-random: inconclusive 40 % for hosts above the 90th activity percentile (10 % otherwise); false benign 25 %; false malicious 2 % |

**Inconclusive hosts are dropped.** "Delayed result" is modelled in E as a one-hour review delay.

## 5. Experiments

| experiment | cells |
|---|---|
| A, B, C | 6 designs × 3 budgets × R0 × {C0, C1, C3}; **20 draws** per stochastic cell (A4 is deterministic: 1 draw) |
| D | 6 designs × R1, R2 at k = 30; 20 draws |
| E | primary design and estimator (A2, C1), k = 30, R0; 20 draws; all cells evaluated on the **second half** of the evaluation period |

**Experiment E cells:**
- E0: hold-out review;
- E1: review restricted to the most recent half of the hold-out;
- E2 refresh: the whole budget spent on the evaluation period's first half, on windows ending at
  least 1 h before the switch;
- E3: E0, abstaining when the label-free KS distance between the hold-out and first-half
  unlabelled scores exceeds 0.10.

**References per fit:**
- U: the unlabelled T0;
- T: the benign hold-out T0 (oracle threshold; the threshold-only ceiling);
- P: the full oracle (P1x).

**Reproduction check:** U, T and P must reproduce Phase 8r (macro recall 0.372 / 0.656 / 0.869)
to 3 decimals before any decision is read.

**Resources:**
- estimated about 17 min CPU and 0.6 GiB peak (dry run: 20 s for 2 domains at 2 draws);
- capped runner; saved scores only.

## 6. Metrics

**Calibration error** (oracle metric, hold-out): `cal_error` = benign hold-out exceedance of the
threshold − α. The primary representativeness metric is |cal_error|.

**Evaluation (unlabelled-memory scores):**
- recall on V2 documented attackers;
- FPR on historical benign windows;
- false alerts per hour and per active benign host-hour;
- top-host share of false alerts;
- R₂₀, R₅₀, entities missed entirely;
- false alerts per detected entity.

**Acquisition:**
- reviews, benign verified, malicious found, inconclusive, review success;
- SIMULATED cost;
- trusted windows, hours and service profiles;
- Kish window n_eff, cluster n_eff, weight CV;
- tail hosts;
- HT-weighted trusted-set contamination;
- threshold bias against T.

**Aggregation (as in Phase 8r):**
- means over domains within a network per (fit, draw), then over (fit, draw);
- p10/p90 over draws;
- macro over networks;
- for |cal_error|, the median over (domain, fit, draw), with an empty trusted set counted as
  +∞.

## 7. Hypotheses and registered decision rules (`experiments.decide`)

**H1, representative sampling (gate B):** A2 + C1 against A0 + C0 at k = 30 under R0, on the median
|cal_error| per network. **SUPPORTED** if:
- A2 + C1 is lower on ≥ 3 of 4 networks; **and**
- its macro (each network's value capped at 1) is ≤ 50 % of A0 + C0's.

**Calibration quality (gate C):** A2 + C1, k = 30, R0. **SUPPORTED** if all of:
1. macro recall − U ≥ 0.10;
2. every network: mean FPR ≤ T FPR + 0.02;
3. every network: p90-over-draws FPR ≤ T FPR + 0.05;
4. every network: abstention ≤ 25 %.

**Detection usefulness (gate D):**
- **DEVELOPMENT GO** if gate C is SUPPORTED **and** the mean R₂₀ gain over U is ≥ 5 entities;
- otherwise **DEVELOPMENT NO-GO**.

**H2, two-dimensional budgets:** across all R0, C1 cells (designs × budgets × draws), per network.
**SUPPORTED** on ≥ 3 of 4 networks if the Spearman correlation of |cal_error| with the Kish window
n_eff is stronger in absolute value than its correlation with the verified-benign host count.

**H3, weighting:** the paired difference |cal_error(C1)| − |cal_error(C0)| under A2 at k = 30 (R0).
**SUPPORTED** if its median is < 0 on ≥ 3 of 4 networks.

**H4, reviewer error:** A2 + C1 at k = 30 under R1. **SUPPORTED** if both:
- the median HT-weighted trusted-set contamination is ≤ 1 % on every network; **and**
- criterion 2 holds.

**H5, temporal:** the median |FPR − α| on the evaluation second half. **SUPPORTED** if E2 < E0 on
≥ 3 of 4 networks.

**Comparisons.**
- **Primary comparison: equal expected review attempts.** Results are also reported against
  realised successful benign verifications and SIMULATED cost, with unsuccessful reviews always
  counted.
- **Paired comparisons** use the same (domain, fit, draw) seeds only where the seed is shared;
  designs draw independently.

## 8. Other gates

| gate | rule |
|---|---|
| A. Phase 8r engineering closure | PASS: the full suite on `bb9c9f2` has 0 failures and 0 errors, and CI status is documented. Recorded before this registration: **PASS** (419 passed; CI run 42521466177 success) |
| E. Independent confirmation | READY only with a frozen protocol **and** an eligible unused network (none known): NOT READY |
| F. Deployment | NO-GO unless independent evidence and authorization exist |

**Optional learned acquisition policy (Part 13): NOT RUN by registration.**
- Four development networks, of which NF-UNSW and NF-BoT are census-sized.
- They provide no independent training environments for nested selection of a learned selector.

## 9. Statistics

- **No p-values.** The registered medians and means decide.
- **Variability:** draws (p10/p90) and 6 correlated fits.
- **Dependence:**
  - windows are clustered in hosts;
  - the tail evidence on NF-UNSW, NF-ToN and NF-BoT is one to three hosts (SAMPLING_ESTIMAND
    § 3);
  - no window-level bootstrap is used for any interval.
- **Multiplicity:** one primary cell per hypothesis. Everything else is descriptive.

## 10. Amendments

All three were made after the results commit `a5161d9`, with outcomes visible. None changes a
registered verdict or a saved result.

| id | original | new | reason | outcomes visible? | effect |
|---|---|---|---|---|---|
| S-1 | `summarise` averaged recall with NaN for domains without documented attacks in a period | NaN recall excluded from means (abstention still counts as 0) | NF-CIC temporal recall printed as NaN | yes | reporting only. Gates A–D have no NaN. H5 uses FPR. The corrected temporal table is in `posthoc.json` (EXPLORATORY); the registered JSON is kept |
| S-2 | the frozen-score hash check passed files missing from the Phase 8o registry | fail closed | review finding D2 | yes | none: all 54 files were present and matched |
| S-3 | H1 and H3 count NF-UNSW and NF-BoT among "networks" | unchanged; **disclosed**: at k = 30 they are census-limited, so every design reviews the same hosts and the comparison reflects only the estimator's quantile definition | review findings C1 and C2 | yes | the verdicts stand as registered; their substantive support is 2 of 2 non-census networks (NF-CIC, NF-ToN) |
