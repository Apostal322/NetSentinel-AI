# Phase 8t final report: host-conditional and hierarchical calibration

**Question.** Can host-conditional or hierarchically pooled calibration detect attacks materially
better than one global threshold, at the same 1 % false-alert budget and with realistically
available calibration information?

**Answer on development data: no.** The limit lies in the scores, not in the threshold.

**At a true global 1 % benign-window FPR, the frozen M2 detects** (deployable memory):

| network | recall | normalised partial AUC (FPR ≤ 1 %) |
|---|---|---|
| NF-CIC | 0.50 | 0.44 |
| NF-UNSW | 0.02 | 0.012 |
| NF-ToN | 0.007 | 0.003 |
| NF-BoT | 0.57 | 0.58 |

- On NF-UNSW and NF-ToN, documented attacks score *below* the benign median in most service
  profiles.

**A retrospective oracle with service-profile thresholds raises macro recall from 0.275 to 0.491**
at the same budget.
- It does so mostly by spending the alert budget where it *knows* the attacks are.

**Deployable versions calibrated only on benign data recover none of it:**
- hierarchical pooling: 0.270 vs 0.275 global;
- per-host thresholds: 0.241.

**Reported first, at the reviewer's request:**
- **The as-calibrated thresholds reach recall about 0.66 only by running at 4–16× the 1 % FPR
  target** (NF-ToN 16 %, NF-BoT 9 %, NF-UNSW 3.8 %).
- **10–17 of 48 documented attackers are missed entirely** under every method.

## Decisions

| decision | verdict | basis |
|---|---|---|
| research completion | **GO** (completed) | all registered stages ran; stopping rules applied |
| host-conditional feasibility | **NOT SUPPORTED** | per-host oracles are host-identity memorisation on this benchmark (no host has both classes). The constrained group oracle passes G1 retrospectively (+0.216), but the deployable version does not (H1: −0.005) |
| hierarchical calibration improvement | **NOT SUPPORTED** for detection | pooling improves the transfer of group thresholds (H2 SUPPORTED, 3 of 4 networks) but adds no recall (H1, gate) |
| operational detection improvement | **DEVELOPMENT NO-GO** | as calibrated, D2 vs D0: macro −0.003, R₂₀ +0.7; H1 failed |
| independent validation | **NOT READY** | no unused eligible network |
| deployment | **NO-GO** | — |

**Further threshold engineering should stop.** Under the current score representation, no
conditional or pooled threshold showed a deployable path to better detection at 1 % FPR. **The
next phase should target the scoring model** (§ Recommendation).

## Repository

**Commits:**
- **Start:** `f4f712e` (= `origin/main`, CI run 42533247601 success), with a clean tree.
- **Commits:**
  - `05b8dc3`: registration;
  - `caaa602`: oracle results and A-1;
  - `ebe8596`: deployable code;
  - `9bf9611`: first run and A-2;
  - `eb2c4bb`: r2;
  - `ec091fe`: A-3;
  - `973d7a4`: r3;
  - review and closure follow.

**Push:** not pushed (needs authorization).

**New code:**
- `scripts/phase8t/{threshold_oracles, oracle_feasibility, conditional_calibration, deployable_eval, figures}.py`;
- `tests/unit/test_phase8t.py` (12 tests).

**Unchanged:** `src/`, the frozen M2, every Phase 8h–8s artifact.

**Compute:** oracle run 44 s; each deployable run about 2 min; peak at most 0.8 GiB.

## Stage results

**Baseline (ORACLE_FEASIBILITY § 1):** the global hold-out thresholds reproduce Phase 8r/8s.
- U 0.374 here vs 0.372; T 0.661 vs 0.656.
- The differences come from the quantile definition.

**Objective (PREREGISTRATION § 1):**
- the window-weighted benign FPR at 1 % and documented-attack recall at the shared budget
  B = ⌊α · N_benign⌋;
- per-host concentration is secondary;
- **the 1 % target was not relaxed.**

**Oracle feasibility (ORACLE_FEASIBILITY):**

| oracle | macro at 1 % FPR | R₂₀ |
|---|---|---|
| O0 global | 0.275 | 16 |
| O2g activity groups | 0.362 | 19.2 |
| O3g service groups | 0.491 | 24 |
| O4 per-host (memorisation) | 0.880 | — |

**G1 PASS, as registered, but fragile:**
- the NF-ToN gain keeps 5 % under the temporal holdout;
- under the "≥ 3 of 4 networks" reading, criterion 3 fails;
- the R₂₀ gain's domain-cluster interval is [0, 21.3].

**Score distributions (ORACLE_FEASIBILITY § 4):**
- benign tails differ strongly by service profile;
- attacks concentrate in low-benign-score profiles on NF-UNSW and NF-BoT;
- on NF-CIC, attacks share the dominant TCP single-port profile.

**Deployable comparison (DETECTION_RESULTS):** at the matched budget, D2 (κ = 500) 0.270 vs D0
0.275.
- **It is informative only on NF-CIC:** 0.481 vs 0.500.
- On the drift networks, more benign windows than the budget exceed every calibration maximum,
  so all CDF methods collapse to global ranking.

**Temporal:**
- H4 NOT SUPPORTED (second half +0.004; NF-ToN FPR 5.2 % vs 3.1 %);
- the older half of the hold-out calibrates worse.

**Stress cases (EXPLORATORY):**
- removing NF-BoT's noisiest benign calibration host raises its FPR from 9 % to 55 % under both D0
  and D2;
- service grouping has no host state, so new hosts need no policy.

## Machine learning

- **Models trained:** none. Saved Phase 8o F0 scores of the frozen M2 construction:
  - 6 fits, seeds 1000 + 10r + m;
  - K = 5;
  - hyperparameters as Phase 8i B-raw.
- **Implemented:**
  - exact multiple-choice-knapsack threshold allocation (oracle);
  - a weighted-CDF calibrator with global, group, pseudo-count hierarchical (κ = 500),
    reliability-gated and per-host variants;
  - a matched-budget comparator that reproduces the global oracle exactly.

## Statistical validity

- **Units:** 4 networks (2 institutions), 9 domains, 48 documented entities, 6 correlated fits.
- **No window-level bootstrap.** Entity- and domain-cluster bootstraps are reported for the oracle
  gain.
- **Every oracle number is retrospective,** chosen with the labels it is scored on.
- **Within-host separation is unmeasurable here,** by construction of the benchmark.

**Amendments:**
- A-1: candidates registered after the oracle results, before deployable outcomes.
- A-2: a matched-budget saturation defect.
- A-3: inexact CDF saturation, found by the review.

All three are recorded, and the earlier outputs are kept.

**The calibration/evaluation boundary shares one slot** (inherited; negligible).

## Validation

**Full suite on `0aaa806`** (the final code): 449 passed, 0 failed, 0 errors, 0 skipped,
2 deselected, in 1,035 s.
- JUnit file: `reports/phase8t/junit_phase8t_final.xml`.

**Other checks:**
- `ruff check` and `ruff format --check`: clean (496 files);
- dependency gate: OK;
- dependencies added: none.

## Recommendation: target the scoring model

The evidence points at the score representation:
- documented attacks on NF-UNSW and NF-ToN score below benign medians;
- the normalised partial AUC at FPR ≤ 1 % is 0.003–0.012 there;
- a clean destination memory raises NF-CIC to 0.80, but NF-UNSW (0.17) and NF-ToN (0.09) stay low;
- the oracle's only stable gain (NF-UNSW multi-port TCP) shows that service-profile context
  matters for separating benign from attack traffic.

**Proposed next phase (not started):** a registered **low-FPR training-objective study** on the
same frozen data and features.
- **Arms:**
  - a partial-AUC or top-of-ranking objective;
  - hard-negative mining from the benign tail hosts;
  - service-profile-conditioned training, with the profile as a feature or an interaction.
- **Evaluation:** at the shared 1 % budget, with the matched-budget comparator and these
  baselines.
- It needs authorization for refits. About 15–20 min per arm set, from Phase 8o timings.

## Three highest-priority gaps

1. **Low-FPR separation in the scorer** on NF-UNSW and NF-ToN (partial AUC ≈ 0.01).
2. **Drift:** in the evaluation period the benign tail exceeds anything seen in calibration, on
   three of four networks.
3. **No independent network,** and no verified benign data.

**Phase 8u is not started.**

## Portfolio summaries (verified claims only)

**ML Research Engineer:**
- "Tested whether host-, service- or hierarchically pooled thresholds could rescue a frozen
  intrusion detector at a fixed 1 % false-positive budget.
- I built an exact knapsack oracle for budget allocation, separated memorisation from genuine
  separation, and implemented pseudo-count partial pooling and a matched-budget comparator.
- I showed the oracle's gain comes from knowing where attacks are, and that deployable versions
  recover none of it. The bottleneck is the scorer, not the threshold.
- Pre-registered; two defects found and fixed (one by the independent review); negative results
  reported."

**Do not claim:**
- improved detection;
- FPR control;
- per-host calibration works;
- production readiness;
- independent generalisation.

## Addendum (2026-11-09, Phase 8u)

The normalised partial-AUC values quoted above (model limit: NF-CIC 0.44, NF-UNSW 0.012, NF-ToN
0.003, NF-BoT 0.58) were computed with `threshold_oracles.partial_auc`.
- Phase 8u's independent review found that function slightly optimistic: it places ROC points only
  at benign scores.
- The exact values are a little lower (Phase 8u amendment U-1).
- No Phase 8t gate used partial AUC, so no verdict changes. The recall-at-1 % numbers are
  unaffected.
