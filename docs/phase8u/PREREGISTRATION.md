# Phase 8u pre-registration: low-FPR-aware training of the M2 member recipe

**Registered:** 2026-11-09, before any Phase 8u model was fitted.

**Seen before registration:**
- the Phase 8t results;
- a pre-check (no fits) showing that `full_rows` + `subsample_idx` reproduce Phase 8n
  `train_rows` exactly;
- the synthetic tests in `tests/unit/test_phase8u.py`.

**Code:**
- `scripts/phase8u/lowfpr.py` (components);
- `scripts/phase8u/experiment.py` (driver, ledger, metrics, gates).

**Authorisation (Phase 8u brief, Part 12):**
- ≤ 30 LightGBM fits;
- ≤ 120 min cumulative fit time;
- < 3.4 GiB per process;
- one process at a time.

The ledger `reports/phase8u/fit_ledger.json` counts every booster, and the driver refuses to
exceed the budget.

## 1. Recipe, partitions, information roles

**Model:** the frozen M2 *member* recipe (Phase 8n/8o F0), unchanged except for the registered
intervention:
- LightGBM with Phase 8i `LGB` parameters (200 trees, 15 leaves, learning rate 0.05, subsample and
  colsample 0.8, `n_jobs` 2);
- network- and class-balanced weights;
- a 50k cap per source domain.

**Leave-one-network-out training:** one fit per target network.

| target | source networks |
|---|---|
| NF-CIC (6 days share the fit) | UNSW, ToN |
| NF-UNSW | CIC, ToN |
| NF-ToN | CIC, UNSW |
| NF-BoT (target only) | CIC, UNSW, ToN |

**Information roles:**

| role | data |
|---|---|
| training | the source domains' Phase 8h train rows (clean calibration + non-noisy evaluation windows), **unchanged training labels** (the historical policy). The Phase 8q audit is not used to relabel training rows |
| training-internal mining | the same source rows, scored **cross-fitted**: a source window of network S, in target T's training set, is scored by a model trained on neither S nor T (for T = NF-BoT: the A0 model of target S, trained on the other two networks). No target-network data, no evaluation labels |
| calibration | the target's hold-out (last 30 % of calibration slots): **CAL_T** = benign hold-out windows (calibration labels; best-case trusted review), **CAL_U** = the unlabelled hold-out |
| analysis | the target's evaluation windows: Phase 8q audited view (V2 documented attackers vs historical benign), deployable memory (S_U = `s_ev_u`) |

**These four networks are consumed development data.** Nothing here is independent confirmation.

**Model selection:** there is no separate selection partition. Candidates are fixed here, and
only the registered gates decide.

## 2. Baselines

- **Frozen M2 reference:** the saved Phase 8o F0 base r6 member scores (seeds 1060 + m).
- **Contemporary retrained baseline A0:** the same recipe at seed 1060, refitted for targets
  NF-CIC, NF-UNSW and NF-ToN.
  - **Gate R0:** A0 must reproduce the saved member-0 scores, max |Δ probability| ≤ 1e-9. If it
    passes, the saved members serve as the matched baselines for seeds 1060–1062 (NF-BoT's A0 is
    the saved member, with R0 shown on the other three targets).
  - If R0 fails, every comparison uses only refitted models, and the budget is re-planned by
    amendment.
- **Ensemble comparison:** **not attempted.** A 5-member candidate ensemble needs 20 fits beyond
  the budget.

## 3. Variants (single member, seed 1060 for screening)

| id | hypothesis | change from A0 (only) |
|---|---|---|
| A1 | control | uniform negative upweighting: each source domain's negatives multiplied by the factor that gives the **same total negative weight as A2** (generic class weighting) |
| A2 | H1 hard negatives | mined hard negatives weighted × 5 |
| B | H2 low-FPR objective | log-loss + λ · pairwise squared-hinge one-way pAUC surrogate (§ 5) |
| C1 | H3 service-relative representation | 4 extra features: log_flows, log_up_bytes, log_pkts, med_log_dur minus the median of the same domain's unlabelled calibration windows **of the same service profile** |
| C1ns | H3 negative control | the same 4 deviations from the **all-profile** domain median (service identity withheld). Run only if C1 is replicated (§ 7) |

## 4. Hard-negative mining (H1)

**Eligible negatives:**
- label 0;
- the host has **no** attack window in that source domain;
- ambiguous windows of attacking hosts are never mined.

**Selection:**
- the top 5 % of eligible negatives by cross-fitted mining score, per source domain;
- at most 50 per host (the highest-scoring first);
- weight × 5.

**Frozen before candidate training:** mined row indices go to
`data/derived/phase8u/mining/mined__<target>.npz`. Composition is reported (network, hosts,
top-host share, service profile, score quantiles).

**Mining fits (counted):**
- three single-network models (CIC only, UNSW only, ToN only; seed 1060);
- the three A0 models.

## 5. Low-FPR objective (H2)

**Objective:** log-loss (sample-weighted) + λ · Σ_d w_d · L_d, where L_d is the squared-hinge
surrogate over all pairs (attack, top-5 % eligible negatives by current margin) **within source
domain d**.

**Parameters:**
- λ = the sum of sample weights (so the pairwise term carries weight comparable to the data);
- w_d = the network weight of domain d.

**Implementation:**
- exact gradients (tested against brute force and finite differences);
- a diagonal Hessian, floored at 1e-6;
- a non-finite check.

**This is a surrogate of the one-way partial AUC, not direct pAUC optimisation.**

## 6. Metrics (per target domain; mean over domains within a network; macro = equal weight per network)

**Primary: `pauc_1pct`.**
- The normalised partial ROC-AUC over FPR ∈ [0, 0.01]: the mean TPR over that FPR range.
- Step ROC, with ties handled by a trapezoid across the jump (`threshold_oracles.partial_auc`).
- A random scorer gets ≈ 0.005, a perfect one 1.

**Secondary (oracle diagnostic): `recall_1pct`.** Recall at the retrospective global threshold
with benign false alerts ≤ ⌊0.01 · N_benign⌋. It is not a deployable result.

**Also:**
- ROC-AUC and PR-AUC (V2 vs benign);
- entity R₂₀ and entities missed entirely;
- detection delay.

**Operational:** CAL_T (conformal rank of benign hold-out scores) and CAL_U. We report:
- realised FPR;
- recall;
- false alerts per hour;
- top host's share of false alerts;
- missed entities.

**Statistical units:**
- 4 networks (2 institutions), 9 domains, 48 entities;
- seeds are the replication unit;
- no window-level bootstrap.

## 7. Gates

**Screening** (seed 1060, candidate vs the saved member 0). **PASS** if all:
1. Δ macro `pauc_1pct` ≥ +0.02;
2. Δ macro `recall_1pct` ≥ +0.02;
3. no network with Δ `pauc_1pct` < −0.02;
4. no network with Δ `recall_1pct` < −0.05.

**Progression** (fits 23–30):
- **One candidate is replicated:** the screening-passing candidate with the largest Δ macro
  `pauc_1pct`.
- **If it is A2 or B:** seeds 1061 and 1062 (8 fits), against saved members 1 and 2.
- **If it is C1:** seed 1061 (4 fits) plus the C1ns control at seed 1060 (4 fits).
- **If none passes:** no further fits.

**Replicated** (over the replicated seeds and 1060): all of
- mean Δ macro pAUC ≥ +0.02;
- mean Δ macro recall@1 % ≥ +0.02;
- Δ macro pAUC > 0 for every seed;
- no network Δ recall@1 % < −0.05 in any seed;
- the operational guardrails hold in every seed.

**Operational guardrails** (CAL_T, per network, vs the matched baseline):
- FPR ≤ baseline + 0.01;
- false alerts per hour ≤ 1.2 × baseline + 1;
- total entities missed ≤ baseline + 2.

**Hypothesis verdicts:**

| hypothesis | rule |
|---|---|
| **H1 (A2)** | SUPPORTED if A2 is replicated **and** beats A1 at screening by ≥ 0.01 macro pAUC. NOT SUPPORTED if A2 fails screening or replication. NOT EVALUABLE if it passed screening but the budget went to another candidate |
| **H2 (B)** | same rule (B must also beat A1 by ≥ 0.01, the ordinary-class-weighting control) |
| **H3 (C1)** | SUPPORTED if C1 is replicated **and** C1ns keeps < 50 % of C1's screening pAUC gain |
| **H4** | NOT ATTEMPTED unless two hypotheses are SUPPORTED with budget left (none can be: the budget is exhausted by one replication) |
| **Gate M** | DEVELOPMENT GO if any of H1–H3 is SUPPORTED; otherwise NO-GO |

**Ensemble evaluation:** not attempted (budget). A GO would therefore be a single-member result.

**Gates I and D:** independent confirmation NOT READY (no unused network); deployment NO-GO.

## 8. Amendments

| id | when | original | new | reason | outcomes visible? | effect |
|---|---|---|---|---|---|---|
| U-1 | 2026-11-09, after `evaluation_final.json` | `pauc_1pct` = `threshold_oracles.partial_auc`: ROC points only at benign scores, with a trapezoid across each jump | `lowfpr.partial_auc_exact`: the exact empirical ROC at every distinct score, interpolated at FPR = 1 % (tested against sklearn) | the independent review showed the registered version credits positives lying strictly between benign scores (optimistic; toy case 0.5 instead of 0) | yes | every gate recomputed (`evaluation_pauc_exact.json`); **all verdicts unchanged** (B screening +0.108, replication mean +0.058; A2/C1 pass, A1 fails). The registered file is kept |
