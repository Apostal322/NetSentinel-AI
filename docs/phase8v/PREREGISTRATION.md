# Phase 8v pre-registration: enriched flow-window representations

**Registered:** 2026-11-09, before any registered model was fitted.

**Already seen (disclosed):**
- the telemetry audit (label-free);
- the exploratory learnability analysis on the four development networks, **with their
  evaluation labels** (OBSERVABILITY_ANALYSIS). It shaped the candidates below;
- the frozen baseline reference;
- a no-fit pre-check of the training pipeline, including which columns `INV` drops per fit
  (computed from training rows only).

Everything below is therefore **development confirmation on consumed networks, not independent
evidence.**

**Code:**
- `scripts/phase8v/flow_features.py`, `selection.py`, `experiment.py`;
- `tests/unit/test_phase8v.py` (13 tests).

## 1. Hypotheses and gates

| gate | hypothesis | candidate |
|---|---|---|
| G1 representation information | flow-statistical features add transferable attack evidence | `FLOW` |
| G2 temporal features (H1, H3) | within-window timing and 4-window causal context improve low-FPR ranking | `TIME` |
| G3 bidirectional features (H2) | per-direction TCP and byte statistics add information | `BIDIR` |
| G5 cross-network (H5) | a representation restricted to source-invariant directions transfers better | `INV` |
| G4 sequence learning (H4) | — | **NOT ATTEMPTED:** the exploratory analysis found no in-network gain from ordering features, and nothing new justifies revisiting GRU/TCN |

## 2. Recipe, data, baseline

**Model:** the frozen M2 member recipe, unchanged except for the added columns.
- LightGBM 4.7 with Phase 8i `LGB` parameters;
- network- and class-balanced weights;
- 50k cap per source domain;
- the same CAP subsample, checked row for row against `fragility.train_rows`.

**Training:** leave-one-network-out, one fit per target network (NF-CIC's six days share a fit;
NF-BoT is a target only). Historical training labels.

**Features:** the 12 original features plus the registered columns of `flowwin-1.0.0`
(FEATURE_SCHEMA). Missing values stay NaN.

**Baseline:** the saved Phase 8o F0 base r6 member with the same seed (1060 + m). Phase 8u gate R0
showed the refit reproduces it exactly, so no baseline is refitted.

**Evaluation population:** unchanged. Every Phase 8q audited evaluation window of every domain
(V2 documented attackers vs historical benign), on deployable-memory features. No window is
dropped: the enriched table covers 100 % of the windows, and the driver stops otherwise.

## 3. Candidates

| id | columns added to the 12 | fits |
|---|---|---|
| `FLOW` | 5 flow-statistical features | 4 |
| `TIME` | 7 temporal features | 4 |
| `BIDIR` | 4 bidirectional features | 4 |
| `INV` | all 16, then **every column (original or new) whose univariate direction conflicts between the fit's source networks is dropped** (`selection.invariant_columns`: opposite sides of AUC 0.5 by ≥ 0.1 in two source networks; training rows and labels only) | 4 |

**Not run in this budget** (code present):
- `ALL` (all 16, no selection);
- `PERM:<family>`, the within-domain permutation control. **It is required before any
  promotion** (§ 7).

## 4. Budget (needs the user's approval before the first fit)

| item | value |
|---|---|
| LightGBM fits | **≤ 24:** 16 screening (seed 1060) + 8 replication (seeds 1061–1062) for one candidate |
| neural runs | 0 |
| cumulative fit time | estimated 6–10 min (Phase 8u: 591 s for 30 fits); limit 120 min |
| peak memory | estimated 1.9–2.2 GiB per process; cap 3.4 GiB |
| processes | one at a time |
| ledger | `reports/phase8v/fit_ledger.json`; the driver refuses a 25th fit and refuses a dirty tree |

## 5. Metrics

**Primary:** exact normalised partial ROC-AUC over FPR ∈ [0, 0.01]
(`lowfpr.partial_auc_exact`: empirical step ROC at every distinct score, linear interpolation at
FPR = 1 %, divided by 0.01; regression case benign [1, 0], attack [0.5] → 0).
- Per domain; mean over a network's domains; macro = equal weight per network.

**Secondary (oracle diagnostic):** recall at the retrospective threshold with benign false alerts
≤ ⌊0.01 · N_benign⌋. Also ROC-AUC, PR-AUC, entity R₂₀, entities missed, detection delay.

**Operational (CAL_T):** the conformal rank of the benign hold-out scores (calibration labels:
the best case of trusted review). We report realised FPR, recall, false alerts per hour and
entities missed. **No hold-out threshold reaches 1 % FPR on three networks** (Phases 8s–8u); this
is reported, not hidden.

**Units:** 4 networks (2 institutions), 9 domains, 48 documented entities; seeds are the
replication unit. No window-level interval is reported.

## 6. Decision rules (`selection.decide`)

**Why the gates centre on NF-UNSW and NF-ToN.** They are the phase's target. Their baseline seed
SD of partial AUC is about 0.0025, against 0.08–0.12 on NF-CIC and NF-BoT, where Phase 8u could
not separate effects from seed noise.

**Screening (seed 1060 vs the frozen member with seed 1060). PASS if all:**
1. Δ partial AUC averaged over NF-UNSW and NF-ToN ≥ **+0.02**;
2. Δ macro partial AUC ≥ 0;
3. guardrails:
   - no network loses more than 0.10 recall at 1 % FPR;
   - as-calibrated macro recall ≥ baseline − 0.03 (a model may not pass by alerting less);
   - as-calibrated FPR ≤ baseline + 0.01 on every network;
   - entities missed ≤ baseline + 2.

**Progression.** The passing candidate with the largest hard-network gain is replicated at seeds
1061 and 1062. If none passes, no further fit is run.

**Replicated if all:**
- mean hard-network Δ ≥ +0.02 over the three seeds, and > 0 in every seed;
- mean Δ macro ≥ 0;
- guardrails in every seed.

**Verdicts:**

| gate | SUPPORTED | NOT SUPPORTED | NOT EVALUABLE |
|---|---|---|---|
| G1 / G2 / G3 | its family is replicated | it fails screening or replication | it passes screening but another candidate is replicated |
| G5 | a replicated candidate improves mean partial AUC on ≥ 3 networks, including both hard ones | a candidate is replicated without that, or none passes screening | — |
| model development | **DEVELOPMENT GO** needs a replicated candidate, G5 SUPPORTED **and** a later `PERM` control keeping < 50 % of the hard-network gain | NO-GO if nothing passes screening or replication | **"GO pending the shortcut control"** if replicated with G5, because the control is outside this budget |

**Independent validation:** NOT READY (no unused network). **Deployment:** NO-GO.

## 7. Controls and their limits

- **Run:** `INV` is itself an anti-shortcut design. It removes directions that disagree between
  source networks.
- **Not run (budget):** the within-domain permutation control and a five-member ensemble. A
  replicated result is a single-member development result until both are done.
- **Known limit of `INV`:** it cannot see a conflict between the *target* and the sources
  (NF-UNSW's inverted volume direction is invisible from NF-CIC and NF-ToN).

## 8. Amendments

None yet. Any amendment records the time, the original and new rule, the reason, whether outcomes
were visible, and the effect.

### Amendment V-1 (2026-11-10, after the screening evaluation; outcomes visible)

| item | content |
|---|---|
| defect | the driver wrote each saved booster with a text-mode write, so the 16 model files have CRLF line endings, which LightGBM cannot parse |
| effect on results | **none.** Scores were computed from the in-memory models before saving. Each file, with CRLF normalised to LF, matches the SHA-256 recorded in its manifest (checked for all 16 in `posthoc.py`) |
| fix | the driver now writes bytes; `posthoc.py` loads the saved files through the normalised text. The saved files are kept as written |
| registered verdicts | unchanged |
