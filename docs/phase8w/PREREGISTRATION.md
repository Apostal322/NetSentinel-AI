# Phase 8w pre-registration: network-relative representations

**Registered:** 2026-11-10, before any registered model was fitted.

**Already seen (disclosed):**
- every earlier phase's results on these four networks, including their evaluation labels;
- the Phase 8h audit (HISTORICAL_NORMALIZATION_AUDIT);
- the reference tables and the **no-fit direction diagnostic, which uses evaluation labels**
  (IDENTIFIABILITY §§ 3–5). It shaped the choice of the unsigned arm and the decision not to fit
  a context arm;
- the dry run (no real fit) and the frozen reference numbers.

Everything below is therefore **development confirmation on consumed networks, not independent
evidence.**

**Code:** `scripts/phase8w/{relative, references, gates, experiment}.py`;
`tests/unit/test_phase8w.py` (19 tests).

## 1. Hypotheses and gates

| gate | hypothesis | evidence in this phase |
|---|---|---|
| G0 research and baseline correctness | the driver reproduces the frozen member; references are causal | `R0` vs the saved member; unit tests; dry run |
| G1 signed relative representation (H1) | a network-relative deviation, signed or unsigned, improves low-FPR ranking | arms `S` and `A` vs `R0` |
| G2 context-conditioned (H2) | conditional references add value | **NOT EVALUABLE (registered now):** no context arm is fitted |
| G3 contamination robustness (H3) | the gain survives an unlabelled, contaminated target history | the selected arm under `Z1` vs `Z3`; stress re-scoring |
| G4 cross-network low-FPR improvement (H4) | improvement under the deployable reference without unacceptable regressions | the selected arm under `Z1`, five seeds, guardrails |

## 2. Recipe, data, arms

**Model:** the frozen M2 member recipe, unchanged.
- LightGBM with Phase 8i `LGB` parameters (200 trees, 15 leaves, learning rate 0.05, subsample
  and colsample 0.8);
- network- and class-balanced weights; 50k cap per source domain;
- leave-one-network-out, one fit per target network (NF-CIC's six days share a fit; NF-BoT is a
  target only);
- training rows checked row for row against `fragility.train_rows`.

**Arms** (REFERENCE_ESTIMATION § 3): `R0` raw (null control), `S` signed z, `A` unsigned |z|.
Twelve columns each, same order.

**References:** source domains use their label-benign calibration windows. The target reference
is chosen at scoring time, with no refit:

| scenario | kind | status of results |
|---|---|---|
| `Z1` unlabelled history | unsupervised target-adaptive | **primary, deployable** |
| `Z3` oracle-clean | oracle-assisted | diagnostic upper reference |
| `Z2` simulated review (800 windows, perfect reviewer) | weakly supervised, simulated | diagnostic |
| `T` label-benign calibration (Phase 8h) | oracle-assisted | diagnostic; train-consistent |
| `Z0` median of source references | zero-shot | diagnostic |

`R0` uses no reference and is the same in every scenario. Scenarios are reported in separate
tables.

**Evaluation population:** unchanged. Every Phase 8q audited evaluation window of the nine
evaluated domains (V2 documented attackers vs historical benign), deployable-memory features.

## 3. Seeds and stages

| stage | seeds | arms | fits |
|---|---|---|---|
| screening | 1060, 1061 | `R0`, `S`, `A` | 24 |
| replication (only if § 6 selects an arm) | 1062, 1063, 1064 | `R0` and the selected arm | 24 |

Seeds are the frozen M2 member seeds, so each `R0` fit has a saved counterpart.

## 4. Budget (needs the user's approval before the first fit)

| item | value |
|---|---|
| registered LightGBM fits | **≤ 48** (the driver refuses a 49th) |
| small diagnostic fits | ≤ 4 (benign-only network classifier per representation, § 7) |
| neural runs | 0 |
| cumulative fit time | estimated 30–40 min (Phase 8v: 637 s for 16 fits); limit 120 min |
| wall time | about 10–15 min per seed, five seed processes at most |
| peak memory | estimated 1.8–2.2 GiB; cap 3.4 GiB |
| processes | one at a time |
| ledger | `reports/phase8w/fit_ledger.json`; the driver refuses a dirty tree before every fit |

## 5. Metrics

**Primary:** exact normalised partial ROC-AUC over FPR ∈ [0, 0.01]
(`lowfpr.partial_auc_exact`; regression case benign [1, 0], attack [0.5] → 0).
- Per domain; mean over a network's domains; macro = equal weight per network.
- "Hard networks" = mean of NF-UNSW and NF-ToN.

**Secondary (oracle diagnostic):** recall at the retrospective threshold with benign false alerts
≤ ⌊0.01 · N_benign⌋; ROC-AUC, PR-AUC, entity R₂₀, entities missed, detection delay.

**Operational (as calibrated, CAL_T):** the conformal rank of the benign hold-out scores
(calibration labels: the best case of trusted review). Realised FPR, recall, false alerts per
hour, entities missed.

**Units:** 4 networks (2 institutions), 9 domains, 48 documented entities. Seeds are the
replication unit; no window-level interval is reported. Five seeds measure training noise, not
network-to-network variation.

## 6. Decision rules (`gates.py`; unit-tested)

Every difference is the candidate member minus `R0` with the same seed.

**Ranking criteria** over a set of seeds, all required:
1. mean Δ hard-network partial AUC ≥ **+0.02**, and > 0 in every seed;
2. mean Δ macro partial AUC ≥ **+0.02**, and > 0 in every seed.

Reference for scale: baseline seed SD is about 0.0025 on the hard networks and about 0.009 on
the macro mean; the frozen member's macro partial AUC is 0.254.

**Guardrails** on seed means, all required:

| guardrail | limit |
|---|---|
| recall at the retrospective 1 % FPR, each network | ≥ `R0` − 0.10 |
| as-calibrated macro recall | ≥ `R0` − 0.03 |
| as-calibrated FPR | ≤ `R0` + 0.01 on NF-CIC, NF-UNSW, NF-ToN; ≤ `R0` + 0.06 on NF-BoT |
| entities missed as calibrated | ≤ `R0` + 2 |
| NF-UNSW and NF-ToN partial AUC, each | not below `R0` |

NF-BoT's FPR tolerance is wider because its benign tail is one host and its baseline seeds span
7–19 % (Phase 8v review, finding D3).

**Screening (seeds 1060–1061), per arm and per scenario:** PASS = ranking criteria and guardrails.

**Selection: at most one arm is replicated.**
1. an arm that passes screening under `Z1` (scope: G1, G3, G4);
2. otherwise an arm that meets the ranking criteria under `Z3` (scope: **G1 only**);
3. otherwise stop after 24 fits.
Ties go to the larger hard-network gain.

**Verdicts (five seeds, 1060–1064):**

| gate | SUPPORTED | NOT SUPPORTED | NOT EVALUABLE |
|---|---|---|---|
| G0 | every `R0` refit matches its saved member (score difference ≤ 1e-9), tests pass | otherwise FAIL, and the difference is explained | — |
| G1 | the replicated arm meets the ranking criteria under `Z3` or `Z1` | it does not, or nothing was selected | replication incomplete |
| G3 | ranking criteria under `Z1` **and** the `Z1` macro gain is ≥ 50 % of the `Z3` macro gain (when that is positive) | otherwise | replication incomplete |
| G4 | ranking criteria **and** guardrails under `Z1` | otherwise | replication incomplete |
| model development | **DEVELOPMENT GO (single member)** needs G3 and G4 | NO-GO otherwise | replication incomplete |

- A screening pass alone supports nothing.
- An oracle-only gain (`Z3` without `Z1`) is never a development GO.
- A development GO would still be a single-member result pending a five-member ensemble
  confirmation and an independent network.

**Independent confirmation:** NOT READY (no unused network). **Deployment:** NO-GO.

## 7. Registered analyses without new registered fits

| analysis | definition |
|---|---|
| signed vs unsigned | `A` − `S` at matched seeds, per scenario and network |
| pipeline decomposition | saved member → `R0` refit (pipeline effect) → candidate (representation effect) → scenario change (reference effect) |
| contamination stress | re-score the saved boosters with the `Z3` reference rows plus injected attack windows at 0, 5, 10, 20, 30, 45 and 60 % of the reference; contaminants are the domain's evaluation attack windows (worst case: the evaluated attack was already running). Diagnostic only |
| simulated review sensitivity | `Z2` with five draws, and with a reviewer that passes 10 % of attack windows as benign |
| entity analysis | entities detected, missed and newly lost or gained per arm, as calibrated and at the retrospective 1 % FPR |
| domain shortcut | benign-only network classifier accuracy on `R0`, `S`, `A` representations (≤ 4 small fits). Lower accuracy is not counted as an improvement by itself |
| exploratory ensemble | mean of the five members' probabilities vs the frozen M2 ensemble, if five seeds exist. Not a validated ensemble |

## 8. Amendments

None at registration. Each amendment records the time, the original and new rule, the reason,
whether outcomes were visible, and the effect.

### Corrections after the independent review (2026-11-10; outcomes visible; no rule changed)

| id | original text | correction | effect on verdicts |
|---|---|---|---|
| W-1 | § 6: baseline seed SD "about 0.009 on the macro mean" | 0.009 is the SD of the first three saved members. The five members give **0.0145**. Two seeds cannot resolve a ±0.02 macro effect; screening fixes the sign per network only | none: no arm met the macro criterion in either direction of that noise (`A`: −0.047 and +0.000) |
| W-2 | § 2: `T` "label-benign calibration (Phase 8h); train-consistent" | `T` covers the whole calibration period including the hold-out, and its host cleaning uses evaluation labels (IDENTIFIABILITY § 1). It is not a causal reference | none: `T` is diagnostic only |
| W-3 | § 5: "Operational (as calibrated, CAL_T)" under the deployable scenario | the `Z1` reference is label-free, but the CAL_T threshold is label-assisted. A label-free threshold (`cal_U`) was added to the review checks | none |
| W-4 | § 7 lists the registered no-refit analyses | two further stages were added with outcomes visible and are exploratory: `scale` (mechanism view) and `review` (checks requested by the reviewer). `posthoc.py` was written while the fits ran and committed after them; it is not part of the registration commit | none |
| W-5 | — | code changes after the registered evaluation: `stage_eval` now checks key and window alignment of audited and scored rows (the reviewer verified it for all nine domains); post-hoc outputs are write-once. No saved output was regenerated | none |
