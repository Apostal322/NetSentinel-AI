# Phase 8u final report: low-FPR-aware training of the detector

**Question.** Can new training objectives, mined difficult benign examples, or service-relative
features rank attacks above the hardest benign traffic at FPR ≤ 1 %? Without evaluation labels,
privileged identities or dataset shortcuts?

**Answer on development data:**
- **One variant passes the registered rules:** B, the pairwise squared-hinge partial-AUC
  surrogate, in a single model.
  - Macro partial AUC (FPR ≤ 1 %): +0.056 averaged over 3 paired seeds (exact ROC: +0.058).
  - Recall at the retrospective 1 % threshold: +0.053.
- **Its evidence is weak:**
  - It is not separable from seed noise (paired t(2) ≈ 2.4, p ≈ 0.14).
  - Almost all of it comes from NF-BoT, where the 1 % budget is about 6 benign windows and the
    baseline's own seed SD is 0.12, plus NF-CIC.
  - **NF-UNSW and NF-ToN show no low-FPR signal under any variant** (pAUC ≈ 0.001–0.01, the random
    level is ≈ 0.005). The one exception is a single-seed hard-negative run on NF-ToN (0.058).
  - **As calibrated on the benign hold-out, B detects less** (macro recall 0.47–0.60 vs 0.61–0.65)
    while raising fewer false alerts.

## Decisions

| gate | verdict |
|---|---|
| R0 baseline reproduction | **PASS**: the refitted M2 member equals the saved frozen member exactly (max \|Δp\| = 0.0) |
| H1 hard-negative mining (A2) | **NOT EVALUABLE**: passed screening (macro pAUC +0.080; the only NF-ToN gain); the registered rule spent the replication budget on B |
| H2 low-FPR objective (B) | **SUPPORTED by the registered rule**: replicated over 3 seeds and beats the class-weighting control. Qualified: not separable from seed noise, concentrated in NF-BoT and NF-CIC, lower as-calibrated recall |
| H3 service-relative features (C1) | **NOT EVALUABLE**: passed screening; not replicated; its negative control was not run; it hurt NF-ToN (ROC 0.82 → 0.74) |
| H4 combined candidate | **NOT ATTEMPTED** (budget; only one hypothesis evaluable) |
| Gate M model development | **DEVELOPMENT GO, single member only, by the registered rule**, with the qualifications above. The five-member ensemble was **not** evaluated |
| Gate I independent confirmation | **NOT READY** (no unused eligible network) |
| Gate D deployment | **NO-GO** |

**Where the bottleneck lies.**
- **NF-UNSW and NF-ToN:** none of three training interventions (hard-negative weighting, a
  partial-AUC surrogate, service-relative features) lifts the documented attacks above the benign
  tail. Together with Phase 8t's finding that these attacks score below the benign median in most
  service profiles, the evidence points to **representation or observability** with the 12
  window features, **not the training objective.** Learnability under these features is not
  established; impossibility is not claimed.
- **NF-CIC and NF-BoT:** rankings can move, but seed noise is as large as the effects.

## Repository

**Commits:**
- **Start:** `ceb6c8e` (= `origin/main`; CI run 42538532401 success), with a clean tree.
- **Commits:**
  - `a8ad978`: registration, before any fit;
  - `bac19ad`: mining and screening;
  - `98b8cc8`: replication and evaluation;
  - review, amendment U-1 and docs follow.

**Push:** not pushed (needs authorization). Branch `main`.

**New code:**
- `scripts/phase8u/{lowfpr, experiment, pauc_exact, posthoc, figures}.py`;
- `tests/unit/test_phase8u.py` (8 tests).

**Artifacts:**
- `data/derived/phase8u/` (33 MB; git-ignored): 30 boosters as `.txt`, scores, mined indices,
  manifests with model and score SHA-256;
- the ledger and evaluations in `reports/phase8u/`.

**Unchanged:** the frozen M2, every Phase 8h–8t artifact, `src/`, the deployed defaults.

**Tests (full suite on `5fb9775`):** 456 passed, **1 failed**, 0 errors, 0 skipped, 2 deselected,
in 2,993 s. JUnit file: `reports/phase8u/junit_phase8u_final.xml`.
- **The failure:** `tests/integration/test_dashboard.py::test_all_pages_render`, a Streamlit
  AppTest timeout (60 s) after 194 s.
- **Cause:** machine load. The suite ran about 3× slower than the Phase 8t run.
- **Evidence:**
  - the test **passes when re-run alone** on the same commit;
  - `src/` and `tests/integration/` are unchanged since `ceb6c8e`, whose full suite passed
    (449 / 449).
- **Not fixed.** The test's 60 s timeout is a load sensitivity, recorded here rather than weakened.

**Other checks:** `ruff check` and `ruff format --check` clean (506 files); no dependencies added.

## Methods

**Recipe:** the frozen M2 member.
- LightGBM 4.7, 200 trees, 15 leaves, learning rate 0.05, subsample and colsample 0.8.
- Network- and class-balanced weights; 50k cap per source domain.
- Leave-one-network-out: one fit per target network.

**Seeds:** 1060–1062 (= Phase 8o member seeds), base regime.

**Hard negatives (A2):**
- **Cross-fitted:** a source window of network S, in target T's training set, is scored by a model
  trained on neither S nor T. The mining models are three single-network models plus the A0 refits.
- **Selection:**
  - only eligible negatives: label 0, and the host never attacks in that domain;
  - the top 5 % per source domain;
  - at most 50 per host;
  - weight × 5.
- **Mined:** about 11.7k per NF-CIC day (2.5–4.3k hosts), 1,300 for NF-UNSW (35–36 hosts; top
  host 4 %), 2,835 for NF-ToN (509–758 hosts).

**Class-weighting control (A1):** each domain's negatives get the same total extra weight as A2's,
spread uniformly.

**Low-FPR objective (B):**
- weighted log-loss + λ · Σ_d w_d · (1 / (P_d N_d)) · Σ max(0, 1 − (f_i − f_j))² over attack ×
  top-5 % eligible negatives **within each source domain**;
- the negatives are re-selected every iteration;
- λ = Σ sample weights;
- exact gradients (tested against brute force and finite differences); diagonal Hessian.

**Service-relative features (C1):** 4 features: log_flows, log_up_bytes, log_pkts, med_log_dur
minus the median of the same domain's unlabelled calibration windows with the same service profile.

## Model performance (single member; frozen-member baseline; S_U deployable memory)

**Screening, seed 1060 (registered pAUC):**

| variant | macro pAUC | macro recall @ 1 % | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|---|---|
| frozen member | 0.264 | 0.266 | 0.331 | 0.006 | 0.008 | 0.710 |
| A1 control | 0.233 | 0.258 | 0.417 | 0.009 | 0.007 | 0.500 |
| A2 | 0.344 | 0.401 | 0.377 | 0.017 | **0.058** | 0.924 |
| **B** | **0.362** | 0.365 | 0.501 | 0.008 | 0.001 | 0.939 |
| C1 | 0.329 | 0.370 | 0.342 | 0.033 | 0.000 | 0.940 |

**Replication of B (Δ vs the matched frozen member):**
- macro pAUC +0.098 / +0.018 / +0.051;
- per network (mean): NF-CIC +0.064, NF-UNSW −0.000, NF-ToN −0.002, NF-BoT +0.160;
- baseline seed SD: NF-CIC 0.079, NF-BoT 0.123.

**ROC-AUC:** B 0.859–0.869 vs 0.847–0.853.

**As calibrated (CAL_T, mean of 3 seeds):** B lowers FPR on NF-ToN (13.4 % → 5.5 %) and NF-BoT
(14.8 % → 3.7 %), at a recall cost of 0.13–0.17.
- Entities missed entirely: 4–7 vs 8.
- At the retrospective 1 % threshold B misses 1–2 more entities.
- **No threshold calibrated on the hold-out reaches 1 % FPR on NF-UNSW, NF-ToN or NF-BoT** for
  either model.

**False alerts per hour:** NF-CIC about 290–330 for every model.

**Detection delay** (median over domains, retrospective 1 %): B 0 min; baseline 0.25–4.25 min.

## Resource use

| item | value |
|---|---|
| fits | 30 / 30 authorised |
| cumulative fit time | 591 s of 7,200 s |
| peak process memory | 1.93 GiB of 3.4 GiB |
| model artifacts and scores | 33 MB |
| evaluation runs | about 1 min each, ≤ 1 GiB |

## Scientific validity

- **Units:** 4 networks (2 institutions), 9 domains, 48 documented entities. **3 training seeds are
  the replication unit.** No window-level bootstrap.
- **Every result is development evidence** on networks consumed by earlier phases.
- **Corrections:** amendment U-1 (exact partial AUC; the review found the registered function
  optimistic; verdicts unchanged; Phase 8t addendum).
- **Limits of the registered design** (disclosed after the review):
  - the guardrails do not penalise lower recall from alerting less;
  - A1 is a weak hurdle for B;
  - no tail-specificity control was run;
  - the NF-BoT metric rests on about 6 benign windows.

## Next steps (three)

1. **Representation and observability on NF-UNSW and NF-ToN.** No tested objective or weighting
   moves their attacks above the benign tail.
   - *Evidence needed:* a registered study of additional observable flow evidence (per-flow
     sequences or payload-independent protocol fields not in the 12 window features), with an
     in-network learnability check first.
2. **Confirm or reject B** with enough seeds to beat the seed noise (at least 10 paired seeds), a
   tail-specificity control (β = 1), a recall guardrail and a 5-member ensemble comparison.
   - That is about 60–80 fits: **authorization needed.**
3. **Independent data.** Any surviving candidate needs an unused network with host-level ground
   truth before any generalisation claim.

**Phase 8v is not started.**

## Portfolio summary (verified claims only)

**ML Research Engineer:**
- "Implemented and pre-registered low-FPR training interventions for a LightGBM intrusion
  detector:
  - cross-fitted hard-negative mining with leakage-safe leave-one-network-out scoring;
  - a custom pairwise partial-AUC surrogate objective (gradients verified against brute force);
  - service-relative features.
- Reproduced the frozen baseline bit-exactly, worked within a 30-fit budget, and had an
  independent review correct the partial-AUC metric.
- Result: a registered single-model gain that does not separate from seed noise, and no low-FPR
  signal on two of four networks, pointing at representation rather than objective."

**Do not claim:**
- improved detection;
- a validated new model;
- FPR control;
- generalisation;
- production readiness.
