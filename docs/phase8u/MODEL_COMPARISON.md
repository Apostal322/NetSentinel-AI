# Phase 8u: registered model comparison

**Status:** REGISTERED (PREREGISTRATION, `a8ad978`, before any fit).

**Commits:**
- mining and screening `bac19ad`;
- replication and final evaluation `98b8cc8`.

**Sources:** `reports/phase8u/evaluation_screening.json`, `evaluation_final.json` (+ `.sha256`),
`fit_ledger.json`, `mining.json`; EXPLORATORY `posthoc.json`.

**Budget used:** 30 / 30 fits; 591 s of cumulative fit time; peak 1.9 GiB.

**Data:** development data only (four consumed networks). Deployable memory scores (S_U).

**pAUC values below are the registered `partial_auc`.**
- That function is slightly optimistic (amendment U-1, found by the independent review).
- With the exact empirical ROC (`evaluation_pauc_exact.json`), every gate gives the same verdict:
  - B screening: +0.108;
  - B replication mean: +0.058;
  - baseline member 0 macro: 0.254 instead of 0.264;
  - NF-BoT member 0: 0.671 instead of 0.710.

## 1. Reproduction (gate R0): PASS

**A0 (the frozen M2 member recipe, seed 1060), refitted for targets NF-CIC, NF-UNSW and NF-ToN,
reproduces the saved Phase 8o F0 base r6 member-0 scores exactly** (max |Δ probability| = 0.0).
- The saved members 0–2 (seeds 1060–1062) therefore serve as the matched baselines.

## 2. Screening (seed 1060; single member vs the matched frozen member)

| variant | macro pAUC (FPR ≤ 1 %) | macro recall @ 1 % | ROC-AUC | PR-AUC | NF-CIC pAUC | NF-UNSW | NF-ToN | NF-BoT | screening |
|---|---|---|---|---|---|---|---|---|---|
| frozen member (= A0) | 0.264 | 0.266 | 0.847 | 0.675 | 0.331 | 0.0063 | 0.0081 | 0.710 | — |
| A1 uniform negative weight (control) | 0.233 | 0.258 | 0.850 | 0.683 | 0.417 | 0.0087 | 0.0065 | **0.500** | fail |
| A2 hard negatives × 5 | 0.344 | 0.401 | 0.851 | 0.699 | 0.377 | 0.0167 | **0.0577** | 0.924 | pass |
| **B pairwise tail objective** | **0.362** | 0.365 | 0.869 | 0.728 | 0.501 | 0.0081 | 0.0009 | 0.939 | pass (largest) |
| C1 service-relative features | 0.329 | 0.370 | 0.813 | 0.592 | 0.342 | 0.0334 | 0.0001 | 0.940 | pass |

The registered progression rule sends the largest screening gain, **B**, to replication.
- A2 and C1 also passed screening but were not replicated (budget).
- **A2 is the only variant that moved NF-ToN** (pAUC 0.008 → 0.058; recall @ 1 % 0.013 → 0.154)
  and doubled NF-UNSW. That is single-seed evidence, and A2 fails the NF-UNSW FPR guardrail as
  calibrated.

## 3. Replication of B (seeds 1060–1062, paired with frozen members 0–2)

| seed | Δ macro pAUC | Δ macro recall @ 1 % | Δ NF-CIC pAUC | Δ NF-UNSW | Δ NF-ToN | Δ NF-BoT |
|---|---|---|---|---|---|---|
| 1060 | +0.098 | +0.099 | +0.171 | +0.002 | −0.007 | +0.229 |
| 1061 | +0.018 | +0.005 | +0.041 | −0.002 | −0.001 | +0.032 |
| 1062 | +0.051 | +0.055 | −0.019 | −0.000 | +0.003 | +0.219 |
| **mean** | **+0.056** | **+0.053** | +0.064 | −0.000 | −0.002 | +0.160 |

**Registered rule:** **replicated.**
- **However, a paired t-test over the three seeds gives t(2) ≈ 2.4, p ≈ 0.14** (independent
  review). The gain is not separable from seed noise.
- The mean gains clear the +0.02 thresholds.
- Every seed is positive.
- No network loses > 0.05 recall @ 1 %.
- The operational guardrails hold in every seed.

**What the rule does not show (EXPLORATORY, `posthoc.json`):**
- **The gain is NF-BoT (+0.160) and NF-CIC (+0.064).** NF-UNSW and NF-ToN, the networks that
  motivated this phase, do not move (|Δ| ≤ 0.002).
- **The baseline's own seed-to-seed SD of pAUC is 0.123 on NF-BoT and 0.079 on NF-CIC.**
  B's per-network gains are about one baseline SD (figure 07).
- **NF-BoT's 1 %-FPR budget is about 6 benign windows** (620 benign windows, 4 entities).
- **Without NF-BoT the macro gain is +0.021,** and seed 1062 is negative (−0.005).

## 4. Operational behaviour (as calibrated on the benign hold-out, CAL_T; mean over 3 seeds)

| network | baseline recall / FPR / FA per h | B recall / FPR / FA per h |
|---|---|---|
| NF-CIC | 0.46 / 1.3 % / 328 | 0.51 / 1.1 % / 294 |
| NF-UNSW | 0.58 / 3.6 % / 49 | 0.46 / 3.8 % / 51 |
| NF-ToN | 0.51 / 13.4 % / 13.8 | 0.38 / **5.5 %** / 5.7 |
| NF-BoT | 0.94 / 14.8 % / 0.2 | **0.77** / 3.7 % / 0.1 |

- **As calibrated, B trades recall for fewer false alerts** on NF-ToN and NF-BoT (FPR down 3–4×,
  recall down 0.13–0.17).
- **Entities missed entirely:**
  - as calibrated: 4–7 vs 8 for the baseline;
  - at the retrospective 1 % threshold: B misses 1–2 more entities in every seed.
- **Median detection delay** at the retrospective 1 % threshold: 0 min for B vs 0.25–4.25 min for
  the baseline (domain medians).
- **No hold-out-calibrated threshold reaches 1 % FPR on NF-UNSW, NF-ToN or NF-BoT,** for either
  model.

## 5. Verdicts (registered rules)

| gate | verdict |
|---|---|
| R0 baseline | **PASS** |
| H1 hard-negative mining (A2) | **NOT EVALUABLE**: passed screening; the budget went to B, as registered |
| H2 low-FPR objective (B) | **SUPPORTED** (registered): replicated, and beats the A1 class-weighting control (0.362 vs 0.233). **Substantively limited to NF-BoT and NF-CIC, within about one baseline seed SD** |
| H3 service-relative features (C1) | **NOT EVALUABLE**: passed screening; not replicated; negative control not run |
| H4 combination | **NOT ATTEMPTED** (budget; only one hypothesis evaluable) |
| Gate M model development | **DEVELOPMENT GO, single member**, by the registered rule. The ensemble was not evaluated |
| Gate I independent confirmation | **NOT READY** |
| Gate D deployment | **NO-GO** |
