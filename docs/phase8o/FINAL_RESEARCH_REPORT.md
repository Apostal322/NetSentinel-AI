# Phase 8o final report: feature semantics, ensemble efficiency, entity robustness, calibration

**Question.** Can NetSentinel's feature semantics and trained models become more consistent,
while keeping useful detection under false-alert and compute limits?

The three parts (feature semantics, model robustness, operational reliability) were evaluated
separately.

**Answer on development data:**
- **Feature semantics.** The training rows do mix memory semantics, and that mix is confounded
  with the label. A deployment-aligned partial fix had no detectable effect.
- **Robustness.** The 5-member ensemble's stability gain reproduces on fresh randomness. No
  smaller ensemble meets the registered rule.
- **Calibration.** It fails for a different reason on each network, and none of the four simple
  methods fixes it. Without confirmed calibration labels, detection collapses.
- **Outcome.** No new candidate. The frozen M2 and the deployed detector are unchanged.

## Decisions (Part 20)

| decision | verdict | basis |
|---|---|---|
| 1. scientific research completion | **GO** | R1/R2 reproduce M2 and B0 exactly on 9 targets; R3 is bit-exact on 14 domains; all 216 registered score files exist; every rule applied as registered and independently recomputed. One registered control (F4) was degenerate (§ H) |
| 2. feature-semantics improvement | **NOT SUPPORTED** | H1 (F1 vs F0): macro recall −0.006; no path met. H1b (cold-start exclusion): NF-ToN −0.20 |
| 3. ML model improvement | **DEVELOPMENT NO-GO** | neither H1 nor H1b supported; no K < 5 preserves M2's benefit; no candidate improves the detection/false-alert/stability trade-off |
| 4. deployment readiness | **NO-GO** | no independent data (desk check: none eligible); FPR 8–16 × α on 2 networks; operation needs confirmed calibration labels |

## A. Repository

**Commits:**
- **Start:** `1ea3243` (= `origin/main`), with a clean tree.
- **Registration** `1872b1f` (audit, feature build, pre-registration, harness), committed before
  any Phase 8o fit.
- **Results, review and docs:** the following commit.
- Nothing has been pushed. No tag or release exists.

**CI: NOT VERIFIED** (`gh` is not installed).

**New files:**
- `scripts/phase8o/{semantics_audit, build_aligned, experiment_d, analyze_d, profile_inference, figures}.py`;
- `tests/unit/test_phase8o.py` (14 tests);
- `docs/phase8o/*` (this report, GAP_REGISTER, FEATURE_SEMANTICS, PREREGISTRATION,
  MODEL_COMPARISON, ENSEMBLE_EFFICIENCY, ENTITY_ROBUSTNESS, CALIBRATION_ANALYSIS,
  INDEPENDENT_DATA, INDEPENDENT_REVIEW, 9 figures);
- `reports/phase8o/*.json`, including a SHA-256 manifest of the 216 score files.

**Edited:**
- the Phase 8n report (publication-status addendum);
- README, `docs/RESULTS.md`, `docs/HYPOTHESIS_LEDGER.md` (Phase 8o entries).

**Unchanged:** every Phase 8h–8n artifact, every frozen result, and the deployed code
(`src/` untouched). No data was downloaded.

**Runs** (sequential, `run_capped` 3.4 GiB, CPU):

| run | time | peak |
|---|---|---|
| Stage A audit | 37 s | 1.3 GiB |
| feature build | 2 min | 1.4 GiB |
| inference profile | 106 s | 1.5 GiB |
| **Experiment D** (authorized) | 89 min | 1.95 GiB |
| analysis | about 4 min | 0.8 GiB |

## B. Gaps (GAP_REGISTER.md)

| gap | root cause | correction / test | evidence | remaining limit |
|---|---|---|---|---|
| G0.1 mixed memory semantics in training | calibration rows use an expanding memory and are all benign; every attack row uses a frozen one | F1 (partial alignment), F2 (dose contrast) | F1 −0.006 macro recall; F2 NF-CIC AUC 0.48 | the confound remains; an "expanding in training and scoring" arm is untested |
| G0.2 cold-start source days (NF-CIC 02-27/02-28) | the Phase 8i time midpoint leaves 331 and 855 calibration flows | F5 | NF-ToN −0.20 | harm not established |
| G0.3 hold-out less novel than evaluation | expanding hold-out vs frozen evaluation | C1 | 3 of 4 networks closer to α; NF-UNSW recall halves | open |
| G1.1 excess FPR | stale memory and host turnover (NF-ToN); 17–80 host-hour blocks (NF-UNSW, NF-BoT); host concentration (NF-BoT) | C1–C4 | CALIBRATION_ANALYSIS | open |
| G1.2 ensemble cost | — | K-curve plus measured cost | K = 5 retained | — |
| G1.3 entity flips | attack clusters 0.00–0.06 above T0 | ensembling | single-member U₂₀ 13–24 → 5 | 20 entities never detected |
| G2.1 / G2.2 missing reply field; split windows | `fill_null(0)`; per-call aggregation | regression tests | — | no change to deployed behaviour |

## C. Feature semantics

- **What was inconsistent:** `new_dst_frac` is computed with an expanding memory in calibration
  rows (training, and the T0 hold-out) and a frozen memory in evaluation rows (training attack
  rows, and target scoring). Feature names match; semantics do not. The other 11 features carry
  no state (FEATURE_SEMANTICS § 2).
- **Was there an actual training/inference mismatch?** Partly.
  - Attack rows are trained with the scoring semantics.
  - Benign calibration rows and the T0 hold-out are not.
  - One source day (02-28) supplies an expected 73 % of the novel benign NF-CIC training rows.
- **Fixes implemented:**
  - causal rebuilds: F1 with memory frozen at q in source calibration; C1, the hold-out frozen at
    its start;
  - each verified bit-exact before its freeze point and against the historical rebuild (F3);
  - causality is tested (`test_freeze_inside_calibration_is_causal_and_reproduces_before_q`).
- **Did they improve the model?** No.
  - F1: no detectable effect.
  - F5: NF-ToN recall −0.20.
  - C1: NF-UNSW recall −0.32.
- **Most informative result: F2.** Removing the frozen-novelty attack association in training
  collapses NF-CIC to chance ranking. The model's NF-CIC detection rests on that association,
  which is a dataset-specific shortcut.

## D. ML models trained

| run | models | configuration |
|---|---|---|
| Experiment D | 480 LightGBM members | arms F0, F1, F4 (base + stress × r 6–8) and F2, F5 (base × r 6–8); 5 members each; 4 leave-one-network-out source sets |
| R1 / R2 checks | 24 | M2 r0 members and B0 r0 |
| profile | 5 | M2 r0 members on the NF-CIC target's sources |

**Shared setup:**
- Phase 8i B-raw LightGBM parameters;
- member seeds 1000 + 10r + m;
- the 12 registered features (F4: squared `new_dst_frac`);
- P1x calibration; α = 1 %.

**Fit time:** median about 45 s per source set for 5 members.

**Provenance:** git HEAD, code hashes, package versions and parameters are recorded in
`reports/phase8o/experiment_d_runs.json`. Score hashes are in
`experiment_d_scores_sha256.json`. Profile model hashes are in `inference_profile.json`.

## E. Ensemble efficiency (ENSEMBLE_EFFICIENCY.md)

| K | macro recall | U₂₀ | collapses | windows/s (2 threads) | single-window latency (ms) | artifact (MB) |
|---|---|---|---|---|---|---|
| 1 | 0.599 (members: 0.60–0.77, mean 0.695) | 24 (members 13–24) | 5 | 94,300 | 0.10 | 0.35 |
| 2 | 0.708 | 11 | 0 | 55,400 | 0.18 | 0.71 |
| 3 | 0.725 | 6 | 0 | 36,000 | 0.27 | 1.06 |
| **5** | **0.762** | **5** | 0 | 20,600 | 0.42 | 1.77 |

- **K = 3 keeps stability but loses recall** on NF-UNSW (−0.03), NF-ToN (−0.05) and NF-BoT (−0.07).
- **Best supported size: K = 5**, because no prefix K < 5 met the rule.
- **Cost is linear in K and small:** about 20,000 windows/s on a 4-core i5.
- **Uncertainty:** the 6 fits are correlated; subset spreads are reported, not intervals.

## F. Attack detection (F0, K = 5, 6 fits)

| network | window recall (min–max) | FPR | false alerts / h | median delay |
|---|---|---|---|---|
| NF-CIC (6 days) | 0.680 (0.02–1.00 by day) | 1.2 % | 295 | 15 s |
| NF-UNSW | 0.835 (0.28–0.99) | 3.7 % | 49 | 5 s |
| NF-ToN | 0.659 (0.58–0.74) | 16.5 % | 17 | 40 s |
| NF-BoT | 0.873 (0.85–0.89) | 8.0 % | 0.1 | 0 s |

**Entities** (75; at ≥ 20 % of windows):
- 40 detected in all 6 fits, 5 in some, 30 in none;
- 20 never alerted at all: 19 web attacks on 02-22 and 1 LOIC-HTTP source.

**Worst-entity failures:**
- single members lose the single-attacker days (02-14, 02-16) and the 03-02 bots in 6–13 of 30
  fits;
- K = 5 loses none of them.

**Per-domain recall:** MODEL_COMPARISON § 4.

## G. Calibration (CALIBRATION_ANALYSIS.md)

**Registered threshold:** T0, a conformal rank on the P1x hold-out.

**Evidence that calibration fails:** FPR is 1.2 % (NF-CIC), 3.7 % (NF-UNSW), 16.5 % (NF-ToN) and
8.0 % (NF-BoT) against α = 1 %. The causes differ by network.

**Methods tested:**

| method | result |
|---|---|
| C1 aligned hold-out | NOT SUPPORTED |
| C2 minimum evidence | flags NF-UNSW and NF-BoT as invalid and silences them; does not catch NF-ToN |
| C3 no calibration labels | recall collapses through the threshold *and* through the destination memory |
| C4 novelty-rate abstention (exploratory) | abstains on 98–99.9 % of three networks; triggered by the attacks themselves |

**Statistical limits:**
- T0 rests on the 4th or 7th highest hold-out score on NF-UNSW and NF-BoT;
- windows are dependent;
- no distribution-free guarantee holds under this shift.

## H. Scientific integrity

**Registered and decided:** H1, H1b, H2, C1.

**Registered and descriptive:** H3, H5, C2, C3, F2.

**EXPLORATORY:**
- the Stage A audit;
- C4;
- the subset spreads;
- the per-fit paired differences;
- the C1 NF-CIC subgroup.

**Replication:**
- M2's construction reproduced bit for bit (R1);
- its stability gain over single members reproduced on fresh replicates r = 6–8.

**Negative results:**
- H1, H1b, C1 and K < 5;
- F2's collapse;
- C3's collapse;
- C4's failure.

**Design error:**
- **F4, the registered matched-information control, was degenerate.** A monotone transform
  leaves LightGBM splits unchanged, so the noise floor was 0 by construction.
- No verdict depends on it.
- Recorded rather than repaired after the fact.

**Independent review:** 14 findings; INDEPENDENT_REVIEW.md lists each one with its action.
Corrections after the review:
- C3 mechanism (features as well as threshold);
- the F2 reading;
- H2's comparison baseline (member average);
- H1 wording ("no detectable effect");
- biased R/U comparisons;
- C1 rule weaknesses;
- prevalence caveats.

No verdict changed.

**Unchanged:**
- historical verdicts and frozen artifacts;
- the frozen M2;
- DEDALE (not used).

## I. Validation

- **pytest:** 384 passed, 2 deselected (`slow`/`gpu`/`data` markers), 0 failed, 0 skipped, in
  4 min 16 s. It includes the 14 new Phase 8o tests:
  - feature contract (6);
  - F1 causality and F3 reproduction;
  - arm construction;
  - metrics and assessment gate;
  - prefix ensembling;
  - the H1, H2 and C1 rules.
- **ruff check and format:** clean (421 files).
- **Dependencies:** none added.
- **Feature compatibility:** `WINDOW_FEATURES` is unchanged; R3 is bit-exact.
- **Model compatibility:** R1/R2 exact.
- **Artifact integrity:** a SHA-256 manifest of all 216 score files; profile model hashes.

## J. Recommendation

- **Close Phase 8o.** The registered questions are answered, mostly negatively, with reproducible
  evidence.
- **No new candidate deserves independent testing.** The frozen Phase 8n M2 remains the only
  candidate and stays development-only.
- **No model should be deployed.**

**The three most important remaining problems, and the evidence they need:**

1. **Calibration is not valid under host turnover and memory ageing, and it needs confirmed
   calibration labels** (FPR 8–16 × α on NF-ToN and NF-BoT; C3 collapse).
   - *Evidence needed:* networks with many independent benign host-hour blocks and documented
     clean calibration periods, to test a dependence-aware threshold with a memory-age validity
     rule.
2. **Detection relies on a dataset-specific novelty shortcut, and misses whole attack classes.**
   - F2: NF-CIC AUC 0.48 without the shortcut.
   - 30 of 75 entities are never detected at ≥ 20 %. Web attacks and distributed HTTP floods sit
     0.4–0.85 below T0.
   - *Evidence needed:* a registered victim-side or service-level representation, compared
     against B0 on development data, then on fresh networks.
3. **No independent confirmation is possible.**
   - The four networks are consumed and correlated: 52 of 75 entities are on NF-CIC.
   - The desk check found no eligible fresh network.
   - *Evidence needed:* 13–30 independent networks (Phase 8l power analysis) under the E1–E7
     rules.

Phase 8p is not started.

## Portfolio summary (verified claims only)

- **Pre-registered and ran a matched-arm feature-semantics study on LightGBM.**
  - 480 member fits, with every reference reproducing the frozen models bit for bit.
  - It showed the detector's novelty signal is confounded with how training rows were built.
  - Reported that a causal alignment fix gave no detectable gain.
- **Measured ensemble cost and stability.**
  - A 5-model ensemble cut unstable attacker outcomes from 13–24 to 5 relative to single
    members.
  - Scoring stays linear in K: about 20k windows/s at K = 5.
  - Smaller ensembles failed the registered recall guardrail.
- **Ran an independent review that corrected several of the phase's own claims** and caught a
  degenerate pre-registered control, without changing any registered verdict.

**Do not claim:**
- production readiness;
- cross-network generalisation;
- FPR control;
- that "alignment does not matter".
