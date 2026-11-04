# Phase 8q final report: ground-truth integrity and label-free calibration

**Question.** Can we build a defensible attack-detection benchmark, and calibrate the detector
without verified attacker identities while keeping useful detection?

**Answer on development data:**
- **Benchmark (Problem A): yes.** A versioned, reproducible audit separates documented attackers,
  attacked hosts, undocumented sources and ambiguous cases. It changes *what is measured*, not
  how good the detector is.
- **Calibration (Problem B): no, on these data.**
  - The dependency on calibration labels was decomposed: roughly two thirds threshold
    contamination, one third contamination of the frozen destination memory.
  - None of the four registered label-free threshold estimators recovered the loss.
  - The calibration periods of NF-ToN and NF-BoT are attack-dominated, and the NF-CIC detections
    on 02-22 and 03-02 rest on a purged memory.

## Decisions (Part 21)

| decision | verdict | basis |
|---|---|---|
| ground-truth audit | **COMPLETE** | `label-audit-1.0.0`: every evaluation window categorised; official Table 2 rows verified (independent review); reproduces Phase 8p roles and S0 exactly. Limits: UTC−4 inferred from data; NF-BoT roles data-derived; no verified-benign population |
| calibration research | **NOT SUPPORTED** | Experiment F: best label-free gain +0.015 against the required +0.10 (L1); every candidate NOT SUPPORTED |
| model candidate | **NOT EVALUABLE** | no model was trained. The dependency lies in the calibration inputs, so retraining the scorer does not address the threshold part, and a memory change needs refits not covered by this phase |
| independent validation | **NOT READY** | no candidate; no eligible independent network (Phase 8o INDEPENDENT_DATA) |
| deployment | **NO-GO** | — |

## Repository

**Commits:**
- **Start:** `f112a1c` (= `origin/main`), with a clean tree and no tags.
- **Registration:** `50bcc4b`, before any candidate was computed.
- **Results:** `cfb0c67`; post-review fixes `55ecf65`.
- **Docs and closure:** the following commit.

**Not pushed. CI: NOT VERIFIED** (`gh` is not installed).

**New code and tests:**
- `scripts/phase8q/{label_audit, benchmark_metrics, calibration_decomposition, calibration_methods, experiment_fg, memory_guard_diag, figures}.py`;
- `tests/unit/test_phase8q.py` (8 tests).

**Unchanged:** raw data, frozen M2, every Phase 8h–8p artifact, and the deployed code (`src/`
untouched).

**Tests:** see the closing commit.

## Ground-truth findings (LABEL_AUDIT.md)

**Original attacking entities:** 75. By role:

| role | entities |
|---|---|
| documented attackers (or documented infected hosts) | 48 |
| attacked hosts | 5 |
| undocumented sources | 22 |

**Sources by role:** 48 / 7 / 290.

**Conflicts:**
- **02-20:** all 106 evaluation attack windows are the documented LOIC-UDP onset under the
  LOIC-HTTP label.
- **03-02:** 2,317 of 2,408 bot windows fall outside the documented operator intervals, as
  infected hosts beacon all day.
- **02-22:** 796 attack windows come from undocumented sources, plus 13,035 other windows of
  those hosts.
- **NF-ToN:** 32,924 non-attack windows of attacker hosts fall outside every metric.
- **Verified benign:** none.

**Frozen M2 (reference replicate) by view:**

| view | macro recall | R₂₀ |
|---|---|---|
| V0 historical | 0.788 | 44 / 75 |
| **V2 documented attackers** | **0.904** | 37 / 48 |
| V1 strict | 0.938 | 37 / 38 |
| attacked hosts | 0.33 | — |
| undocumented sources | 0.05 | — |

The difference between the views is the evaluation population, not a model improvement.

## Calibration findings (CALIBRATION_DECOMPOSITION.md, LABEL_FREE_CALIBRATION.md)

**Where the oracle-label dependency comes from.** P1x uses the calibration-attacker identities in
two places:
- it removes their windows from the T0 hold-out;
- it keeps their destinations out of the frozen memory used by every evaluation window.

**Decomposition** (Phase 8o F0 scores; macro recall_doc):

| cell | macro |
|---|---|
| U, no labels | 0.372 |
| T, threshold-only exclusion | 0.656 |
| TE | 0.869 |
| P, oracle | 0.869 |

| component | effect | where |
|---|---|---|
| threshold contamination | 0.285–0.351 | NF-UNSW +0.50, NF-ToN +0.64 |
| evaluation-memory contamination | 0.146–0.213 | NF-CIC +0.30, all from 02-22 and 03-02 |
| hold-out memory | 0 | — |

**Why:**
- **The threshold:** calibration attackers hold 92 % (NF-BoT), 76 % (NF-ToN) and 29 % (NF-UNSW)
  of the unlabelled hold-out windows.
- **The memory:** P1x's purge keeps 24 (02-22) and 9 (03-02) destinations, contacted during
  calibration only by the labelled sources, out of the memory. That is what makes those days'
  attacks novel.

**Label-free results:**

| method | macro recall_doc |
|---|---|
| U | 0.372 |
| L1 host cap α/2 | 0.387 |
| L2 block median | 0.372 (it fell back to U on NF-CIC and NF-UNSW: too few hour blocks) |
| L4 leave-one-host-out trim | 0.376 (NF-BoT FPR 14 %) |
| L5 abstention | 0.126 (abstains on NF-UNSW, NF-ToN, NF-BoT) |

Entity R₂₀ is unchanged except for L5 (−4, interval [−12, 0]).

**Controlled contamination of a clean hold-out (≤ 10 %):**
- **L1** resists one persistent host on NF-ToN (0.93 vs 0.71 at 10 %), but doubles clean FPR
  (31 % vs 16.5 %).
- **L4** resists spread contamination best (breakdown at 5 % vs 2 %), but trims a genuine benign
  NF-BoT host (FPR 56 %).

**Host diversity:** with 10 % of the hosts, T0's SD is 0.008 on NF-CIC and 0.21 on NF-ToN.

**Temporal drift:** not re-measured in this phase (Phase 8o/8p: benign novelty rises with memory
age; FPR 16 % on NF-ToN even with oracle labels).

**Memory guard** (≥ 2 sources; exploratory, feature level): it restores attack novelty only on
02-14, which needed none, fails on 02-22 and 03-02, and adds benign novelty everywhere.

## Machine learning

- **Implemented:** label-free threshold estimators (L1, L2, L4, L5), a counterfactual
  decomposition, contamination injection and a memory-guard diagnostic.
- **Trained:** no models. All analyses reuse the saved Phase 8o F0 per-member scores (seeds
  1000 + 10r + m, r = 6–8, base and stress) and the Phase 8n M2 scores.
- **Compute:**

  | run | time | peak |
  |---|---|---|
  | label audit | 42 s | 2.4 GiB |
  | decomposition | under 1 min | 0.6 GiB |
  | Experiment F | under 1 min | 0.7 GiB |
  | Experiment G | about 10 min | 0.7 GiB |
  | guard diagnostic | about 2 min | 1.8 GiB |

- **Model hashes:** not applicable (no new model).
- **Ablations:** the decomposition is the ablation of the two label mechanisms.

## Detection performance (frozen M2 on the audited benchmark)

**Documented-attacker recall, P1x oracle calibration (Phase 8o F0, 6 fits):**

| network | recall | FPR | false alerts / h |
|---|---|---|---|
| NF-CIC | 0.807 | 1.2 % | 295 |
| NF-UNSW | 0.835 | 3.7 % | 49 |
| NF-ToN | 0.884 | 16.5 % | 17 |
| NF-BoT | 0.950 | 8.0 % | 0.1 |

**Entities:** R₂₀ 37 of 48. The 11 never at ≥ 20 % are the ten 02-20 LOIC-UDP-onset attackers
and NF-ToN .37.

**Without labels:** NF-UNSW 0.054, NF-ToN 0.001.

**Detection delay:** Phase 8o, unchanged.

**Precision:** not reported. Attack prevalence differs from deployment, and there is no verified
benign set.

## Scientific validity

- **Hypotheses:** registered F decision rule (NOT SUPPORTED); G descriptive; the guard exploratory.
- **Pre-registration defects** caught on synthetic tests before registration: a cap above α, and a
  self-masking quantile.
- **Decision unit:** window recall averaged over 6 correlated fits, then over domains and networks.
  No sampling interval enters the rule.
- **Entity bootstrap** (domain clusters): reported.
- **Corrections after the independent review** (INDEPENDENT_REVIEW.md):
  - the memory effect located in 02-22 and 03-02, not "one destination";
  - wording: "the registered candidates did not recover", not "cannot work";
  - NF-UNSW described as contaminated, not dominated;
  - the registered extras added;
  - G's range limits stated.
- **Limits of generalisation:**
  - four consumed development networks, from two institutions;
  - attack-dominated calibration periods are a property of these testbeds.

## Top three unresolved problems

1. **Calibration still needs vetted calibration periods.** Both the threshold and the memory depend
   on knowing the calibration-period attackers.
   - *Evidence needed:* networks whose calibration contamination is sparse and documented, where
     the bounded-contamination estimators (L1/L4 hold to 5–10 %) can be tested where they are
     designed to work.
2. **On several days, detection rests on memory purity** (02-22, 03-02): the frozen-novelty
   shortcut.
   - *Evidence needed:* a registered, refit-based test of a representation that does not need a
     purged memory.
3. **Ground truth stays partial.**
   - There is no verified-benign set, and NF-BoT roles are data-derived.
   - The undocumented 02-22 sources are unresolved (undocumented is not benign).
   - *Evidence needed:* datasets with host-level ground truth and benign attestations.

Phase 8r is not started.

## Portfolio summaries (verified claims only)

- **GitHub:** "ML research on a network-intrusion detector: versioned ground-truth audit against
  official attack schedules, a counterfactual decomposition of calibration-label dependency, and
  pre-registered label-free calibration and contamination experiments; negative results
  reported."
- **ML Engineer:** "Built a reproducible label-audit layer (versioned evidence categories over
  about 710k evaluation windows, raw labels untouched) and a saved-score evaluation harness that
  reproduces earlier results exactly. Found and fixed estimator defects with synthetic tests before
  registration."
- **ML Research Engineer:** "Decomposed a detector's dependence on calibration labels into
  threshold (≈ 2/3) and feature-state (≈ 1/3) contamination. Showed the testbeds' calibration
  periods are attack-dominated (76–92 %). Pre-registered robust label-free thresholds, which did
  not recover the loss, and quantified their contamination breakdown points."
- **Do not claim:**
  - label-free calibration works;
  - FPR control;
  - production readiness;
  - cross-network generalisation.
