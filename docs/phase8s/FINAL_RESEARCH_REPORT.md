# Phase 8s final report: active, representative trusted calibration

**Question.** Can an active or stratified selection strategy find a small, realistic, trustworthy
and representative calibration sample that improves attack detection under a fixed false-alert
budget, without privileged attacker identities or future information?

**Answer on development data, with SIMULATED review:**
- **Representativeness: yes, the design problem is solved.**
  - Reviewing hosts with probability proportional to their window mass, and weighting by
    1/π_h (Hájek), removes Phase 8r's failure.
  - The NF-ToN median calibration error falls from 6.4 to 0.4 points.
- **Calibration: not at the registered budget.** At 30 expected host reviews, NF-ToN still
  exceeds its false-alert limit (FPR 20.1 % vs 18.0 % allowed). About 100 reviews would be needed
  (exploratory).
- **Realistic review breaks it.** Those designs must review the heavy attacker hosts, so a
  10–25 % false-benign reviewer contaminates the trusted set (about 20 % attack windows on NF-ToN
  and NF-BoT).
- **The tail is the binding constraint.** On NF-UNSW, NF-ToN and NF-BoT the benign 1 % tail
  lives on one to three hosts. No sample, however chosen, gives a tail guarantee there.
- **In the evaluation period, a correctly calibrated 1 % threshold detects almost nothing on
  NF-ToN and NF-UNSW.** The useful recall of every hold-out threshold there, the oracle's
  included, rests on FPR far above α.

## Decisions

| gate | verdict | basis |
|---|---|---|
| **A. Phase 8r engineering closure** | **PASS** | full suite on `bb9c9f2`: 419 passed, 0 failed, 0 errors, 0 skipped, 2 deselected (JUnit kept); CI run 42521466177 succeeded (test, docker, security); lint, format, dependency gate and lock clean |
| **B. Representative sampling** (H1) | **SUPPORTED** (registered); substantively on 2 of 2 non-census networks | median \|calibration error\| PPS + C1 vs random-host + C0: NF-ToN 0.37 vs 6.36 pp, NF-CIC 0.49 vs 0.62 pp. NF-UNSW/NF-BoT are census-limited (amendment S-3) |
| **C. Calibration quality** | **NOT SUPPORTED** | NF-ToN mean FPR 20.1 % (limit 18.0 %), p90 24.2 % (limit 21.0 %); the other networks pass |
| **D. Detection usefulness** | **DEVELOPMENT NO-GO** | gate C failed. The R₂₀ gain over the unlabelled threshold is +11.6, but against T (an oracle) it is +0.3 |
| **E. Independent confirmation** | **NOT READY** | no eligible unused network; DEDALE consumed; AIT/UWF have documented limits |
| **F. Deployment** | **NO-GO** | — |

**Secondary hypotheses:**

| hypothesis | verdict |
|---|---|
| H2 (Kish n_eff tracks error better than host count) | NOT SUPPORTED (2 of 4) |
| H3 (Hájek weighting helps) | SUPPORTED by rule; substantive on NF-CIC/NF-ToN only |
| H4 (robust to reviewer error) | NOT SUPPORTED |
| H5 (freshness) | SUPPORTED on its FPR-only metric, while detection collapses (macro 0.45 → 0.20) |

**Learned acquisition policy:** NOT RUN, as registered. There are no independent training
environments.

## Repository

**Commits:**
- **Start:** `bb9c9f2` (= `origin/main`), with a clean tree and no tags.
- **Registration:** `16f564b`.
- **Results:** `a5161d9`.
- **Review fixes and docs:** the following commit(s).

**Push:** not pushed (needs authorization).

**CI:** for this phase, not run (nothing pushed). For `bb9c9f2`: success.

**New code:**
- `scripts/phase8s/{active_calibration, experiments, estimand, posthoc, summarise, figures}.py`;
- `tests/unit/test_phase8s.py` (18 tests).

**Unchanged:** `src/`, the frozen M2, every Phase 8h–8r result.

**Run:** 631 s, peak 0.6 GiB (capped runner).
- Provenance in `experiments.json`: git SHA, clean-tree flag, 54 frozen-score hashes checked
  against Phase 8o, input hashes, feature-schema hash, split and arguments.
- Output hash in `experiments.sha256`.
- Per-row results and the primary review log (candidate IDs, π, outcomes) in
  `data/derived/phase8s/`, hashed in `derived_manifest.json`.
- Writes are atomic and never overwrite.

**Tests:** see § Validation.

## Stage 3: estimand and tail evidence (SAMPLING_ESTIMAND.md)

**Target:** the window-weighted benign FPR, with threshold q_b at α = 1 %.

**Evidence needed for an i.i.d. 1 % quantile:**
- 99 draws for E[FPR] ≤ α;
- 299 for the sample maximum to exceed q_b with 95 % probability.

**Benign hosts carrying the tail above q_b:**

| network | hosts (Kish) |
|---|---|
| NF-CIC | 153–214 (84–141) |
| NF-UNSW | 2.8 |
| NF-ToN | 2.0 (1.3) |
| NF-BoT | 1 |

**98 % of NF-ToN's benign hosts are single-window.** The one-way ANOVA design effect understates
this clustering.

## Experiments A–C (ACTIVE_CALIBRATION.md)

**k = 30, perfect simulated review:**

| cell | macro recall | NF-CIC FPR | NF-UNSW FPR | NF-ToN recall / FPR | NF-BoT FPR |
|---|---|---|---|---|---|
| U unlabelled | 0.372 | 1.2 % | 1.8 % | 0.001 / 0.4 % | 9.6 % |
| T oracle threshold | 0.656 | 1.2 % | 3.6 % | 0.640 / 16.0 % | 7.8 % |
| random host + C0 (8r style) | 0.724 | 1.5 % | 3.6 % | 0.926 / **45.7 %** | 7.8 % |
| **PPS + C1 (primary)** | 0.674 | 1.7 % | 3.8 % | 0.706 / **20.1 %** | 9.0 % |
| tail + C1 | 0.683 | 1.3 % | 3.8 % | 0.732 / 21.4 % | 9.0 % |
| PPS + C3 (conservative) | 0.144 | 1.1 % (abstains 21 %) | abstains 67 % | abstains 100 % | abstains 100 % |

**At k = 100** (exploratory): PPS, random-window and tail designs reach T's FPR on all four
networks (macro 0.659–0.661). Stratified and random-host designs do not.

**Why:**
- Random-host review lands on the near-silent single-window hosts.
- Equal-mass strata spend a third of the budget on the heavy attackers.
- Window-proportional designs reach the heavy benign hosts that carry the tail.
  - They also reach the attackers. On NF-ToN, 43 % of PPS reviews return MALICIOUS, and the
    SIMULATED cost is about 6× that of random-host review.

**No active or tail design beat the simple window-proportional controls.** Budget mattered more
than design.

**Operational burden at the primary cell:**
- false alerts per active benign host-hour: 0.08 (NF-CIC), 1.8 (NF-UNSW), 1.7 (NF-ToN),
  1.3 (NF-BoT);
- one host produces every NF-BoT false alert.

## Experiment D: reviewer error (CONTAMINATION_STUDY.md)

| reviewer | macro recall (PPS + C1) | key change |
|---|---|---|
| perfect (R0) | 0.674 | — |
| R1: 10 % false benign, 10 % inconclusive | 0.554 | NF-ToN recall 0.41; trusted sets about 23 % attack windows on NF-ToN and 20 % on NF-BoT |
| R2: missing-not-at-random review | 0.509 | — |

**Window-proportional review must be both representative *and* accurate on exactly the hosts
where errors cost most.**

## Experiment E: freshness (TEMPORAL_STABILITY.md)

**Refreshing the trusted set on the evaluation period's first half** (1 h review delay):
- brings second-half FPR to about α everywhere (0.2–1.8 %);
- its thresholds are 0.99 (NF-ToN), 0.94 (NF-BoT) and 0.67 (NF-UNSW);
- recall falls to 0.002, 0.50 and 0.03.

**On those networks, the benign 1 % tail of the evaluation period sits at attack level.**

## Machine learning

- **Models trained:** none. All results use the saved Phase 8o F0 scores of the frozen M2
  construction:
  - 6 fits, seeds 1000 + 10r + m (r = 6–8, base and stress), K = 5;
  - hyperparameters as Phase 8i B-raw.
- **Implemented:**
  - six Poisson sampling designs;
  - a simulated host reviewer (errors, inconclusive results, missing-not-at-random failures,
    SIMULATED cost);
  - Hájek and conservative cluster-bootstrap threshold estimators;
  - design-effect and tail-support diagnostics.
- **Ablations:** designs × estimators × budgets × reviewers, all reported.

## Statistical validity

- **Estimand:** the window-weighted benign FPR.
- **C1's validity:** design-consistent under perfect, conclusive review. Under R1/R2 it needs
  missing-at-random review failures, and R2 violates that by design.
- **Dependence:** hosts are clusters, and a review verdict is per host. No window-level bootstrap
  is used.
- **Tail evidence:** one to three hosts on three networks, so **no confidence statement about the
  1 % tail is possible there.** C3 abstains accordingly.
- **Uncertainty:** draws (p10/p90; degenerate on census networks) and 6 correlated fits.
- **Multiplicity:** 7 primary decisions on 4 correlated networks, 2 of them census-limited.
- **Independent review** (INDEPENDENT_REVIEW.md):
  - every decision input recomputed, and matched;
  - no leakage;
  - the H1/H3 census artefact and the H5 recall collapse are disclosed (amendments S-1 to S-3).

## Validation

**Full suite on the final code** (the code of `29c5ae4`; started after the review's code fixes):
437 passed, 0 failed, 0 errors, 0 skipped, 2 deselected, in 773 s.
- That is the 419 earlier tests plus 18 Phase 8s tests.
- JUnit file: `reports/phase8s/junit_phase8s_final.xml`.

**Other checks:**
- `ruff check` and `ruff format --check`: clean (485 files);
- dependency gate: OK;
- `uv lock --check`: current;
- dependencies added: none.

## Top three unresolved problems

1. **Calibrated detection on attack-dominated, drifting networks.** At a true 1 % FPR in the
   evaluation period, the frozen M2 with its frozen memory barely separates attacks on NF-ToN and
   NF-UNSW. Every useful recall there is bought with FPR well above α.
2. **The tail is a property of one to three hosts on three of four networks.** Thresholds there
   need host-level handling (per-host baselines or suppression) rather than one global quantile.
   *Evidence needed:* a registered comparison of per-host or host-group thresholds at matched
   alert budgets.
3. **Accurate review of heavy hosts.** Window-representative calibration must review exactly the
   hosts where reviewer error is costliest. No real reviewer error rates exist; these are
   simulated.

**Recommended next phase (not started):**
- a registered study of **host-conditional alerting**: per-host or per-host-group baselines and
  thresholds, against the global threshold, at matched false alerts per host-hour;
- it uses the saved scores, PPS review and the census networks as stress cases.

**Phase 8t is not started.**

## Portfolio summaries (verified claims only)

- **ML Research Engineer:**
  - "Recast intrusion-detector calibration as design-based survey sampling: Poisson PPS host
    review with Horvitz–Thompson/Hájek-weighted tail quantiles.
  - It removed the representativeness failure of random host vetting (median calibration error
    6.4 → 0.4 points on the hardest network).
  - I showed with tail-support diagnostics why no sample can certify a 1 % tail carried by one to
    three hosts, and why simulated reviewer error and drift defeat it.
  - Pre-registered, independently reviewed; negative results reported."
- **Do not claim:**
  - working trusted calibration;
  - FPR control;
  - validated human review;
  - production readiness;
  - independent generalisation.
