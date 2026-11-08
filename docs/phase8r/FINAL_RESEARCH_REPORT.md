# Phase 8r final report: trusted calibration, weak supervision and contamination

**Question.** Can limited, realistically obtainable trusted evidence support useful calibration
and attack detection, without complete attacker identities or future ground-truth labels?

**Answer on development data: not with the budgets and selection policies tested.**
- **Without trusted evidence or a contamination bound, the benign threshold is not
  identifiable.** This is a property of the problem, not of Phase 8q's estimators.
- **A representative trusted-benign sample would identify it.** But the target is
  window-weighted, while realistic vetting samples hosts.
- **Host-sampled trusted sets** (3–30 hosts, ORACLE-SIMULATED vetting) pushed the threshold below
  the benign tail. Recall rose with 3–6× the oracle FPR on NF-ToN and NF-BoT.
- **Trusted sets tolerate only 2–5 % contamination.**
- **No memory policy restored NF-CIC 02-22 / 03-02 novelty** without flooding benign novelty.

## Decisions

| gate | verdict | basis |
|---|---|---|
| scientific identifiability | **CONDITIONALLY IDENTIFIABLE** | the threshold is identifiable only with window-representative trusted benign evidence. Otherwise NOT IDENTIFIABLE: the identified set is the whole score range. A host-level FPR guarantee is NOT IDENTIFIABLE on NF-UNSW and NF-BoT (17 and 7 benign hosts), and recall is not identifiable without T4 evidence |
| trusted calibration | **NOT SUPPORTED** | H-A1: +0.337 macro recall, but FPR criteria (ii) and (iv) fail on NF-CIC (ii), NF-ToN and NF-BoT |
| contamination robustness | **NOT SUPPORTED** | H-B1: A3 loses more than 0.10 at 5 % under 5 of 6 mechanisms. *The verdict hinges on NF-ToN* (about 10 trusted windows; "5 %" ≈ 9 %); without NF-ToN every mechanism stays within the limit |
| model improvement | **NOT EVALUABLE** | no memory variant passed the registered feature-level gate, so the scored refits were not run; Experiment D's condition was false, so it was not run |
| independent confirmation | **NOT READY** | no eligible unconsumed network; DEDALE consumed |
| deployment | **NO-GO** | — |

## Repository

**Commits:**
- **Start:** `84a3d0e` (= `origin/main`), with a clean tree and no tags.
- **Registration:** `fd7affa`, before any A/B/C outcome.
- **Results:** `a8a6980`.
- **Review fixes, docs and closure:** the following commit.

**Not pushed. CI: NOT VERIFIED** (`gh` is not installed).

**New code:**
- `scripts/phase8r/{identifiability, trusted_methods, experiment_ab, experiment_c_features, summarise, figures}.py`;
- `tests/unit/test_phase8r.py` (12 tests).

**Unchanged:** raw data, the frozen M2, every Phase 8h–8q artifact, and `src/`.

**Tests:**
- **Full suite** (detached, `--junitxml`, 19 min, with other projects' runs active): 418 passed,
  **1 failed**, 2 deselected.
  - The failure was the new M3 test. It ran against the pre-fix code because the fix was applied
    while the suite was running.
  - After the fix, `tests/unit/test_phase8r.py` gives 12 / 12 passed.
  - **The full suite was not re-run after the fix.**
- **ruff check and format:** clean for `scripts/phase8r` and the new tests.
- **Dependencies:** none added.

**Compute** (all saved-score analyses; no model was trained):

| run | time | peak |
|---|---|---|
| identifiability | under 1 min | 0.6 GiB |
| Experiments A and B | 7.8 min | 0.9 GiB |
| Experiment C, feature level (each run) | about 2 min | 1.2 GiB |

## Stage 1: identifiability (CALIBRATION_IDENTIFIABILITY.md)

**Trust categories:**
- T0 unknown;
- T1 dataset-labelled benign;
- T2 weakly trusted;
- T3 vetted benign;
- T4 confirmed malicious.

**Deployment information boundary:** T1, P1x and evaluation labels are never available to a
deployment method.

**Horowitz–Manski identified sets:**
- At the true contamination the FPR range spans 0.1–64 % on NF-ToN, 1.5–97 % on NF-BoT and
  1.7–19 % on NF-UNSW.
- Any bound tight enough to help is false on those networks. On NF-CIC, small bounds hold on 4 of
  6 days.
- **Memory:** with the unlabelled memory, the oracle threshold gives 02-22 recall 0.003 and 03-02
  0.0004. That loss is feature state, which no threshold fixes.

## Experiment A: trusted-negative calibration (TRUSTED_CALIBRATION.md)

| cell | macro | NF-CIC FPR | NF-UNSW FPR | NF-ToN FPR | NF-BoT FPR |
|---|---|---|---|---|---|
| A0 unlabelled | 0.372 | 1.2 % | 1.8 % | 0.4 % | 9.6 % |
| A1T oracle threshold | 0.656 | 1.2 % | 3.6 % | 16.0 % | 7.8 % |
| A1 full oracle | 0.869 | 1.2 % | 3.6 % | 16.4 % | 8.0 % |
| **A3 modest / random (primary)** | 0.709 | 3.7 % | 3.6 % | **68.9 %** | **25.7 %** |

**Why:**
- 98 % of NF-ToN's benign hold-out hosts have a single near-silent window. Ten random hosts give
  about 11 trusted windows.
- Below 99 windows the capped conformal rank is the sample maximum (disclosed).

**Other findings:**
- **Persistent-host vetting at the larger budget** reproduces the oracle threshold on three
  networks (exploratory).
- **The catch:** persistent hosts are largely attackers (9 of the 10 most persistent NF-ToN
  hosts), so vetting must find them all.
- **Unvetted administrator trust (T2)** stays at A0.
- **Annotation errors** of 10–25 % cost 0.14–0.23 macro under persistent-host vetting.

## Experiment B: contamination of the trusted set (CONTAMINATION_ROBUSTNESS.md)

| method | breakdown |
|---|---|
| A2 | 2 % |
| A4 | 2 % |
| A3 | 5 % (`service_matched`: 10 %) |

- This is the same bounded robustness as Phase 8q's label-free estimators, far below the real
  calibration contamination of these testbeds (29–92 %).

## Experiment C: memory contamination (MEMORY_CONTAMINATION.md)

**Feature level only.** No variant passed the scored-part gate.

| policy | result |
|---|---|
| quarantine | promotion needs ≥ 2 sources AND ≥ 2 hours; restores 0 novelty on 02-22 and 0.004 on 03-02 |
| purge of vetted-malicious destinations | restores 0 on both days (random vetting finds about 0 of 191 attackers) |
| trusted-only allowlist | restores everything, but benign novelty rises by 67–84 points |

**The purge works where vetting finds the attackers.** That is NF-UNSW (random vetting) and NF-BoT
(persistent-host vetting). These are the networks where attackers are a large share of hosts.

**Bug found by the review and fixed:** the first M3 run implemented OR instead of AND. The verdict
is unchanged (amendment R-1).

## Experiment D: weakly supervised training

**NOT RUN.** Its registered condition was H-A1 SUPPORTED and an H-C1 candidate, and it was false.
Realistic budgets yield a handful of T4 hosts per domain, too few for supervision.

## Statistics and validity

**Decision units:** the registered means, with draw p10/p90 and 6 correlated fits. No p-values.

**Review** (INDEPENDENT_REVIEW.md):
- every reported A/B number recomputed, and they matched;
- no leakage;
- chronology confirmed.

**Corrections after the review:**
- the M3 bug;
- the NF-ToN dependence of H-B1;
- the sample-maximum behaviour;
- the NF-CIC bound qualified by day;
- the 99-host statement restated.

**Generalisation:** four consumed development networks from two institutions. Every result is
development evidence.

## Independent-data strategy

A confirmatory test of trusted calibration needs a network with:
1. host-level ground truth for the calibration period, so that vetting can be simulated without
   flow-label noise;
2. a benign population whose window mass is not dominated by attackers;
3. enough benign hosts (≥ 99) for a host-level guarantee;
4. no prior use in this project.

None is known locally. Acquiring one needs the user's authorization (download size, licence).

## Top three unresolved problems

1. **Window-representative vetting.**
   - The FPR target weighs traffic, but analysts review hosts.
   - *Evidence needed:* a registered test of activity-weighted (or stratified-by-volume) host
     sampling with abstention below 99 trusted windows, on a network whose heavy hosts are
     mostly benign.
2. **Memory purity on shared-target attacks** (02-22, 03-02).
   - Neither quarantine nor trusted purges restore novelty.
   - *Evidence needed:* a representation that does not rely on a purged destination memory,
     tested with refits.
3. **No verified benign data and no independent network.** All vetting here is simulated from
   dataset labels.

Phase 8s is not started.

## Portfolio summaries (verified claims only)

- **ML Research Engineer:** "Framed detector calibration as partial identification
  (Horowitz–Manski). I showed that the benign threshold is not identifiable from contaminated
  calibration data without trusted evidence. I pre-registered trusted-sample calibration with
  simulated vetting budgets and selection policies, and it failed because host sampling does not
  represent window-weighted FPR. An independent review caught an implementation bug, which was
  fixed and disclosed."
- **Do not claim:**
  - trusted calibration works;
  - FPR control;
  - robustness to contamination;
  - production readiness;
  - independent generalisation.

## Addendum (2026-11-09): publication and closure status

Added in Phase 8s. The findings above are unchanged.

**Publication.** The report's "Not pushed. CI: NOT VERIFIED" line describes the state when it was
written.
- `fd7affa`, `a8a6980` and `bb9c9f2` were pushed to `origin/main` on 2026-11-08 (`84a3d0e..bb9c9f2`).

**CI.** GitHub Actions run 42521466177 (workflow `ci`, push event, head `bb9c9f2`) **succeeded**.
- Its jobs: `test` (uv sync, dependency gate, ruff check, ruff format --check, pytest), `docker`
  and `security`.
- It was read through the public GitHub REST API, since `gh` is not installed.

**Full local regression on `bb9c9f2`:** 419 passed, 0 failed, 0 errors, 0 skipped, 2 deselected
(1,750 s, with other projects' training and tests sharing the machine).
- This includes `test_quarantine_promotion_needs_two_sources_and_two_hours`.
- JUnit file: `reports/phase8s/junit_phase8r_closure_bb9c9f2.xml`.
- It replaces the "full suite was not re-run after the fix" caveat above.
