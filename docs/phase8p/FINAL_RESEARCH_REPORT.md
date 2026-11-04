# Phase 8p final report: victim-side, service-aware and bidirectional detection; realistic calibration

**Question.** Can victim-side, service-aware and bidirectional representations improve
detection of the attacks the detector misses, at an acceptable false-alert rate and without
dataset-specific shortcuts? And is the missing evidence present in the telemetry at all?

**Answer on development data:**
- **Most "missed attacks" were not missed attacks.** A label audit against the official
  CSE-CIC-IDS2018 table shows that 19 of the 20 never-detected entities are undocumented sources:
  label artifacts.
- **The remaining documented misses are separable within their own network.** That is not
  established as transferable evidence.
- **No new representation improved operational detection under the shared 1 % budget.**
  - Victim context mostly encodes shared-infrastructure fan-in, and it collapsed NF-CIC.
  - Late fusion inherited victim scores onto benign co-clients.
- **Without confirmed calibration labels, detection collapses.**
- **No candidate.** The frozen M2 and the deployed detector are unchanged.

## Verdicts (Part 22)

| decision | verdict | basis |
|---|---|---|
| research completion | **GO** | R1 exact (27/27); every registered fit complete (297 score files); decisions recomputed independently; two registered-design defects recorded (D3 ties, the 0.03-margin justification) |
| victim-side ML contribution | **NOT SUPPORTED** | D2: documented-attacker R₂₀ −19, NF-CIC recall 0.81 → 0.18. D1 does not transfer (NF-CIC victim-window AUC below 0.5 on 4 of 6 days). Exploratory only: oracle ranking improves on 3 of 4 networks |
| service-aware ML contribution | **NOT SUPPORTED** | S1: R₂₀ −7 (all from the 03-02 bots and one 02-14 attacker, partly offset on NF-ToN); NF-ToN false alerts 1.70 ×; no port shortcut (service-only control 0.13) |
| model candidate | **DEVELOPMENT NO-GO** | D2, S1, D2S and D3 all fail guardrails |
| deployment | **NO-GO** | no independent data (Phase 8o INDEPENDENT_DATA); FPR 8–16 × α on 2 networks even with oracle calibration labels |

## A. Repository

**Commits:**
- **Start:** `8e5d079` (= `origin/main`), with a clean tree and no tags.
- **Registration** `5cdbe8d`: Stage 1, features, pre-registration and harness, before any
  Experiment E fit.
- **Results, review and docs:** the following commit.
- Nothing has been pushed. No tag or release exists.

**CI: NOT VERIFIED** (`gh` is not installed).

**New code and tests:**
- `src/netsentinel/behavior/victim.py`, a research module not used by the monitor;
- `scripts/phase8p/{missed_inventory, observability, build_victim, build_c2, experiment_e, analyze_e, figures}.py`;
- `tests/unit/test_phase8p_victim.py` (8) and `test_phase8p_decisions.py` (7).

**Unchanged:** deployed code paths, frozen artifacts, Phase 8h–8o results, M2 and DEDALE. No data
was downloaded. The only network access was reading the official dataset web pages.

**Tests executed:** see § H.

## B. Detection-gap analysis (ATTACK_OBSERVABILITY.md, FAILURE_ANALYSIS.md)

**The role audit of the 75 evaluation entities:**

| role | entities | detected ≥ 20 % in all fits | never alerted |
|---|---|---|---|
| documented attackers | 48 | 37 | 1 |
| attacked hosts' traffic | 5 | 2 | 0 |
| undocumented sources | 22 | 1 | 19 |

**Which attack families were missed:**
- **"Web attacks" on 02-22:** label artifacts. They include:
  - internet hosts whose labelled flows are 0.6–2 % of their traffic;
  - keepalive-like flows;
  - the victim's own DHCP.
- **The documented web attacker is detected** (median recall 0.89).
- **02-20 "LOIC-HTTP" (10 documented attackers):** the evaluation holds the onset of the
  documented DDoS-LOIC-UDP attack under the HTTP class label (a likely family mismatch). The HTTP
  flood itself is in calibration.
- **NF-ToN 192.168.1.37:** low-rate SMB on a mixed host; weakly observable.

**Observable evidence:**
- every documented miss is separable within its network on both sides;
- the in-domain ceiling can leak host identity, so this is not evidence of transferable signal.

**Not established by these data:**
- whether payload-only web exploits are observable in flows. There is only one documented web
  attacker, and it is detected through volume and novelty.

**Label ambiguities that matter:**
- attack labels on undocumented hosts and outside the documented intervals;
- attacked hosts' responses labelled attack;
- a family label inconsistent with the documented attack.

## C. New ML features

**Victim windows** (`VICTIM_FEATURES`, 16; schema `victim-1.0.0`):
- inbound flows, distinct sources, ports and bytes in each direction, packets;
- no-reply, reset, UDP and short-connection shares; median duration;
- response share, top-source concentration, web share;
- a causal expanding history: deviation from the host's earlier windows, and the count of them.

**Source-window victim context** (5): the extremes, over the responders contacted in the
window, of their victim features.

**Service context** (4): web, DNS and well-known-port shares; the number of service categories.

**Causality:**
- the history is tested to use only earlier windows;
- chunked processing equals one-shot processing;
- a rebuild with the final code is identical.

**Ablations:**

| arm | macro recall_doc |
|---|---|
| D1 vs D1h (no history) | no difference in conclusion |
| Sonly (service only) | 0.13 |
| D2 (context) | 0.70 |
| S1 (service) | 0.79 |
| D2S (both) | 0.77 |
| S0 (source only) | 0.87 |

## D. Model training

**Implemented and trained:** S0 (refit), D2, S1, D2S, Sonly, D1 and D1h, plus D3 without a fit.

| item | value |
|---|---|
| LightGBM fits | 660 members |
| construction | 5 members, Phase 8i parameters, seeds 1000 + 10r + m, r = 6–8 |
| regimes | base and stress (controls: base only) |
| sources | leave-one-network-out; training cap 50,000 per domain; network- and class-balanced weights |
| calibration | P1x, T0 at α = 1 % |
| runtime | 113 min from first to last score file (≈ 117 with data loading); the registered estimate was 100–120 min |
| peak memory | 2.2 GiB under the 3.4 GiB cap |

**Artifacts:**
- no models are saved;
- per-member scores, plus a SHA-256 manifest (`reports/phase8p/experiment_e_scores_sha256.json`);
- provenance (git HEAD, code hashes, versions) in `experiment_e_runs.json`.

## E. Model performance (MODEL_COMPARISON.md)

| arm | NF-CIC recall_doc / FA | NF-UNSW | NF-ToN | NF-BoT | R₂₀,doc |
|---|---|---|---|---|---|
| S0 | 0.807 / 1,216 | 0.835 / 436 | 0.884 / 1,225 | 0.950 / 49 | 37 |
| D2 | 0.182 / 1,040 | 0.919 / 644 | 0.902 / 1,304 | 0.802 / 38 | 18 |
| S1 | 0.540 / 1,195 | 0.704 / 340 | 0.961 / 2,086 | 0.933 / 48 | 30 |
| D3 | 0.779 / 1,248 | not operable | 0.877 / 1,204 | 0.928 / 284 | 32 |

**Missed entities:**
- no arm recovers any of the ten 02-20 LOIC attackers;
- S1 detects NF-ToN .37, but only at 28 % FPR on NF-ToN.

**FPR at T0 (S0):** NF-CIC 1.2 %, NF-UNSW 3.7 %, NF-ToN 16.5 %, NF-BoT 8.0 %.

**Delay and workload** (Phase 8o, same fits):
- median delay: 15, 5, 40 and 0 s;
- false alerts per hour: 295, 49, 17 and 0.1.

**Precision is not reported.** Attack prevalence in evaluation (NF-UNSW 25 %, NF-BoT 46 %) makes
it non-transferable.

**Ranking (diagnostic only):**
- victim context improves oracle ranking recall on NF-UNSW (0.17 → 0.34), NF-ToN (0.06 → 0.27)
  and NF-BoT (0.45 → 0.67);
- it destroys NF-CIC's (0.68 → 0.07).

**Uncertainty:**
- 6 correlated fits;
- domain-cluster bootstrap intervals of the R₂₀ change: D2 [−43, −2], S1 [−22, +2], D3 [−13, 0];
- paired network-macro differences are negative in every base fit.

## F. Calibration (CALIBRATION_STUDY.md)

| scenario | macro recall_doc | note |
|---|---|---|
| C0 P1x (oracle labels) | 0.869 | reference |
| C1 unlabelled | 0.372 | NF-UNSW 0.05, NF-ToN 0.001 |
| C2 labels after 60 min | 0.387 | attackers active until near the calibration end stay unlabelled |
| C3 host-balanced | 0.613 | restores NF-ToN (0.93) by moving T0 into transient hosts' scores (FPR 34 %) |

- **Assumption:** the conformal rank's exchangeability, which does not hold across this shift.
- **No scenario controls FPR,** including the oracle one.
- **Operational limitation:** operation requires verified calibration-period labels.

## G. Scientific results

| hypothesis | registered outcome | counterexample / note |
|---|---|---|
| H1 victim-side signal | NOT SUPPORTED | oracle ranking gains on 3 networks (exploratory) |
| H2 service context | NOT SUPPORTED | service-only control weak, so no shortcut |
| H3 bidirectional fusion | NOT SUPPORTED | tie defect on NF-UNSW; inherited scores on NF-BoT |
| H4 realistic calibration | NOT SUPPORTED | C3 restores NF-ToN recall, at 34 % FPR |

**Independent confirmation:** none exists.

## H. Engineering quality

**Bugs fixed:**
- a string-buffer pinning leak (victim build: 3.3 → 1.3 GiB);
- the cap overrun of the Stage 1 inventory;
- tie handling in the univariate AUC;
- the documented-interval table (UTC offset; the missing LOIC-UDP row; per-host intervals);
- the domain-path bug in the harness, caught by the dry run before training;
- the join-order guard.

**Pipeline and model compatibility:**
- the deployed feature list and models are untouched;
- new features carry a schema version.

**Resources:** every run is under the cap.

**Remaining:**
- the live streaming path computes no victim features;
- the D3 fusion needs a tie-aware rank.

**Tests:** 15 new.
- **Full suite:** 399 passed, 2 deselected (`slow`/`gpu`/`data` markers), 0 failed, 0 skipped.
  It took 14 min only because other projects' test runs shared the CPU (Phase 8o: 4 min).
- **ruff check and format:** clean (440 files).
- **Dependencies:** none added.

## I. Final verdict

| question | verdict |
|---|---|
| research | GO |
| development model | NO-GO |
| independent validation readiness | not applicable (no candidate; no eligible network) |
| deployment | NO-GO |

## J. Remaining priorities (at most three; none started)

1. **A label-audited evaluation set as the default.** Make the documented-attacker set (with
   documented intervals) the standard entity set for every future comparison, and re-score Phase
   8n M2 against it.
   - The 02-22 artifacts and the 02-20 family mismatch show the historical set mis-states what is
     missed.
   - Saved scores suffice; no training is needed.
2. **Calibration that is valid under host turnover and needs no labels.**
   - Neither delayed labels nor host balancing works here.
   - The evidence needed is networks with many independent benign hosts and documented clean
     calibration periods.
3. **Network-invariant victim evidence.**
   - Victim fan-in reflects topology.
   - A per-responder *self-normalised* representation is the next registered test before any
     fusion is retried: deviation from the responder's own calibration profile, compared only
     within service. It must come with a tie-aware rank and a calibration covering
     evaluation-time victim scores.

Phase 8q is not started.

## Portfolio summaries (verified claims only)

- **GitHub:** "Pre-registered ML research on a network-intrusion detector: label audits against
  official ground truth, victim-side and service-aware features with causality tests, matched
  LightGBM ensembles and calibration studies; negative results reported."
- **ML Engineer résumé:** "Built a causal, memory-bounded (≤ 2.2 GiB) victim-side feature
  pipeline over 50 M+ flows and a paired LightGBM harness that reproduces earlier models bit for
  bit. Found and fixed a string-buffer memory leak (3.3 → 1.3 GiB) and a silent join-path bug
  before training."
- **ML Research Engineer résumé:** "Audited attack labels against the dataset's official attacker
  table and showed that 19 of 20 'undetected attackers' were label artifacts. Pre-registered and
  tested victim-context, service-context and score-fusion detectors (660 fits): none improved
  detection under a shared false-alert budget, with mechanisms documented and an independent
  review that corrected the phase's own claims."
- **Do not claim:**
  - better detection;
  - cross-network generalisation;
  - FPR control;
  - that web exploits are or are not observable in flows.
