# Phase 8m final report: adaptive network novelty and contamination-resistant memory

**Question.** Can an adaptive representation of destination novelty improve intrusion detection
under temporal shift, while keeping a controlled false-alert budget and keeping malicious traffic
out of the baseline?

**Answer on development data: no, not with destination-level memories of this family.** The
registered comparison is a NO-GO, and the deployed detector (B0) stays.

## 1. Repository state

- **Commits:** local only, never pushed, on top of `f971e74` (Phase 8l, pushed). Stage 1 is at
  `40fab1f`; the code at `1e42b65`; the build fix at `2dc32f2`; the results commit follows.
- **Frozen Phase 8l and DEDALE artifacts are unchanged.** DEDALE was used only for the Stage 1
  POST-HOC audit, which reproduced the confirmatory FPR exactly; it was never rerun with `--final`.
- **New code:**
  - `src/netsentinel/behavior/novelty.py`, a research module the monitor does not use;
  - `scripts/phase8m/{novelty_audit, build_novelty, dev_scores, compare, contamination, figures}.py`;
  - tests in `tests/unit/test_phase8m_{novelty,compare}.py` (19).
- **Docs:** PREREGISTRATION (amendments 1–2), NOVELTY_FAILURE_ANALYSIS (with an erratum),
  ADAPTIVE_MEMORY_METHODS, MODEL_COMPARISON, CONTAMINATION_EXPERIMENTS, TEMPORAL_GENERALIZATION,
  RESULTS, this report and REVIEW (independent review and the corrections it led to).
  - RESEARCH_PLAN.md was not written: the pre-registration is the plan.
- **Runs,** all under `run_capped` (3.4 GiB), one process at a time, CPU only, authorized by the
  user on 2026-11-02:

  | run | time | peak |
  |---|---|---|
  | novelty build (11 NF-CIC days + 3 networks), run twice because of the build fix | about 4 min each | 2.6 GiB |
  | training (seeds 0–2 × 6 variants × 4 source sets) | 22 min | 2.0 GiB |
  | contamination | 3 min | 0.6 GiB |
  | comparison | about 1 min | 1.0 GiB |

  The Stage 1 audit ran for 100 min (1.0 GiB). No data was downloaded.

## 2. Scientific findings

1. **Why the novelty feature fails (Stage 1).**
   - **The mechanism.** The deployed `new_dst_frac` uses an expanding memory in calibration and a
     frozen one in evaluation. So every destination first seen after calibration stays "new" for
     ever.
   - **DEDALE (POST-HOC):**
     - novel windows rise from 8.6 % to 27.8 % over 10 days, while in calibration they fall to
       1.6 %;
     - 88 % of false alerts are novel (lift 4.1), and SHAP ranks the feature first (+1.80);
     - setting it to 0 removes 88 % of the false alerts **and all** detection.
   - **Development:** the same pattern holds on NF-ToN-IoT (99 % of false alerts novel; 59 % from
     benign hosts first seen after calibration, which make up 30 % of benign windows). It does not
     hold on NF-UNSW or NF-BoT-IoT.
   - **These are associations,** from correlation, model attribution and an out-of-support
     counterfactual, not causal effects.
   - **Phase 8l's "~200 false alerts/day":** the mean is 151 per working day (range 20–251), or
     0.51 per active host-hour.
2. **Registered development (B2 vs B0):** H3, H1 and H2 are all NOT SUPPORTED.
   - Recall falls on all 4 networks (−0.13 to −0.47).
   - False alerts fall on 3 networks (NF-ToN-IoT −89 %) and double on NF-BoT-IoT.
3. **Contamination.**
   - **What the guard does well:** it never accepts a single-host beacon (100 % of windows stay
     novel).
   - **Its limits:**
     - two hosts get any destination accepted after exactly 1 h;
     - post-freeze destinations contacted in attack windows are accepted: NF-UNSW 100 %, NF-ToN-IoT
       45 %; all promoted ones on NF-UNSW and NF-BoT, and 73 of 99 on NF-ToN, had ≥ 2 attacker
       sources;
     - only 5.5 % of benign post-freeze destinations are accepted (mean over 3 networks).
   - **Of the three H2 clauses, only the last is empirical;** the other two hold by construction.
   - **No grid point reaches 50 % benign acceptance.**
4. **Mechanism (EXPLORATORY; corrected after review).**
   - **On NF-UNSW and NF-ToN-IoT, the frozen novelty carries attack signal.**
     - Attack windows there are 100 % and 76 % novel under A0.
     - Swapping in the guarded novelty without retraining (Q1) costs 0.34 and 0.33 recall.
     - Under the guarded memory, attack-window novelty falls faster than benign novelty.
   - **On NF-CIC, the recall loss is mostly refit fragility, not the memory.**
     - Every retrained variant, including "no novelty", loses the single-attacker days 02-14 and
       02-16 (recall ≈ 0).
     - B0, and Q1 (B0's models with guarded novelty), detect them (0.96–0.996).

## 3. ML details

- **Unchanged protocol (Phase 8j P1x):**
  - leave-one-network-out B-raw LightGBM (Phase 8i settings: 200 trees, 15 leaves, lr 0.05,
    network-balanced weights, 50k-window cap);
  - seeds {0, 1, 2};
  - calibration-period attackers purged (P1x);
  - T0 = conformal rank at α = 1 % on the last 30 % of calibration slots.
- **Only the novelty columns differ.** The B0 refit reproduces the Phase 8j scores bit for bit
  (max difference 0.0); it validates determinism and the training subsample, not the novelty join.
  The novelty memory reproduces `new_dst_frac` exactly on every window of all domains except the one
  straddling the midpoint: a build bug in that window's handling was found and fixed before
  training.
- **Same training windows across variants:** the index-based subsample is identical.
- **Uncertainty:**
  - paired host-cluster bootstrap per domain (B = 2,000, seed 8, one-sided 95 % bounds);
  - sign counts across the 4 networks;
  - no cross-network p-values.
- **Error analysis:** MODEL_COMPARISON.md. Per-domain losses are largest on NF-CIC 02-14 and 02-16
  (−1.0 and −0.96 recall), where the retrained models stop using novelty the way B0 does.

## 4. Integrity labels

| result | label |
|---|---|
| DEDALE novelty audit, counterfactual, SHAP, alert-rate reconciliation | POST-HOC retrospective diagnostic (consumed data; nothing changes Phase 8l) |
| development novelty audit | EXPLORATORY (correlational) |
| H1, H2, H3, B1 vs B0, selection | REGISTERED DEVELOPMENT |
| B3, B1u, ablations, Q1, temporal slices, sensitivity grid | EXPLORATORY |
| applying a candidate to DEDALE | NOT EVALUABLE (no candidate) |
| independent confirmation | NOT EVALUABLE (no fresh eligible network) |

SHAP values are model attributions, not causal effects. The counterfactual input lies outside the
training support.

## 5. Deployment decision: NO-GO

- The deployed detector and its frozen destination memory stay unchanged.
- The guarded memory is not deployed, not even in shadow mode: on development data it does not
  separate benign adaptation from attacker acceptance.
- No blocking or other active response was implemented.
- DEDALE's detection problem (recall 7 %, about 151 false alerts per working day) remains open.

## 6. Next experiments (at most 3; none started)

1. **A role-aware memory, registered on development data.**
   - Treat calibration-known destinations as known; this union with A0 is what A3 lacked.
   - Promote post-freeze destinations only with evidence an attacker cannot produce cheaply: for
     example, sources that each have benign history from before the freeze, or contacts on several
     separate days.
   - Measure the separation at memory level first, attack vs benign promotion, before any model is
     trained.
2. **Make B0 itself robust before adding features.**
   - B0's NF-CIC recall depends on fits that any change of feature set undoes: single-attacker days
     go from 0.996 to 0.
   - A registered robustness study on development data is the prerequisite for attributing any
     future feature change to the feature itself: refits across seeds, feature subsets and
     source-network weights, plus per-day entity-level detection stability.
   - Separately, the NF-ToN-IoT false alerts concentrate on benign hosts first seen after
     calibration (FPR 29 % vs 8.7 %). A host-onboarding treatment would be the targeted test of that
     false-alert mechanism, to be registered together with its recall cost.
3. **Find a fresh eligible network before any new candidate is claimed.** DEDALE is consumed, and the
   development networks are exhausted for confirmation. Any candidate from experiments 1–2 needs a
   new, untouched network under the Phase 8l eligibility rules: a desk check first, and downloads
   only with authorization.

## Editorial addendum (2026-11-03, Phase 8n)

Section 1 says the commits are "local only, never pushed". That was true when the report was
written. The user then authorized a push, and `0cb0ad7..80c0b5c` has been on `origin/main` since
2026-11-03. No result, verdict or number in this report is changed by this note.
