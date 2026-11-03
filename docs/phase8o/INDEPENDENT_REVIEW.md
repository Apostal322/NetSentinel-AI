# Phase 8o: independent review and actions

**The review.** A separate agent did a read-only audit as five reviewers (ML methodology,
statistics, data integrity, operational usefulness, claims). It was given the code, the
pre-registration and the saved results, but not the author's conclusions. It recomputed the
registered decisions and several numbers from the per-member score files with its own code.

Every finding used below was re-checked against the saved data before any change. Where the
reviewer's number differed from the re-check, the re-checked value is used (noted).

## Confirmed

- **No code bug changes a verdict.**
  - H1, H2 and C1 were recomputed independently and follow the registered rules exactly.
  - The network recalls match.
- **The arms are matched as claimed:**
  - the subsample depends only on row index and label;
  - `replace_column` verifies the row order;
  - F1 changes only rows with win ≥ q;
  - F3 and the before-q checks are exact on all 14 domains.
- **F0 is the M2 construction** (R1 and R2 0.0 on all 9 targets).
- **Chronology:**
  - registration commit `1872b1f` at 16:13:35;
  - first score file at 16:25:37, last at 17:47:30;
  - the run log's provenance records `git_head` = `1872b1f`;
  - the only post-registration change to `analyze_d.py` is descriptive output (per-domain
    summaries, family names), and no decision code changed.
- **No leakage** in F1, C1 or C4. The memories use calibration flows only. C4's trailing window
  uses strictly earlier windows. Evaluation labels are used only for metrics.

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| 1 | high | **The F4 control is degenerate.** Squaring the feature leaves LightGBM's splits unchanged; scores are bit-identical. The noise floor was zero by construction, the NOT EVALUABLE branch could never fire, and the pre-registration's "different histogram bins" was wrong | yes (max \|Δ\| = 0 over 54 files) | recorded as a registered-design error (MODEL_COMPARISON § 2). Refit noise is reported from paired per-fit differences, labelled exploratory. No verdict depends on it |
| 2 | high | **C3 changes the threshold and the features at once.** The first draft named only the threshold. On NF-CIC 03-02 the collapse is entirely the features (memory absorbs the bots' destinations) | yes (re-run decomposition) | CALIBRATION_ANALYSIS § 3: decomposition table and both mechanisms |
| 3 | high (interpretation) | C4 is causal, but in effect the attacks trigger it (NF-UNSW: median trailing novelty 0.26 over all windows, 0.0 over non-attack windows) | consistent with the stored assessed shares | already stated; kept EXPLORATORY |
| 4 | medium | **H1 "no effect" is overstated.** The fits are correlated, and per-fit F1 − F0 differences have SD 0.011 | yes | "no *detectable* effect of a partial alignment"; per-fit differences added |
| 5 | medium | F5 also re-splits NF-CIC's network weight; it is identical to F0 on NF-CIC targets, so H1b covers 3 networks; G0.2's "harmful artifact" reading is unsupported | yes | MODEL_COMPARISON § 2; GAP_REGISTER G0.2 status |
| 6 | medium | **F2 over-read.** On NF-ToN, F2 *improves* AUC (0.86 → 0.94) and ranking recall; "must be trained on the semantics it is scored with" is untested; "which is why it works" recast the label confound as a strength | yes | MODEL_COMPARISON § 3 rewritten |
| 7 | medium | **H2 over-read.** The +0.16 contrast used the worst member; against the member average it is +0.066 (U₂₀ 18 → 5). K = 3 also fails on NF-ToN (−0.046). "False alerts within ±10 %" was false (NF-UNSW −16 %). "K = 5 retained" means no prefix K < 5 met the rule, not that 5 are necessary | yes | ENSEMBLE_EFFICIENCY corrected |
| 8 | medium | R/U counts compared over 30 single-member vs 6 ensemble fits are biased | yes | ENTITY_ROBUSTNESS: same-6-fit comparison (U₂₀ 13–24 vs 5) |
| 9 | medium | C1 rule weaknesses (no margin for "closer"; recall guardrail only where FPR ≤ 2α). NF-BoT's T0 is the 7th-highest of 781 hold-out scores, so C1 leaves it identical | yes; the score change is ≤ 0.38 on the ensemble mean (reviewer: 0.49, probably per member) | CALIBRATION_ANALYSIS § 3 |
| 10 | medium | **Workload does not transfer.** Attack prevalence in evaluation is 25.5 % (NF-UNSW) and 45.8 % (NF-BoT) | yes | CALIBRATION_ANALYSIS |
| 11 | low | the C1 NF-CIC gain is a post-hoc subgroup of a NOT SUPPORTED test | — | labelled EXPLORATORY |
| 12 | low | cost claims cover batch scoring of precomputed matrices only | — | ENSEMBLE_EFFICIENCY limits expanded |
| 13 | low | score files are untracked; mtimes are weak chronology evidence | — | `reports/phase8o/experiment_d_scores_sha256.json` (216 SHA-256) and the run log committed |
| 14 | low | source benign calibration rows exclude hosts that attack *later* (Phase 8i `load_domain`): pre-existing source-side curation with future labels | yes (code) | documented here; source side only, never the target; not changed (frozen protocol) |

## Not changed

- **No registered verdict** (H1, H1b, H2, C1) and no saved score.
- **The frozen M2 candidate.**
- **The pre-registration text** is left as committed. Its F4 rationale error is recorded here and
  in MODEL_COMPARISON.
