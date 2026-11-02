# Phase 8m: independent review and corrections

**Review.** The reviewer was a separate agent given the code, the saved results and the docs, but
not the author's conclusions. It did a read-only audit of:
- `src/netsentinel/behavior/novelty.py`;
- `scripts/phase8m/*`, with the reused Phase 8b–8j protocol code;
- the tests;
- `reports/phase8m/*.json`;
- every Phase 8m doc.

The author re-checked each finding below against the data before acting on it.

## Verdict

**Unchanged.** H3, H1 and H2 are NOT SUPPORTED, there is no candidate, and B0 stays.

The reviewer confirmed:
- the H1 and H3 clauses, the selection rule (including amendment 2's B1-only case), the T0 rank
  and the entity definition, against the pre-registration;
- causal scoring before update, and excluding sources only before the freeze;
- identical windows and training subsamples across variants;
- the feature counts of every saved booster;
- the 0.0 `nov_frozen` / `new_dst_frac` check;
- the doc tables it spot-checked.

**H2 does not depend on the missing NF-UNSW value.** Even if that value were 100 %, the benign
acceptance mean would be 0.29, still below 0.50.

## Findings and what was done

| # | finding | checked | action |
|---|---|---|---|
| 1 | NF-CIC's recall loss is mostly **refit fragility**, not memory adaptation: every retrained variant (A_none included) scores ≈ 0 on 02-14, 02-16 and 02-21, while Q1 (B0's models, no retraining) keeps 0.99 | confirmed | MODEL_COMPARISON item 1, RESULTS and FINAL §2.4 rewritten; FINAL next experiment 2 now proposes a B0 robustness study |
| 2 | the "hosts first seen after calibration" **recall** slice is an artefact of P1x, which purges calibration attackers; 12 of 13 NF-ToN evaluation attackers were active in calibration | confirmed (NF-ToN 12/13, NF-BoT 8/8, NF-UNSW 4/4) | TEMPORAL marks the recall column invalid; the claims based on it were removed; FPR on benign hosts is unaffected |
| 3 | `novelty_audit.py:97` divided by all evaluation windows instead of benign ones | confirmed (NF-ToN 30 %, not 5 %; NF-BoT 0.8 %, not 0.1 %) | code fixed; NOVELTY_FAILURE table corrected, with an erratum; the saved JSON is kept as produced |
| 4 | the real attack-destination accounting is asymmetric: destinations shared with benign hosts always fall in the attack set; "victims" is an unverified label; the registered "recall in their windows" was not computed | confirmed (NF-ToN: 73 of 99 promoted had ≥ 2 attacker sources, 52 also a benign source; NF-UNSW 9/9 and 3; NF-BoT 8/8 and 1) | CONTAMINATION rewritten with these counts; "victims" removed; the missing measure stated |
| 5 | the H2 benign-promotion mean covers 3 networks, not 4; two of the three H2 clauses hold by construction | confirmed | stated in CONTAMINATION and RESULTS; the contamination docstring now says so |
| 6 | the "alert change" rescores a benign host's windows: the baseline alerts are false alerts, and it mixes three effects; "change the same way everywhere" was false | confirmed | CONTAMINATION reworded; the NF-BoT suppression is noted as an evasion concern |
| minor | the straddling window is excluded from "exactly"; B0r does not test the novelty join; bootstrap intervals collapse on single-attacker days; NF-BoT's H1 failure is a point estimate whose interval includes 0; causal wording in RESULTS ("drives"); the grid does not measure recall; B1u age wording; non-monotone age pattern; amendment 1 cited instead of 2 in two code comments; undocumented precision, delay and Q1 details | confirmed | all corrected in the docs and code comments |

## What was not changed

- No registered rule, threshold, feature, parameter or result.
- `reports/phase8m/novelty_audit.json`, `model_comparison.json` and `contamination.json` are the
  files the runs produced; nothing was re-run after the review.
- The code edits after the review are comment and label strings, plus the audit denominator. The
  denominator fix affects only a field that the erratum supersedes.
