# Phase 8w: independent review and actions

**The review.** A separate agent did a read-only audit as six reviewers: domain adaptation,
statistics, machine learning, data leakage, operational detection, research integrity.
- It had the protocol, the code and the saved results. It was not given the author's
  conclusions; uncommitted drafts of the write-ups were in the working tree and it read them.
- It fitted no model and changed nothing in the repository.

Findings used below were re-checked by the author unless marked "reviewer's figure".

## Recomputed by the reviewer with its own code: all matched

| quantity | result |
|---|---|
| exact partial AUC (FPR ≤ 1 %) and recall at the retrospective budget: 9 domains × 3 arms × 2 seeds, all five scenarios | equal to `evaluation_screening.json` to 2.2e-14 (two independent implementations); recall, as-calibrated recall, FPR and false alerts per hour identical |
| network means and macro values | 2.2e-14 |
| entity counts (48 entities; missed and R₂₀) in 10 arm × seed × scenario cells | identical |
| null control: sigmoid of `R0` scores vs the saved frozen member | 0.0 in 18 files × 2 arrays |
| registered decisions, derived by hand from the summary | identical to `decisions` and to PREREGISTRATION § 6: no arm selected, stop at 24 fits |
| references: median and floored MAD from the window tables for `Z1`, `Z3`, `T` on four domains | difference 0; window counts equal the manifests |
| `A` = \|z\| of the same reference as `S`: all 24 boosters of four folds reloaded and re-scored | saved scores reproduced with difference 0; feeding signed z to an `A` booster differs by 2.5–9.4 |
| pairing | LightGBM parameter blocks byte-identical across arms per seed; 200 trees and 12 features in all 24 models; equal training-row counts within a fold |
| leakage | none into `Z0`/`Z1` or the training rows: `Z1` rows all precede the cut in nine domains; source networks never include the target |
| chronology and hashes | registration commit 11:06:38 UTC; first fit 11:10:37 UTC; evaluation on a clean tree, committed before any post-hoc. All 7 result hashes, 24 model hashes and 396 score-array hashes match |

**Not verified by the reviewer:** the three shortcut-classifier fits; the stress and simulated-
review re-scoring beyond two identities (share 0 = `Z3`, draw 0 = `Z2`, both exact); the training
rows against the frozen recipe directly (evidence is the bit-identical `R0`); upstream window
construction and the Phase 8q label audit; wall-clock order beyond local git and file times.

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| A1 | medium | **`T` breaks two written causality claims.** It covers the whole calibration period including the hold-out (NF-BoT: 781 of 959 windows), and attacking hosts are removed using evaluation labels too (reviewer's figures: 1,085 windows on NF-CIC 02-22, 912 on NF-ToN) | yes (`phase8i/common.py` removes `attackers ∪ cal_attackers`; 781 confirmed) | IDENTIFIABILITY § 1 and REFERENCE_ESTIMATION § 5 corrected; amendment W-2; `T` vs `Z3` is no longer read as a cleaning effect |
| A2 | medium | **The "deployable" `Z1` block is label-free for ranking only.** As-calibrated numbers and four of five guardrails use a label-benign hold-out threshold (labels drop 92 % of NF-BoT's hold-out, 76 % of NF-ToN's) | yes | captions corrected; a label-free threshold `cal_U` added (MODEL_COMPARISON § 6); amendment W-3 |
| B1 | medium | **Single benign hosts decide the primary metric on NF-BoT and NF-ToN**, so macro differences are largely single-host effects | yes (`posthoc_review.json`: NF-BoT `R0` 0.671 / 0.489 → 0.944 / 0.946 without one host) | MODEL_COMPARISON § 6a; stated in the final report |
| B2 | medium | **Seed noise was understated at registration:** macro SD is 0.0145 over the five saved members, not 0.009 | yes | amendment W-1; screening is read as fixing the sign per network only |
| B3 | medium | **Reference-estimation noise exceeds seed noise**, `Z1` beats "oracle" `Z3` on NF-UNSW, and the oracle is not unique (`T` vs `Z3`: 14.9 scale units on NF-ToN) | yes | CONTAMINATION_ROBUSTNESS § 5: `Z3` is not called an upper bound |
| B4 | medium | **The stress curve cannot separate low contamination from reference noise:** five clean draws miss 9, 28, 17, 9, 9 entities | yes (`posthoc_z2.json`) | the claim "5–10 % contamination already costs entities" was withdrawn from CONTAMINATION_ROBUSTNESS, README, RESULTS and the ledger before they were committed |
| C3 | medium | **The NF-UNSW gain is not independent evidence:** the arm was designed after a no-fit view of these labels; the gain vanishes at the operating point; 4 attacker hosts | yes | "confirming" → "consistent with" in every document; caveats listed in MODEL_COMPARISON § 4 |
| E1 | medium | **Guardrail blind spots:** the entity guardrail (as calibrated) shows 8 → 9 while 16–19 entities are lost at the strict budget; NF-CIC 02-21 FPR goes 1.2–1.7 % → 4.0 % inside a passing network mean | yes | reported in MODEL_COMPARISON §§ 6, 9; the outcome is unchanged (`A` fails four other guardrails); proposed guardrails recorded for future registrations |
| E2 | medium | **False alerts per hour count audited-benign windows only** (73 % of NF-ToN's evaluation windows are outside that population) | yes | "all alerts per hour" added (MODEL_COMPARISON § 6) |
| A3 | low | `Z0` is a median over domains, so it is NF-CIC-dominated (11 of 12 sources) | yes | stated in REFERENCE_ESTIMATION § 6 and MODEL_COMPARISON § 5 |
| B5 | low | floors and the ±10 clip dominate on contaminated networks; the missing-value rule is never exercised (no missing values exist) | yes (clipping: `posthoc_scale.json`) | stated in REFERENCE_ESTIMATION § 6 |
| B6 | low | tie blocks make the realised false alerts at the "1 % budget" much lower than the budget in several cells | yes | realised counts in MODEL_COMPARISON § 6a |
| D2 | low | `stage_eval` checked array sizes, not key and window alignment | yes; the reviewer verified alignment for all nine domains | check added to `stage_eval` (amendment W-5); the registered evaluation was not regenerated |
| E3 | low | as-calibrated thresholds rest on few windows (NF-UNSW: 443 label-benign hold-out windows; NF-BoT: 781 from 7 hosts) | yes (counts) | stated in the final report |
| F2 | low | post-hoc provenance is weaker than the registered part: `posthoc.py` is not in the registration commit, outputs carried no commit id and could be overwritten, the three diagnostic fits are not in the ledger, and the `scale` stage is not in § 7 | yes | amendment W-4; outputs are now write-once; `posthoc_review.json` records the commit |
| F3 | low | no external timestamp: the registration was not pushed before the fits | yes | recorded; pushing needs the user's authorisation |
| F4 | low | dry-run memory quoted as 1.7 GiB while the file records 1.07 GiB resident | yes | both figures given with their meaning |
| C2 | low | `gates.decide` emits no G0 verdict | yes | G0 is reported from the ledger and tests in the final report; code unchanged |

## Not changed

- The registered verdicts: no arm selected, no replication, development NO-GO.
- The registered evaluation file and its hash; every saved score, model and manifest.
- The frozen M2 and all historical artifacts.
