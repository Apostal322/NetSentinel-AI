# Phase 8u: independent review and actions

**The review.** A separate agent did a read-only audit as six reviewers: ML methodology, leakage,
low-FPR statistics, representation, operational, reproducibility.
- It had the protocol, code and saved results, but not the author's conclusions.
- It fitted no model.
- It recomputed metrics with its own code on all 9 domains, for seeds 1060–1062 and every
  variant.

Every finding used below was re-checked by the author.

## Recomputed and matched

| quantity | result |
|---|---|
| `recall_1pct` for all runs | exact match |
| registered `pauc_1pct` (re-running the registered function) | exact match |
| network-mean-then-macro aggregation | match |
| R0: A0 refit = saved member 0 (max \|Δp\| = 0.0) | confirmed |
| variants matched to A0 except the intended change (rows, subsample seed, `random_state`, parameters; saved boosters: 200 trees, 12 or 16 features) | confirmed |
| custom objective: gradient signs, 2·cnt Hessian, β re-selection, within-domain pairs, λ = Σw | correct |
| cross-fitted mining: never scores with a model trained on the window's network or the target | confirmed; mined indices frozen before candidate fits |
| `decide()` matches PREREGISTRATION § 7 | exact |
| chronology: registration `a8ad978` → fits 1–22 at `a8ad978` → screening committed `bac19ad` → fits 23–30 at `bac19ad` | confirmed |
| budget | 30 / 30 fits; 591 s; peak RSS ≤ 1.9 GiB |

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| C7 | medium (bug) | **`partial_auc` credits positives lying strictly between two benign scores** (toy case 0.5 instead of 0; it can exceed recall @ 1 %) | yes | **amendment U-1:** `partial_auc_exact` with a test against sklearn. All gates recomputed; **verdicts unchanged.** Phase 8t addendum added |
| C9 | **high** | **The replicated gain cannot be told apart from seed noise** (Δ macro pAUC by seed: 0.098 / 0.018 / 0.051; paired t(2) ≈ 2.4, p ≈ 0.14). It is concentrated in NF-BoT, where the 1 % budget is about 6 benign windows from 8 hosts (two hold 567 of 620) and pAUC is in effect the share of attacks above the single top benign window. A1, A2 and C1 move NF-BoT just as much | yes | stated in every verdict. H2 is reported as **"SUPPORTED by the registered rule; not separable from seed noise; concentrated in NF-BoT"** |
| E11 | **high** | **As calibrated (CAL_T), B lowers recall in every seed** (macro 0.598 / 0.471 / 0.520 vs 0.611 / 0.647 / 0.610) while lowering FPR. The registered guardrails cap FPR, false alerts per hour and missed entities, so fewer alerts always passes them | yes | reported; a recall guardrail is recommended for any follow-up |
| A3 | medium | **A1 is a valid control for A2 but a weak hurdle for B** (A1 is itself below baseline). No tail-specificity control (pairwise term with β = 1) was run | yes | disclosed; recommended for a follow-up |
| C9b | — | **NF-UNSW and NF-ToN sit near the random level (≈ 0.005) for every model,** so the no-harm gates cannot bind there | yes | NF-UNSW/ToN reported as showing **no low-FPR signal under any tested variant** (one exception: A2's single-seed NF-ToN 0.058) |
| D10 | medium | C1 is per-domain location normalisation in 6 coarse bins; "service-aware" is not separated from "domain-standardised" (C1ns never ran) | yes | H3 stays NOT EVALUABLE; stated |
| A2 | low | B has no boost-from-average start; per row the pairwise Hessian dominates log-loss in the tail | yes | disclosed |
| B6 | low | C1's target medians include the hold-out windows that also set CAL_T | yes | disclosed; negligible |
| F12 | low | the ledger has no timestamps or dirty-tree flag; ordering rests on recorded git SHAs | yes | disclosed |

## Not changed

- The registered verdicts.
- The registered evaluation files.
- The frozen M2 and all historical artifacts.
