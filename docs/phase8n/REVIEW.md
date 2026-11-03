# Phase 8n: independent review and actions

**The review.** A separate agent, given the code, the saved results and the docs but not the
author's conclusions, did a read-only audit of:
- `scripts/phase8n/*` and the reused Phase 8b–8j protocol code;
- the tests;
- `reports/phase8n/*.json`;
- the Phase 8n docs.

It covered ML training, data integrity, statistics, research claims and engineering. Each finding
below was re-checked against the saved data before any action.

## What the review confirmed

- **No leakage.**
  - T0 always comes from the target's P1x calibration hold-out.
  - Stress bootstraps and member seeds act only on source data, and the target network is never a
    source.
  - Evaluation labels are used only for metrics, the oracle ranking quantity, the entity
    definition, and the disclosed development selection on consumed data.
- **Reproduction:** 27/27 P_ref and 54/54 M0 fits match exactly (on this machine).
- **Decision logic:** G1–G3, the selection and R/U/N are implemented as registered.
- **Numbers:** the numbers spot-checked in the docs match the JSON.

## Findings and actions

| # | finding | verified | action |
|---|---|---|---|
| A1 | **G3 rests on one already-seen fit.** Under the "≥ 1 window" definition, every unstable entity of M0, M2 and M3 is lost in stress r = 2 (Experiment A's `A5_host_bootstrap`); M0's stress comparator fits are Experiment A fits, contrary to the pre-registration; G3's margin was set after U(M0) = 9 was seen | yes (`entity_sensitivity.json`: all misses at stress r2) | stated in MODEL_COMPARISON; **amendment 2 registers a replication on fresh randomness** (r = 3–5) |
| A2 | most of the R gain is on entities with 1 alerted window per fit (02-20, 02-22): threshold noise near α | yes | stated; exploratory sensitivity at ≥ 20 % and ≥ 50 % of windows (still favours M2: U 5 vs 22); RP3 in amendment 2 |
| A3 | the rule has no window-level collapse criterion (M3 r0 02-14 recall 0.016 counted as detected) | yes | RP4 in amendment 2; FAILURE_ANALYSIS corrected |
| B | the A5 arms are seed-confounded for r = 1 and 2; a clean one-factor contrast exists only at r = 0 | yes (`fragility.py` seeds) | TRAINING_STABILITY corrected; HA1 reported as one entity-day |
| B | "4 of 4 networks" holds only with the stress fits; base regime 2 of 4; the base NF-CIC gain (+0.108) is the size of a no-op refit (+0.093) | yes | MODEL_COMPARISON corrected |
| B | "ranking, not calibration" holds only where FPR ≈ α (NF-CIC); on NF-ToN, M2's gain is threshold- and workload-driven | yes | MODEL_COMPARISON and TRAINING_STABILITY corrected |
| B | wrong statements: M3's lower R attributed to its 02-14/02-16 collapses; the Spearman range; `udp_share` ≤ 0.17; HA3 under-reported; GAP_REGISTER stale; the 02-22 coverage interpretation stated as fact | yes | all corrected; the coverage claim is now marked as an interpretation and its flow count sourced |
| C | M1 in stress applies a double bootstrap (members see about 40 % of hosts), so its NO-GO says little about bagging in general | yes (design) | stated in the final report |
| C | M2 stress members draw the outer bootstrap over their own subsample's hosts, so they do not share exactly M0's stressed data | yes (design) | stated; the same construction holds in the replication |
| D | non-atomic npz writes; resume by file existence only; no git SHA or package versions recorded; peak RSS of the last invocation only; no tests for metrics, the rule or R/U/N | yes | npz writes now atomic in `fragility.py` and `candidates.py`; `candidates.py` records git HEAD, code hash, package versions and parameters per invocation; new tests in `tests/unit/test_phase8n_decisions.py`; the replication uses new output names, so no stale reuse; resume by hash not added (documented) |

## What was not changed

- **No registered verdict.** HA1, HA2 and amendment 1's selection of M2 stand as registered.
- **No saved result files.** The corrections are in the text, plus the new exploratory file
  `entity_sensitivity.json`.
