# Phase 8n Experiment C: can training changes alone make B0 robust?

**Sources:**
- `reports/phase8n/candidate_comparison.json`, from `scripts/phase8n/compare_candidates.py`;
- the fits from `scripts/phase8n/candidates.py`: 216 model × domain runs, 40 min, peak 1.86 GiB,
  authorized on 2026-11-03;
- the protocol in PREREGISTRATION.md, amendment 1, written after Experiment A and before any
  candidate was trained.

**Label:** REGISTERED DEVELOPMENT, on the four consumed development networks. A development GO
makes a model a candidate for independent testing. It is not a deployment decision.

**Pipeline check.** M0 recomputes Experiment A's P_ref (base) and `A5_host_bootstrap` (stress)
scores exactly: max |Δ| = 0.0 over 54 domain-fits.

## Models

| model | what it is | fits per replicate |
|---|---|---|
| M0 | B0: Phase 8i LightGBM, 12 features | 1 |
| M1 | mean of 5 models, each on its own host bootstrap (bagging) | 5 |
| **M2** | mean of 5 B0-configured models, each with its own subsample seed and LightGBM seed | 5 |
| M3 | 1 model, `min_child_samples` 200, `reg_lambda` 5 | 1 |

**Every model gets 6 fits:**
- 3 **base** fits on the Phase 8j training data;
- 3 **stress** fits after resampling the source hosts with replacement (the perturbation that
  flipped 02-16 in Experiment A).

## Registered rule (G1–G3) and outcome

| | M1 | **M2** | M3 |
|---|---|---|---|
| G1 recall: every network ≥ M0 − 0.05 | ✗ (NF-UNSW 0.616 vs 0.833) | ✓ | ✓ |
| G1 entity recall ≥ M0 − 0.02 (M0 0.713) | ✗ 0.680 | ✓ 0.731 | ✓ 0.727 |
| G2 false alerts ≤ 1.25 × M0, every network | ✗ (NF-BoT 86 vs 54) | ✓ (max ratio 1.16, NF-ToN) | ✓ |
| G3 U ≤ U(M0) − 3 and R ≥ R(M0) (M0: R 46, U 9) | ✗ R 37, U 18 | ✓ **R 54, U 1** | ✓ R 52, U 3 |
| **pass** | no | **yes** | yes |

**Selection by the registered rule (largest R): M2, a development GO.** M3 also passes.

**The evidence behind this GO is weak.** The independent review (REVIEW.md) showed, and I
verified:
1. **Under the registered "≥ 1 alerted window" definition, every unstable entity of M0 (9), M3 (3)
   and M2 (1) is lost in the same fit, stress r = 2.**
   - M0's stress fits are Experiment A's `A5_host_bootstrap`, which had been seen.
   - In the base regime all three models have R/U/N = 55/0/20.
2. **Most of the R gain (46 → 54) sits on entities that are barely detected.**
   - 4 entities on 02-20 and 2 on 02-22 each have 1 alerted window in every fit, so their
     "detection" is threshold noise near α.
   - The rest: 1 on 02-16 and 1 on NF-ToN.
3. **G1–G3 have no window-level collapse criterion.** M3 base r = 0 has recall 0.016 on 02-14 and
   still counts as having detected that entity.

**The exploratory sensitivity points the same way, with the misses now spread over all fits.**
This is post-hoc (`reports/phase8n/entity_sensitivity.json`). R/U across the 6 fits, and U from
the base fits alone:

| entity detected when | M0 | M2 | M3 |
|---|---|---|---|
| ≥ 1 window | 46 / 9 (base U 0) | 54 / 1 (0) | 52 / 3 (0) |
| ≥ 20 % of its windows | 23 / 22 (base U 9) | 40 / 5 (2) | 32 / 13 (4) |
| ≥ 50 % of its windows | 21 / 19 (8) | 36 / 6 (2) | 26 / 15 (6) |

Amendment 2 registers a replication on fresh randomness before anything is concluded from this.

## Network means over the 6 fits

Each cell: recall / false alerts / FPR.

| network | M0 | M2 | M3 | M1 |
|---|---|---|---|---|
| NF-CIC (6 days) | 0.545 / 1,350 / 1.29 % | **0.684** / 1,396 / 1.34 % | 0.599 / 1,415 / 1.35 % | 0.588 / 1,294 / 1.25 % |
| NF-UNSW | 0.833 / 524 / 4.39 % | **0.901** / 471 / 3.95 % | 0.875 / 525 / 4.40 % | 0.616 / 429 / 3.59 % |
| NF-ToN-IoT | 0.568 / 1,022 / 13.7 % | **0.634** / 1,190 / **16.0 %** | 0.521 / 907 / 12.2 % | 0.582 / 1,104 / 14.8 % |
| NF-BoT-IoT | 0.798 / 54 / 8.7 % | **0.883** / 57 / 9.1 % | 0.875 / 44 / 7.0 % | 0.818 / 86 / 13.8 % |

**Base regime only** (directly comparable with Phase 8j B0), M0 → M2:

| network | M0 | M2 | change |
|---|---|---|---|
| NF-CIC | 0.581 | 0.689 | +0.11 |
| NF-UNSW | 0.971 | 0.975 | ≈ 0 |
| NF-ToN-IoT | 0.609 | 0.587 | **−0.02** |
| NF-BoT-IoT | 0.883 | 0.882 | ≈ 0 |

**M2's gain therefore comes mostly from not collapsing when the training data change** (stress):
- NF-UNSW 0.694 → 0.827;
- NF-BoT 0.712 → 0.885;
- NF-ToN 0.527 → 0.680;
- NF-CIC 0.508 → 0.679.

Under the original training data it improves NF-CIC only.

## Ranking vs calibration vs operation

On NF-CIC (network means):

| model | AUC | ranking recall at the benign 99th percentile | T0 | operational recall |
|---|---|---|---|---|
| M0 | 0.773 | 0.537 | 0.857 | 0.545 |
| M2 | 0.781 | 0.682 | 0.772 | 0.684 |

- **The overall AUC barely moves.** The ranking at the top of the score distribution, where the
  1 % threshold sits, improves by about as much as the operational recall.
- **So on NF-CIC the gain is in ranking near the threshold, not a looser threshold.** M2's T0 is
  lower because averaging compresses the scores.
- **This argument holds only where the FPR is near α,** as on NF-CIC. There, T0 is close to the
  benign 99th percentile by construction.
- **On NF-ToN-IoT the opposite holds.** M2's ranking recall at the benign 99th percentile *falls*
  (0.055 → 0.045) while its operational recall rises together with its FPR (13.7 % → 16.0 %). That
  gain is threshold- and workload-driven.
- **The false-alert rate is essentially unchanged** (1.29 % → 1.34 %), as conformal calibration
  should keep it.

**The cost of the gain on NF-ToN-IoT:**
- FPR rises from 13.7 % to 16.0 %, or 14 → 16.5 false alerts per hour. This is inside the
  registered 1.25× budget, but in a direction an operator would notice.
- T0 values cannot be compared across models, because averaging compresses the scores.
- On each model's own hold-out, the exceedance is α by construction. So the rise reflects how M2
  ranks NF-ToN's *evaluation* benign windows relative to its calibration hold-out.
- NF-ToN-IoT's evaluation FPR was already far above α for every model (Phase 8j/8m: stale
  novelty). That calibration problem is not solved here.

## Detection delay

Median delay over detected entities (seconds), M0 → M2:

| network | M0 | M2 |
|---|---|---|
| NF-CIC | 49 | 13 |
| NF-UNSW | 15 | 5 |
| NF-ToN-IoT | 88 | 30 |
| NF-BoT-IoT | 20 | 0 |

These rest on few entities per network.

## Uncertainty and selection bias

**Units are few and correlated.**
- The 75 entities are not independent: NF-CIC contributes 52, from 6 days of one network, and
  entities on one day share a campaign.
- The improvement R 46 → 54 is NF-CIC +7 (mostly the barely detected 02-20 and 02-22 entities)
  and NF-ToN +1.
- No interval is claimed.
- **Across the 4 networks, M2's 6-fit mean recall is higher on 4 of 4.** That count includes the
  stress fits.
- **In the base regime alone it is higher on 2 of 4:** NF-CIC +0.108 and NF-UNSW +0.004, against
  NF-ToN −0.022 and NF-BoT −0.001.
- **The base NF-CIC gain is about the size of a no-op refit.** Reversing the column order (A2)
  moved B0's NF-CIC recall by +0.093.
- With 4 units, the smallest exact one-sided sign-test p is 1/16, and that ignores the
  selection.

**Selection.** Three candidates were compared on consumed data, and two passed. Choosing the best
of them biases its estimates upward. M2's numbers are optimistic estimates.

**Compute.** M2 costs 5× B0 in training and in inference. Median measured fit time per source
set: M2 37 s, M0 7.9 s, M3 6.8 s. Inference cost was not measured separately.
