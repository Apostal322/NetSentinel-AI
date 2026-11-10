# Phase 8w: robustness to an imperfect target reference

**Status.** Diagnostic re-scoring of the saved screening boosters (seeds 1060, 1061). No refit.
Gate G3 is NOT SUPPORTED by the registered rule, because no arm passed screening. This document
explains how the representation behaves when the reference is wrong.

Sources: `reports/phase8w/posthoc_stress.json`, `posthoc_z2.json`, `references.json`.

## 1. Observed contamination (the real `Z1` references)

| network | attack windows in the reference period | effect on the unsigned arm, `Z1` vs oracle `Z3` (partial AUC) |
|---|---|---|
| NF-CIC | 0.2–1.1 % | 0.269 vs 0.269 |
| NF-UNSW | 5.3 % | 0.532 vs 0.415 |
| NF-ToN | 13.6 % | 0.000 vs 0.000 |
| NF-BoT | 62 % | 0.088 vs 0.197 |

- On NF-CIC the unlabelled reference is as good as the oracle one.
- On NF-UNSW the mildly contaminated reference scores **higher** than the oracle one (see § 2).
- On NF-BoT the reference is the attack; ROC-AUC under `Z1` is 0.27.

## 2. Contamination stress

**Design.** Reference = the oracle-benign windows plus injected attack windows at a fixed share.
The injected windows are the domain's own evaluation attack windows: the worst case, where the
evaluated attack was already running during the history. Mean of two seeds; exact partial AUC at
FPR ≤ 1 %.

**Unsigned arm `A`:**

| injected share | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | macro | entities missed (as calibrated / at 1 % FPR) |
|---|---|---|---|---|---|---|
| 0 % | 0.269 | 0.415 | 0.000 | 0.197 | 0.220 | 9 / 30 |
| 5 % | 0.164 | 0.529 | 0.000 | 0.130 | 0.206 | 21.5 / 33 |
| 10 % | 0.167 | 0.523 | 0.000 | 0.025 | 0.179 | 19.5 / 30 |
| 20 % | 0.124 | 0.192 | 0.001 | 0.000 | 0.079 | 20 / 31 |
| 30 % | 0.073 | 0.005 | 0.001 | 0.000 | 0.020 | 27 / 42 |
| 45 % | 0.000 | 0.070 | 0.002 | 0.000 | 0.018 | 33 / 42 |
| 60 % | 0.000 | 0.033 | 0.001 | 0.000 | 0.009 | 34.5 / 42 |

`R0` for reference (no target reference, unaffected): 0.388 / 0.008 / 0.006 / 0.580, macro 0.245.

**Signed arm `S`:** macro 0.147 → 0.116 → 0.159 → 0.093 → 0.095 → 0.022 → 0.006 over the same
shares.

**Reading:**
- **Low contamination (5–10 %) cannot be separated from estimation noise.** Entities missed as
  calibrated rise from 9 to about 20 and NF-CIC loses 0.10, but five *clean* draws of 800
  reference windows (§ 3) miss 9, 28, 17, 9, 9 entities (seed 1060) and 9, 16, 11, 9, 9 (seed
  1061). The stress has one draw per share and no noise baseline (review finding B4).
- **Moderate contamination (20 %) halves the NF-UNSW gain; 30 % removes it** (0.005). This is the
  defensible part of the curve.
- **Severe contamination (≥ 45 %):** nothing is left on any network. This is the median's
  breakdown, and it is NF-BoT's observed situation.
- **Not monotone:** NF-UNSW is better at 5–10 % than at 0 %. A likely reason, not tested: a few
  attack windows widen the scale estimate (by 3–9 %), which moves NF-UNSW's deviations closer to
  the range the model learned on the source networks. That would be an accident of scale
  matching, not robustness.

**Reference shift under stress** (largest location change, in oracle scale units):

| network | 5 % | 10 % | 20 % | 30 % | 45 % |
|---|---|---|---|---|---|
| NF-CIC 02-14 | 0.1 | 0.2 | 0.5 | 0.5 | 2.8 |
| NF-UNSW | 0.1 | 0.2 | 0.5 | 0.8 | 4.0 |
| NF-ToN | **15.2** | 17.6 | 21.2 | 30.7 | 34.8 |
| NF-BoT | 2.0 | 3.3 | 4.8 | 5.0 | 11.0 |

On a unimodal benign population the median holds until about 30 %. On NF-ToN's bimodal one, 5 %
is enough to move a reference by 15 scale units.

## 3. Simulated review (`Z2`)

**Design.** 800 windows drawn uniformly from the history; a simulated reviewer labels them.
"Perfect" keeps exactly the label-benign ones. "Noisy" also passes 10 % of the attack windows.
Five draws each. This is a simulation of a best case, not evidence about real analysts.

| reviewer | `A` macro partial AUC over five draws (mean of two seeds) | NF-UNSW range | NF-BoT range |
|---|---|---|---|
| perfect | 0.152 – 0.259 | 0.268 – 0.544 | 0.097 – 0.351 |
| noisy (10 %) | 0.146 – 0.291 | 0.270 – 0.543 | 0.001 – 0.483 |

- **The result depends on which 800 windows were reviewed.** With a perfect reviewer, the draw
  alone moves NF-UNSW between 0.27 and 0.54 and the macro mean between 0.15 and 0.26, on both
  sides of `R0` (0.245).
- NF-BoT keeps only 308–324 benign windows of 800; a 10 % reviewer error adds 41–51 attack
  windows and its result ranges from 0.001 to 0.48.
- A reference estimated from a few hundred windows is too noisy for this representation.

## 4. Scenarios from the brief that were not measured on data

| scenario | status |
|---|---|
| persistent attacker host | measured with labels, no model: own-host references erase the volume signal on NF-UNSW and NF-ToN (IDENTIFIABILITY § 5) |
| multi-source attack | covered only as the injected-share stress above |
| new legitimate high-volume service; quiet host becoming active; active host becoming quiet | not measured. An unsigned deviation flags all three by construction; the size of that false-alert cost is unknown |
| long-term drift | not measured: each network has one calibration and one evaluation period |

## 5. Conclusion

- The unsigned relative representation is **not robust to its reference**: 20–30 %
  contamination removes the NF-UNSW gain, and the choice of 800 reviewed windows changes the
  answer by more than the training seed does. Below 20 % the stress cannot distinguish
  contamination from that estimation noise.
- **The oracle reference is not an upper bound, and it is not unique.** `Z1` beats `Z3` on
  NF-UNSW, and the two oracle variants (`Z3`, `T`) differ by 14.9 scale units on NF-ToN. The
  registered "share of the oracle gain retained" would have been ill-defined.
- It also fails with an oracle reference on NF-ToN and NF-BoT (MODEL_COMPARISON §§ 5, 8), so a
  cleaner reference is not sufficient.
- A benign reference is not identifiable from unlabelled history on two of the four networks
  (IDENTIFIABILITY § 3).
