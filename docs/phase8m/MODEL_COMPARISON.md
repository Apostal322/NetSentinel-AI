# Phase 8m: model comparison (development)

**Source:** `reports/phase8m/model_comparison.json`.
- Produced by `scripts/phase8m/compare.py` from the saved scores of `scripts/phase8m/dev_scores.py`
  (seeds 0, 1, 2).
- Protocol: PREREGISTRATION.md with amendments 1–2, all written before any build or training.
- **Labels:**
  - B2 vs B0: REGISTERED DEVELOPMENT (primary);
  - B1 vs B0: REGISTERED DEVELOPMENT (secondary);
  - everything else: EXPLORATORY.
  - None of it is independent confirmation: the four networks were explored in Phases 8b–8k.

**Pipeline check.** The refitted B0 (B0r) reproduces the Phase 8j B0 scores exactly: the largest
difference over all 9 domains and 3 seeds is 0.0. The novelty build reproduces `new_dst_frac` exactly
on every window except the one straddling the midpoint (ADAPTIVE_MEMORY_METHODS.md).

What these two checks cover:
- **B0r** uses the original `new_dst_frac` column, so it confirms that training and scoring are
  deterministic and that the training subsample is identical. It does not test the novelty join.
- **The build check** covers the join: it compares `nov_frozen` with `new_dst_frac` on every window.

## Network means

Each value is the mean over a network's domains and the 3 seeds, at each model's own T0 (α = 1 %).
Within each cell, FPR / false alerts / attack-window recall:

| model | NF-CIC (6 days) | NF-UNSW-NB15 | NF-ToN-IoT | NF-BoT-IoT |
|---|---|---|---|---|
| **B0** (deployed features) | 1.29 % / 1,356 / **0.581** | 3.66 % / 437 / **0.971** | 14.84 % / 1,105 / **0.609** | 11.88 % / 74 / **0.883** |
| **B2** (primary candidate) | 1.02 % / 1,070 / 0.113 | 3.02 % / 361 / 0.841 | 1.62 % / 121 / 0.445 | 26.34 % / 163 / 0.434 |
| B1 (secondary) | 1.09 % / 1,157 / 0.002 | 2.87 % / 342 / 0.218 | 0.02 % / 1 / 0.158 | 30.48 % / 189 / 0.714 |
| B3 (`log_new_guarded` only) | 0.33 % / 347 / 0.000 | 0.00 % / 0 / 0.112 | 0.42 % / 31 / 0.001 | 0.00 % / 0 / 0.025 |
| B1u (unconditional, unsafe) | 1.05 % / 1,106 / 0.006 | 3.30 % / 393 / 0.488 | 0.00 % / 0 / 0.139 | 29.46 % / 183 / 0.731 |
| A_none (no novelty) | 1.07 % / 1,143 / 0.004 | 4.55 % / 543 / 0.732 | 0.00 % / 0 / 0.170 | 5.59 % / 35 / 0.428 |
| A_novol (B2 without volume) | 1.14 % / 1,216 / 0.000 | 0.48 % / 58 / 0.746 | 0.09 % / 7 / 0.007 | 30.00 % / 186 / 0.532 |
| Q1 (B0 models, `new_dst_frac` := `nov_guarded`) | 1.32 % / 1,387 / 0.537 | 5.46 % / 651 / 0.635 | 6.45 % / 480 / 0.280 | 12.15 % / 75 / 0.848 |

**Entity recall** (entities = sources with ≥ 5 attack windows):

| model | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|
| B0 | 0.85 | 1.00 | 1.00 | 1.00 |
| B2 | 0.29 | 1.00 | 1.00 | 0.88 |

**Median detection delay**, B0 → B2:

| network | B0 | B2 |
|---|---|---|
| NF-CIC | 77 s | 5,048 s |
| NF-ToN-IoT | 70 s | 330 s |
| NF-UNSW-NB15 | 0 s | 105 s |

## Registered decisions

**H3 (primary, B2 vs B0): NOT SUPPORTED.** All three clauses fail.

| network | recall change | false-alert ratio | bootstrap: recall change (one-sided 95 % bounds) |
|---|---|---|---|
| NF-CIC | −0.468 | 0.79 | every day negative, upper bound below 0 on all 6 days; on 02-14 and 02-16 there is one attacker, so the interval collapses to the point estimate |
| NF-UNSW-NB15 | −0.130 | 0.83 | [−0.142, −0.115] |
| NF-ToN-IoT | −0.163 | 0.11 | [−0.476, +0.020] |
| NF-BoT-IoT | −0.450 | **2.22** | [−0.470, −0.411] |

- Recall gains: 0 of 4 networks (sign count 0/4 positive).
- The workload clause fails on NF-BoT-IoT.

**H1 (B2 lowers FPR from benign destination churn): NOT SUPPORTED.**
- **High-FPR set:** NF-UNSW, NF-ToN-IoT and NF-BoT-IoT, the networks where B0 > 2α (amendment 1).
- **FPR change** (one-sided 95 % host-bootstrap bounds):

  | network | B0 → B2 | change | bounds |
  |---|---|---|---|
  | NF-ToN-IoT | 14.8 % → 1.6 % | −89 % | [−30.1, −3.3] pp |
  | NF-UNSW-NB15 | 3.66 % → 3.02 % | −17 % | [−1.01, −0.44] pp |
  | NF-BoT-IoT | 11.9 % → 26.3 % | **up** | [−1.7, +26.4] pp, on only 620 benign windows |

- The rule needs a lower FPR on every high-FPR network, and NF-BoT-IoT is not lower.
- **NF-BoT-IoT's failure is a point estimate.** As registered, H1 is decided on point estimates.
  The bootstrap interval of the rise includes 0, and it rests on 620 benign windows from 5 + 615
  hosts.
- **Amendment 1's prediction was wrong for NF-UNSW:** B2's FPR did fall there. It cannot be a
  novelty correction, because benign A0 novelty on NF-UNSW is 0.0 %. It comes with a recall loss
  of −0.13.
- **Secondary measure:** in B0's false alerts, the share of windows novel under A0 but not under
  A3:

  | network | share |
  |---|---|
  | NF-ToN-IoT | 65 % |
  | NF-CIC | 6 % |
  | NF-BoT-IoT | 2 % |
  | NF-UNSW | 1 % |

**B1 vs B0 (secondary): NOT SUPPORTED.**
- Recall falls on all 4 networks: −0.58, −0.75, −0.45 and −0.17.

**Selection: no candidate.** By the registered rule this is a NO-GO, and B0 stays.

## What the exploratory variants show

**1. On NF-CIC, most of the recall loss comes from refitting, not from the memory.** This was
corrected after review.

Recall per NF-CIC day:

| day | B0 | Q1 (B0 models, guarded novelty, not retrained) | every retrained variant |
|---|---|---|---|
| 02-14 | 0.996 | 0.996 | 0.000 (B2, B1, B1u, A_none, A_novol) |
| 02-16 | 0.963 | 0.988 | 0.000 |
| 02-21 | 0.991 | 0.991 | 0.00–0.67 (B2: 0.67) |

- **On 02-14 and 02-16 there is a single attack entity.** 02-21 has 10.
- **B0's detections there come from one particular learned model.** Any change of the feature set
  loses them, including removing novelty altogether.
- **So the A_none collapse on NF-CIC (0.58 → 0.004) is refit fragility, not evidence that novelty is
  the attack signal.** On 02-16 the attack windows are not novel under A0 at all.
- **On NF-UNSW and NF-ToN-IoT, the representation itself costs recall.** Q1, without retraining,
  loses 0.34 and 0.33.
- **The attack windows there are mostly novel under A0** (0.999 and 0.759). So on these two
  networks the frozen novelty does carry attack signal, as it does on DEDALE (counterfactual,
  NOVELTY_FAILURE_ANALYSIS.md).
- **A robustness problem for B0 itself.** Its NF-CIC recall rests on fits that a small change of
  features can undo.

**2. The guarded memory removes the attack signal faster than the false-alert signal.** Share of
windows that are novel, A0 → A3:

| network | attack windows | benign windows |
|---|---|---|
| NF-UNSW | 0.999 → 0.114 | 0.000 → 0.018 |
| NF-ToN-IoT | 0.759 → 0.115 | 0.279 → 0.220 |
| NF-BoT-IoT | 0.556 → 0.179 | 0.023 → 0.065 |
| NF-CIC 2018-02-22 | 0.992 → 0.213 | 0.038 → 0.045 |
| NF-CIC 2018-03-02 | 1.000 → 0.353 | 0.038 → 0.054 |

- Two reasons explain this (CONTAMINATION_EXPERIMENTS.md).
- **First, real attacks are multi-source.** Several attacker hosts contact the same destinations,
  and some of those destinations are also contacted by benign hosts. The guarded rule accepts them
  within about an hour.
- **Second, a registered-design consequence.** Under A3 a destination known in calibration still
  needs promotion. Destinations contacted by only one calibration host stay novel, so A3 does not
  lower benign novelty except on NF-ToN-IoT.

**3. Recalibrating is not the issue.**
- Q1 swaps the representation into B0's models without retraining. Recall falls on all 4
  networks: −0.04, −0.34, −0.33 and −0.03.
- False alerts fall only on NF-ToN-IoT (ratio 0.43) and rise on NF-UNSW (1.49).

**4. The label-free rule B3 detects almost nothing.** Its recall is ≤ 0.11 on every network.

**5. Without volume features, B2 is worse on recall everywhere.** A_novol lowers NF-UNSW false alerts
sharply (58), with recall 0.75.

These patterns are exploratory and were not used to choose anything.

## Error analysis

**Per-domain recall change, B2 − B0** (host-cluster bootstrap):

| domain | change |
|---|---|
| NF-CIC 2018-02-14 | −0.996 |
| NF-CIC 2018-02-16 | −0.963 |
| NF-CIC 2018-02-21 | −0.325 |
| NF-CIC 2018-03-02 | −0.345 |
| NF-CIC 2018-02-22 | −0.095 |
| NF-CIC 2018-02-20 | −0.085 |

- On 02-14 and 02-16, B0 caught almost every attack window and B2 almost none.
- On 02-14 the attack windows remain novel under A3 (1.00), yet B2 misses them. The model trained
  on guarded features does not weigh guarded novelty the way B0 weighs frozen novelty: in the
  training (source) windows, guarded and frozen novelty differ.
- On 02-16, B0's detections came from attack windows that are *not* novel under A0 (0.00) and only
  3.7 % novel under A3. Since novelty plays no part in those windows, the 0.96 loss there comes
  from the retrained model as a whole, not from the memory (item 1 above).
- **Metric details:**
  - precision leaves out unverified (noisy) windows;
  - median delays are over detected entities only, so B2's 5,048 s on NF-CIC rests on few
    detections;
  - Q1 uses B0r's T0, which is identical to B0's.

**NF-BoT-IoT: the false-alert increase sits in a tiny benign set** (620 windows, 5 hosts new after
calibration). B2's FPR there is 26 % on the 615 windows of hosts seen in calibration.
