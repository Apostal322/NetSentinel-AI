# Phase 8t Stages 1–5: baseline, objective, oracle feasibility, score distributions

**Status:** retrospective oracle analysis, registered (PREREGISTRATION §§ 1–7, `05b8dc3`) before
any oracle outcome.
- Sources: `scripts/phase8t/oracle_feasibility.py`, `reports/phase8t/oracle_feasibility.json`
  (results `caaa602`).
- Saved scores only. The 54 frozen-score hashes were checked against Phase 8o.
- **Every oracle threshold is chosen with the evaluation labels it is scored on.** None is
  deployable.

## 1. Baseline reproduction

**The global hold-out thresholds reproduce Phase 8r/8s:**
- U (unlabelled hold-out): macro 0.374 here vs 0.372;
- T (benign hold-out): 0.661 vs 0.656;
- NF-ToN FPR 16.0 % in both.

**The small differences come from the quantile definition.** Phase 8t uses the inverted-CDF
quantile; Phase 8r/8s used the conformal rank.

**The frozen M2 construction is unchanged.** No model was fitted.

## 2. A structural limit of this benchmark

**On all 9 domains, no evaluation host has both documented-attack and benign windows** (the
Phase 8i benign set excludes every window of an attacking host). Hence:
- **an unconstrained per-host oracle (O1)** reaches recall 1 at 0 false alerts by memorising host
  identity;
- **within-host benign/attack separation cannot be measured on this benchmark;**
- **O4** (per-host thresholds for the 10–247 hosts per domain with ≥ 100 calibration windows)
  reaches macro 0.880. That is the size of the memorisation channel, not an opportunity.

## 3. Oracle results at the same 1 % budget (S_U = deployable memory; mean of 6 fits)

| oracle | free thresholds | macro recall | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | R₂₀ | missed |
|---|---|---|---|---|---|---|---|---|
| O0 global | 1 | **0.275** | 0.500 | 0.023 | 0.007 | 0.571 | 16.0 | 16.8 |
| O2g activity groups (guarded) | ≤ 4 | 0.362 | 0.507 | 0.026 | 0.344 | 0.571 | 19.2 | 10.3 |
| **O3g service groups (guarded)** | ≤ 6 | **0.491** | 0.503 | 0.202 | 0.364 | 0.896 | 24.0 | 11.0 |
| O3 service groups (unguarded) | 6 | 0.661 | 0.503 | 0.849 | 0.381 | 0.909 | 25.5 | 10.8 |
| O4 per-host (memorisation) | hosts + 1 | 0.880 | 0.691 | 1.000 | 0.830 | 1.000 | 36.0 | 3.8 |
| O0 with clean memory (S_P, diagnostic) | 1 | 0.391 | 0.803 | 0.168 | 0.088 | 0.505 | 27.2 | 7.8 |

All oracles hold FPR at or below 1 % (0.0–1.0 %).

**Gate G1: PASS.**
- O3g: macro gain +0.216; R₂₀ gain +8.0 (entity-cluster bootstrap 95 % [3.8, 12.2], 48
  entities).
- Temporal retention when thresholds are selected on the first half and applied to the second:

  | network | retention |
  |---|---|
  | NF-UNSW | 0.99 |
  | NF-BoT | 1.00 |
  | NF-ToN | **0.05** |
  | NF-CIC | no in-sample gain |

  The mean of 0.68 meets the 0.5 rule.

**G1 is weaker than its PASS suggests** (independent review):
- **Criterion 3 depends on how it is read:**

  | reading | value | result |
  |---|---|---|
  | mean of the ratios, NF-CIC dropped (as coded) | 0.68 | pass |
  | NF-CIC counted as 0 | 0.51 | pass, barely |
  | pooled ratio | 0.87 | pass |
  | ≥ 3 of 4 networks retaining ≥ 50 % | 2 of 4 | fail |

  - The registered exclusion covered only "no second-half positives". NF-CIC has positives but
    no gain.
- **Criterion 2's R₂₀ gain comes from NF-ToN (+5.3) and NF-UNSW (+2.7) only.** A domain-cluster
  bootstrap gives a 95 % interval of [0, 21.3], against the entity bootstrap's [3.8, 12.2].
  NF-ToN is the network that fails temporal retention.
- The PASS is reported as registered. It opened the deployable stage, which then failed (§ 3 of
  DETECTION_RESULTS).

**Model limit, at a true global 1 % FPR on S_U:**

| network | normalised partial AUC (FPR ≤ 1 %) | entities whose best window clears the global threshold |
|---|---|---|
| NF-CIC | 0.44 | 65 % |
| NF-UNSW | 0.012 | 96 % |
| NF-ToN | 0.003 | 43 % |
| NF-BoT | 0.58 | 100 % |

**Detection delay** (median over entities, O0 → O3g): NF-UNSW 38 → 1 min; NF-ToN 58 → 4 min;
NF-CIC and NF-BoT 0.

## 4. Where the oracle's gain comes from (Stage 5 audit)

**Benign tails differ strongly by service profile, and attacks concentrate in profiles whose benign
scores are low** (figure 2; base r6):
- **NF-UNSW:**
  - TCP multi-port windows: 10,166 benign with q99 ≈ 0.02, holding 1,271 attack windows;
  - the benign tail lives in single-port TCP (q99 ≈ 0.91).
  - O3g sets the multi-port threshold at 0.02 and the single-port threshold to +∞.
- **NF-ToN:** most attacks (4,420) are TCP 2–5-port windows (588 benign). O3g lowers that group's
  threshold to 0.73 (global 0.989) and closes four others (+∞).
- **NF-BoT:** two service groups hold all benign windows (310 each); O3g lowers one to 0.59.
- **NF-CIC:** the attacks share their profile (TCP single-port) with 82,000 benign windows. There
  is nothing to gain.

**Classification of the gain** (PREREGISTRATION § 4.5 categories):

| cause | assessment |
|---|---|
| (1) better separation within groups | **partly**, on NF-UNSW multi-port and NF-BoT |
| (2) reallocation of the false-alert budget | **mainly**: the oracle closes benign-tail groups (+∞) and spends the budget where it *knows* the attacks are |
| (3) memorisation of labels | the guard removes group-composition memorisation (O3 → O3g removes 0.17 macro, mostly NF-UNSW); per-host memorisation is excluded by design |
| (4) suppression of noisy hosts | through group closure, yes |
| (5) a few entities | NF-ToN's gain is not temporally stable (retention 0.05) |

**At the true 1 % FPR the scores barely separate attacks on NF-UNSW and NF-ToN.**
- In most service groups the documented attacks score *below* the benign median (figure 2). The
  scorer ranks those attacks as more normal than normal traffic.
- A clean memory (S_P) raises NF-CIC from 0.50 to 0.80, but NF-UNSW (0.17) and NF-ToN (0.09)
  stay low.
