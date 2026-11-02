# Phase 8l statistical power of a network-level confirmation

**Code:** `scripts/phase8l/power_analysis.py`. It uses no data; the output is
`reports/phase8l/power_analysis.json` (2,000 replicates per configuration, ~3 min CPU).

## 1. Model

A confirmation study has N independent network units. For each unit:
- **True status:**
  - adequate with probability `prev`, true FPR ~ U(0.5%, 1.8%) (development NF-CIC: 1.0–1.6%);
  - otherwise unsafe, true FPR ~ U(2.5%, 15%) (development: 3.7–14.8%).
- **The rule** accepts adequate units with probability *sens* and unsafe units with probability
  *FAR*. Three rules are modelled:
  - good: 0.9 / 0.1;
  - moderate: 0.8 / 0.2;
  - weak: 0.7 / 0.3.
- **Dependence:** units are either independent, or in families of 4 whose rule behaviour shares
  a random shift (logit SD 1). The latter mimics networks from one generator, or weeks of one
  range.
- **The adequacy label is observed with noise:** realised FPR ~ Binomial(n_eff, true FPR) over
  the unit's effective independent benign windows. Two labelling schemes:
  - **point** (Phase 8k): adequate if ≤ 2%;
  - **three-state** (proposed): adequate if the exact 95% upper bound is ≤ 2%, unsafe if the
    lower bound is > 2%, otherwise indeterminate and excluded.
- **Criteria:** the registered Phase 8k discrimination criteria:
  - gates E2 and E3;
  - (a) FAR ≤ 0.25;
  - (b) FRR ≤ 0.5 with ≥ 2 accepted;
  - (d) one-sided exact (hypergeometric) p ≤ 0.05.

  Power = P(all hold).

## 2. Label noise alone

Probability that a unit's observed label is wrong under the point rule:

| n_eff (independent benign windows) | 50 | 200 | 1,000 | 5,000 |
|---|---|---|---|---|
| adequate labelled unsafe | 12% | 11% | 4.8% | 0.8% |
| unsafe labelled adequate | 14% | 3.6% | 0.4% | 0% |

F1's networks have 3.6–7 effective benign hosts, so their n_eff is small. With point labels,
mislabelled adequate units then dominate the "unsafe" set and inflate the observed false
acceptance. That is why, when most units are adequate (`prev` = 0.75), the point design reaches
80% power within N ≤ 100 only if n_eff ≥ 5,000.

## 3. Power (three-state labels, prev = 0.5, independent units)

| N networks | good rule, n_eff 200 | moderate, n_eff 200 | good, n_eff 1,000 | moderate, n_eff 1,000 | good, n_eff 1,000, families of 4 |
|---|---|---|---|---|---|
| 7 | 0.00 | 0.00 | 0.05 | 0.02 | 0.03 |
| 13 | 0.06 | 0.03 | 0.55 | 0.25 | 0.46 |
| 20 | 0.18 | 0.07 | **0.80** | 0.46 | 0.70 |
| 30 | 0.39 | 0.19 | 0.95 | 0.63 | **0.85** |
| 50 | 0.71 | 0.37 | 0.99 | 0.75 | 0.94 |
| 100 | 0.96 | 0.69 | 1.00 | **0.82** | 0.98 |

**Minimum N for 80% power, three-state labels:**

| rule | per-unit evidence | independent units | families of 4 |
|---|---|---|---|
| good | n_eff ≥ 1,000 | 20–30 | 30–40 |
| good | n_eff 200 | 60, or never within 100 | 80, or never |
| moderate | n_eff ≥ 1,000 | 60–100 | never within 100 |

**The Phase 8k situation** (7 correlated F1-like units, n_eff 200, point labels): power is
2–21% across all rules and prevalences. Even a good rule would most likely have produced a
"failure" or "not evaluable".

## 4. What this means

1. **A credible network-level confirmation needs at least 20–30 independent networks,** each
   with ≥ 1,000 effective independent verified-benign evaluation windows. That means many
   active benign hosts and days of traffic. And this holds only for a *good* rule.
2. **Public data provides about 1 strictly eligible confirmation unit (DEDALE),** possibly 2
   (DATASET_ELIGIBILITY.md). No adequately powered confirmatory study can be built from public
   data today.
3. **Three-state adequacy labels are required in any future design.** Point labels lose power
   to boundary noise, and can fail even with infinite N when most units are adequate.
4. **Dependence costs about 50% more units.** Networks from one generator or one institution
   should be counted as families, with families as the resampling units.
