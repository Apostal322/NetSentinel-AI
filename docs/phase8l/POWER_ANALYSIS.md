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

The F1 probe network has 3.6 (by flows) to 7.0 (by hold-out windows) effective benign hosts, so its n_eff is small. With point labels,
mislabelled adequate units then dominate the "unsafe" set and inflate the observed false
acceptance. That is why, when most units are adequate (`prev` = 0.75), the point design reaches
80% power within N ≤ 100 only if n_eff ≥ 5,000.

## 3. Power (prev = 0.5, independent units unless stated)

| N networks | three-state, good rule, n_eff 200 | three-state, moderate, n_eff 200 | three-state, good, n_eff 1,000 | three-state, moderate, n_eff 1,000 | three-state, good, n_eff 1,000, families of 4 | point labels, good, n_eff 1,000 |
|---|---|---|---|---|---|---|
| 7 | 0.00 | 0.00 | 0.05 | 0.02 | 0.04 | 0.36 |
| 13 | 0.06 | 0.03 | 0.55 | 0.25 | 0.55 | 0.72 |
| 20 | 0.18 | 0.07 | **0.80** | 0.46 | 0.82 | 0.85 |
| 30 | 0.39 | 0.19 | 0.95 | 0.63 | 0.93 | 0.90 |
| 50 | 0.71 | 0.37 | 0.99 | 0.75 | 0.98 | 0.95 |
| 100 | 0.96 | 0.69 | 1.00 | **0.82** | 1.00 | 0.98 |

**Minimum N for 80% power, good rule** (sensitivity 0.9, FAR 0.1):

| labels | n_eff | prev 0.25 | prev 0.5 | prev 0.75 |
|---|---|---|---|---|
| three-state | 1,000 | 30 | 20 | 25 |
| three-state | 200 | > 100 | 60 | 60 |
| point | 1,000 | 20 | 16 | > 100 |
| point | 200 | 25 | 40 | > 100 |

**Notes on the model:**
- **The dependence model is optimistic.** The family random effect is centred, so it keeps the
  marginal rates; adequacy is not clustered; and the exchangeable test (d) is anti-conservative
  under clustering. Real dependence would cost more units than the "families of 4" column
  shows.
- **The moderate rule needs 80–100 networks, or is never powered.** That is largely because its
  FAR (0.20) sits next to the 0.25 criterion; it is a property of the threshold. A weak rule
  (FAR 0.30) cannot pass (a) at any N, by construction.
- **Sensitivity (independent review):**
  - moving the adequate range further from 2% (U(0.2, 1.2)%) lowers the good-rule minimum to
    about 16;
  - estimating FAR with intervals instead of pass/fail raises it: about 80 networks to show
    FAR < 0.25.
  - Across reasonable choices the minimum is about **13–30**.
- **These minima are lower bounds.** Criteria (c) pooled accepted FPR, (e) detection and any
  per-family condition are not modelled.
  - A per-family FAR criterion is unattainable in families of 2–3: one false acceptance breaks
    it. The review showed power *falling* with N, from 0.35 at N = 20 to 0.09 at N = 50.

**The Phase 8k situation** (7 correlated F1-like networks; n_eff 200 assumed, not derived; point labels): power is
**3–26%** across rules and prevalences, and that is an upper bound since (c), (e) and (f) are
omitted. Even a good rule would most likely have produced a "failure" or "not evaluable".

## 4. What this means

1. **A credible network-level confirmation needs at least about 15–30 independent networks**
   (more under real clustering, and once every criterion is modelled), each with ≥ 1,000
   effective independent verified-benign evaluation windows, and only for a good rule.
2. **Public data provides 0–1 strictly eligible confirmation network** (DEDALE, pending
   verification), possibly 2 (DATASET_ELIGIBILITY.md). No adequately powered network-level
   confirmation can be built from public data today. The gap is about an order of magnitude
   under every reasonable modelling choice.
3. **Three-state adequacy labels are recommended for validity, not power.**
   - Point labels are *more* powerful when prev ≤ 0.5 (minimum N 16 vs 20 at n_eff 1,000).
   - But their mislabelled boundary units bias the observed false acceptance, and with mostly
     adequate networks (prev 0.75) they fail to reach 80% within N = 100 unless n_eff is about
     5,000.
4. **Networks from one generator or institution must be modelled as families**, with
   family-level inference in the test, not only in the bootstrap.
