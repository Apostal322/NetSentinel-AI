# Phase 8s Stage 3: the calibration estimand and the evidence its tail needs

**Sources:**
- `scripts/phase8s/estimand.py`, `reports/phase8s/estimand.json` (saved scores, mean of 6 fits);
- `scripts/phase8s/active_calibration.py`.

Oracle labels describe the population here. They select nothing.

## 1. Estimand

**Operational criterion:** the **window-weighted false-positive rate** on the benign evaluation
windows (Phase 8i historical benign set). Its calibration target is the benign (1 − α) score
quantile q_b, at α = 1 %.

**The best a threshold-only method can reach from the hold-out is the hold-out's benign quantile**
(reference T; Phase 8q cell T, Phase 8r A1T). The evaluation FPR at T still differs from α,
because of stale memory and drift (Phase 8o).

**Other estimands** (false alerts per active host-hour, per day, per host) are reported as
secondary metrics. They are not interchangeable with the target:
- a host-weighted estimand gives each of NF-ToN's 3,635 benign hosts equal influence;
- 98 % of those hosts hold a single near-silent window.

## 2. Sampling unit and designs

**Unit:** a host's hold-out activity (a cluster of windows). One review returns one verdict for the
whole cluster, so review errors are perfectly correlated within a host.

**Design:** every probability design is a **Poisson design** with known π_h and Σπ_h = k expected
reviews. Every window then has an exact inclusion probability π_h.

**Estimators:**
- **C1 (Hájek):** the window-weighted CDF of verified-benign windows, weighted 1/π_h and
  normalised.
  - It is design-consistent for the benign window CDF **only under perfect, always-conclusive
    review**.
  - With inconclusive or erroneous reviews it additionally assumes that review failures are
    missing at random. The MNAR reviewer R2 tests that assumption.
- **A weighted quantile is not automatically valid.** Its sampling distribution depends on how
  many independent clusters carry the tail (§ 3), not on whether the weights sum to one.

## 3. How much evidence a 1 % tail needs

**For i.i.d. benign windows:**
- the conformal rank needs n ≥ 99 for E[FPR] ≤ α;
- the sample maximum exceeds q_b with probability ≥ 95 % only for n ≥ 299 ((1 − α)ⁿ ≤ 0.05).

**Windows are not i.i.d.** The relevant count is the number of independent clusters that hold the
tail.

**Benign hold-out populations** (oracle description):

| domain | benign hosts | benign windows | single-window hosts | top 1 % of hosts hold | hosts holding the tail above q_b (Kish) | exceedance deff (ANOVA) |
|---|---|---|---|---|---|---|
| NF-CIC 02-14 | 6,557 | 35,221 | 59 % | 26 % | 192 (109) | 9.2 |
| NF-CIC 02-16 | 5,053 | 25,919 | 58 % | 23 % | 153 (96) | 13.5 |
| NF-CIC 02-20 | 6,534 | 34,741 | 56 % | 23 % | 179 (84) | 3.9 |
| NF-CIC 02-21 | 6,505 | 36,144 | 56 % | 25 % | 207 (141) | 5.1 |
| NF-CIC 02-22 | 6,002 | 36,303 | 56 % | 25 % | 214 (125) | 6.5 |
| NF-CIC 03-02 | 4,736 | 29,131 | 53 % | 16 % | 165 (94) | 5.7 |
| NF-UNSW | 17 | 443 | 18 % | 9 % | 2.8 (2.8) | 7.5 |
| NF-ToN | 3,635 | 4,572 | **98 %** | 20 % | **2.0 (1.3)** | 1.0 (misleading) |
| NF-BoT | 7 | 781 | 0 % | 64 % | **1.0 (1.0)** | 1.0 |

**Reading:**
- **NF-CIC's tail is carried by about 85–140 effective hosts.** A sample can represent it, given
  enough reviews that reach those hosts.
- **On NF-ToN, NF-BoT and NF-UNSW, the benign 1 % tail is one to three hosts.**
  - "The benign 99th percentile" there is a property of those few hosts, not of a population.
  - A trusted sample estimates it only if it *contains those hosts*. Even a full census holds
    one to three independent tail clusters: far too few for a tail guarantee.
  - The threshold is then identifiable only in the trivial sense of reviewing those hosts. **No
    confidence statement about the tail is possible.**
- **The one-way ANOVA design effect understates clustering when singleton hosts dominate.**
  - NF-ToN's ICC estimate is about 0, because most clusters have one window.
  - The count of tail hosts is the honest measure, and it is what the conservative estimator C3
    checks (it abstains with fewer than 5 tail hosts).

## 4. What follows for the design

1. **A design must reach the high-activity hosts.**
   - Random host vetting (Phase 8r) almost never does.
   - Window-proportional designs (random-window, PPS, mass strata) do by construction.
   - On NF-ToN and NF-BoT, though, they mostly reach attackers: 76–92 % of hold-out window mass.
2. **On NF-CIC a probability design can work.** The decision is how many reviews it needs.
3. **On NF-UNSW, NF-ToN and NF-BoT,** even a perfect design yields a threshold equal to one or two
   hosts' tails, with no evidence for its stability. C3 must abstain there, and the registered
   criteria count abstention against the method.
