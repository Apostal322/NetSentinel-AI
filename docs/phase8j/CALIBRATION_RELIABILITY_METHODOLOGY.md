# Phase 8j calibration-reliability methodology

**Status:** design, development-only analysis [E].
**Code:** `scripts/phase8j/threshold_stats.py` (no network data). It writes
`reports/phase8j/threshold_stats.json`: 200 replicates × 288 configurations, ~4 min CPU.
**Revision:** this version follows the independent review (README, "Review").

## 1. The problem in one paragraph

A split-conformal threshold controls the **average** false-positive rate over calibration
draws when windows are exchangeable. Network calibration violates this twice:
- **Windows are dependent:** one host's windows are correlated in time and share a host
  effect.
- **Few hosts carry the data:** N4 had 2.2 effective hosts; NF-UNSW had 12.3.

The guarantee that matters operationally is **training-conditional**: the chance that *this*
calibration's threshold has FPR > ε. It depends on the number of **independent** observations,
not the number of windows. Section 2 quantifies this. Section 3 tests the four proposed
eligibility checks against it. Sections 4–5 define the learned and dependence-aware methods
registered in [PREREGISTRATION.md](PREREGISTRATION.md).

## 2. Exact results for exchangeable, continuous scores

The T0 threshold is the k-th smallest of n hold-out scores, k = ⌈(n + 1)(1 − α)⌉. With
continuous scores, its FPR on new windows, conditional on the calibration, is
Beta(n + 1 − k, k).

| n | k | mean FPR | P(FPR > 2%) | 95th percentile of FPR |
|---|---|---|---|---|
| 99 | 99 (max) | 1.00% | 13.5% | 2.98% |
| 150 | 150 (max) | 0.66% | 4.8% | 1.98% |
| 198 | 198 (max) | 0.50% | 1.8% | 1.50% |
| **199** | 198 (2nd largest) | 1.00% | **9.1%** | **2.36%** |
| 250 | 249 | 0.80% | 3.9% | 1.88% |
| 300 | 298 | 1.00% | 6.0% | 2.08% |
| 500 | 496 | 1.00% | 2.8% | 1.82% |
| 1,000 | 991 | 1.00% | 0.5% | 1.57% |
| 2,000 | 1,981 | 1.00% | 0.02% | 1.39% |

- **The bound is a sawtooth.** The 95th percentile exceeds 2% for n ∈ [50, 148], [199, 235]
  and [299, 312], and stays ≤ 2% from **n = 313** on.
- **"n ≥ 199" is not a principled cut.** At 199 the threshold steps down from the maximum to
  the second-largest score, and the risk jumps from 1.8% to 9.1%.
- **A training-conditional (PAC) rank is better.** Choose the largest exceedance count l with
  P(FPR > 2α) ≤ δ under Beta(l, n + 1 − l) (Vovk 2012). For δ = 5% this gives l = 0 at
  n = 100 (abstain), 1 at 199, 3 at 313, 5 at 500 and 13 at 1,000.
- **Claiming a realised rate needs even more data.** Take an observed 1%, counted
  conservatively as x = ⌈0.01 n⌉. Its one-sided Clopper-Pearson 95% bound:
  - first reaches ≤ 2% at **590** independent windows, and stays there from **719**;
  - first reaches ≤ 1.5% at 1,696, and stays there from 2,012.
  - The bound is not monotone in n, so the pre-registration's claim rule tests the bound
    itself, not a fixed n.
- **Ties break the continuity assumption.** The source model gives many windows identical
  scores: 0–1.2% of development hold-out scores tie exactly at T0, and 58% on N4. With ties,
  the realised exceedance of "score strictly above the order statistic" is at most the Beta
  law's, and T0 is insensitive to added windows. Every Phase 8j threshold is therefore an
  order statistic with strict-greater-than alerts, and tie mass is reported.

## 3. Dependent calibration: a simulation that knows the truth

**Model:** score z = u_h + √(1 − ρ)·e_t, where:
- u_h ~ N(0, ρ) is a host effect;
- e is a stationary AR(1) series per host with coefficient φ.

Over the host population z ~ N(0, 1), so a threshold t has population FPR 1 − Φ(t) exactly.
**Grid:** hosts H ∈ {2, 3, 5, 10, 20, 50}, windows n ∈ {250, 1,000, 4,000}, ρ ∈ {0, 0.2, 0.5,
0.9}, φ ∈ {0.5, 0.9}, host sizes equal or Zipf.

A replicate is **bad** when the population FPR of the threshold the rule *uses* exceeds 2α:
- T0 for checks 1–3 and the bootstrap rules;
- M3's own threshold for M3.

**Summaries:**
- **Pooled:** bad passes / passes over the whole grid, with a Clopper-Pearson 95% bound.
- **Worst configuration:** with its counts. A small pass count gives a noisy rate.
- **Utility:** mean pass rate over the 43 configurations whose T0 is actually safe
  (P(bad) ≤ 5%).

All summaries depend on the grid: configurations are weighted equally, and the safe ones are
mostly ρ = 0.

| rule | pooled P(bad given pass) [95% bound] | worst configuration | pass rate in safe configurations |
|---|---|---|---|
| check 1: n_eff ≥ 199 (host = session here) | 641 / 7,087 = 0.090 [0.096] | 7 of 7 (H = 2, ρ = 0.9) | 0.65 |
| check 2: effective hosts ≥ 10, top host ≤ 25% | 4,202 / 17,600 = 0.239 [0.244] | 137 of 200 (H = 10, ρ = 0.9) | 0.40 |
| check 3: host-grouped exceedance ≤ 2α | 11,258 / 38,494 = 0.292 [0.296] | 38 of 38 (H = 2, ρ = 0.9) | 1.00 |
| checks 1–3 together | 23 / 2,012 = 0.011 [0.016] | 2 of 17 (H = 10, n = 250, ρ = 0) | 0.23 |
| n_eff ≥ 313 and ≥ 10 hosts | 8 / 1,790 = 0.004 [0.008] | 1 of 1 | 0.21 |
| host-bootstrap bound of in-sample exceedance ≤ 2α, ≥ 20 hosts | 2,889 / 14,383 = 0.201 [0.206] | 38 of 49 (ρ = 0.9) | 0.39 |
| host-bootstrap bound of out-of-fold exceedance ≤ 2α, ≥ 20 hosts | 752 / 5,819 = 0.129 [0.137] | 3 of 3 (ρ = 0.9) | 0.35 |
| **M3: PAC threshold at the dependence-adjusted n_eff, ≥ 10 hosts** | **2 / 2,410 = 0.001 [0.003]** | **1 of 102** (H = 10, n = 1,000, ρ = 0) | **0.28** |

Selected configurations. Each cell is pass rate (P(bad | pass)); "–" means the rule never
passed.

| H | n | ρ | sizes | φ | P(bad) of T0 | check 1 | check 2 | check 3 | 1–3 | M3 |
|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 1,000 | 0.9 | Zipf | 0.9 | 0.88 | 0.04 (1.00) | 0.00 (–) | 0.12 (0.96) | 0.00 (–) | 0.00 (–) |
| 10 | 1,000 | 0 | equal | 0.5 | 0.01 | 0.91 (0.01) | 1.00 (0.01) | 1.00 (0.01) | 0.91 (0.01) | 0.89 (0.00) |
| 10 | 1,000 | 0 | equal | 0.9 | 0.12 | 0.01 (0.00) | 1.00 (0.12) | 0.94 (0.12) | 0.01 (0.00) | 0.00 (–) |
| 10 | 4,000 | 0.5 | equal | 0.9 | 0.38 | 0.00 (–) | 1.00 (0.38) | 0.74 (0.47) | 0.00 (–) | 0.00 (–) |
| 50 | 4,000 | 0.2 | equal | 0.5 | 0.00 | 0.74 (0.00) | 1.00 (0.00) | 1.00 (0.00) | 0.74 (0.00) | 0.99 (0.00) |
| 50 | 4,000 | 0.2 | equal | 0.9 | 0.07 | 0.01 (0.00) | 1.00 (0.07) | 1.00 (0.07) | 0.01 (0.00) | 0.00 (–) |
| 50 | 4,000 | 0.9 | Zipf | 0.9 | 0.52 | 0.00 (–) | 1.00 (0.52) | 0.69 (0.68) | 0.00 (–) | 0.00 (–) |

**Conclusions (for this stylised model):**
1. **No proposed check is safe on its own.**
   - Check 2 passes whenever hosts are many, even when their tails differ strongly.
   - Check 3 is a noisy estimate of a 1% tail and passes most bad calibrations.
   - Check 1 fails with very few hosts, because the ICC estimate is degenerate there.
2. **Checks 1–3 together are mostly safe but not uniformly:** 2 of 17 passes were bad with
   10 hosts and 250 windows. They pass 23% of good calibrations.
3. **Bootstrapping the observed hosts cannot certify the tail of unseen hosts.** Both
   bootstrap bounds are anti-conservative when hosts differ.
4. **M3 had the best trade-off:** 2 bad passes in 2,410, and 28% of good calibrations
   passed.
   - It counts within-host autocorrelation. T0 itself is unsafe at ρ = 0 when φ = 0.9 and
     n = 1,000 (P(bad) 0.12), and M3 correctly abstains there.
   - It is registered as M3. Its support is this simulation only; development and
     confirmation decide J3.
5. **When hosts differ strongly (ρ ≥ 0.5) with ≤ 50 hosts, every safe rule abstains.** Honest
   output there is "budget not supported". Coverage must come from networks with many
   independent hosts.
6. **Recency (check 4) cannot be justified by an exchangeable model.** It addresses drift
   (NF-ToN-IoT: KS 0.68), which only real data can show. It stays an empirical hypothesis.

**On development data** (Phase 8i calibration audit; host-level Kish n_eff without the
autocorrelation deflation): 910–1,150 on the 6 NF-CIC days, 27 on NF-UNSW, and 2.2 on N4. On
NF-ToN-IoT it is a degenerate 4,571 (ICC 0, most hosts with one window), where the failure is
drift, not size. M3's own n_eff (with deflation) is computed in the registered development
runs.

## 4. The learned reliability model (M2)

**Unit:** a (calibration, evaluation block) pair.

**Target: block overrun.** The block's false alerts on verified-benign windows are
significantly above α: the exact one-sided binomial test of FPR ≤ 1% gives p < 0.05. Only
blocks with ≥ 30 verified-benign windows count. A fixed "> 2%" cut was rejected after review:
one false alert in a 30–49-window block would count as an overrun 26–39% of the time even
with perfect calibration. Block size would then dominate the target.

**Development episodes** create calibration variety, since 4 network units alone cannot train
anything. Each development domain is scored under P1x (seeds 0–2), and each calibration is
re-drawn by:
- **host subsampling:** keep H′ ∈ {5, 10, 20, 50, 200} hold-out hosts, chosen uniformly,
  5 draws each, plus the full hold-out once;
- **recency truncation:** keep the last {3 h, 12 h, all} of the hold-out.

**Duplicate variants are dropped:** where H′ is at least the domain's host count, the variant
equals the full hold-out (N4 has 7 hosts, NF-UNSW 17). Every real evaluation block of the
domain is paired with every distinct variant. Evaluation always uses all verified-benign
windows, so a subsampled calibration mimics limited calibration visibility, as on N4. Training
and evaluation weight every network unit equally, whatever its block or variant count.

**Features:** all label-free and available at deployment time.

| group | features |
|---|---|
| calibration size and dependence | log n_hold, log hosts, effective hosts, top host share, session n_eff, M3's n_eff, the PAC exceedance count l (0 if none), tie mass at T0 |
| internal consistency | host-grouped exceedance, out-of-fold host-bootstrap 95% bound |
| block versus calibration | hours since the hold-out ended; bulk score shift (block median and 75th percentile minus hold-out median and 75th percentile); share of block windows from hosts absent from calibration |

- **Excluded on purpose:**
  - Block alert rate and any upper-tail score statistic: attacks raise them, so a model
    using them would abstain *during attacks* and blind the detector.
  - Block size: it would let the model learn "abstain on busy or quiet hours" instead of
    calibration reliability.

  The pre-registration checks both directly (criteria (b) and (e)).
- **Model:** L2 logistic regression (C = 1), standardised features, class-balanced. Simple by
  design, given 4 development units.
- **Abstention:** P(overrun) > τ, with τ chosen by the registered rule (PREREGISTRATION
  section 7).
- **Evaluation:** leave-one-network-out over the 4 development units, plus AUROC and Brier
  score of P(overrun) against the observed overrun.

## 5. Dependence-aware calibration (M3) and the full policy (M4)

- **M3, step by step:**
  1. Compute the pooled within-host lag-1 autocorrelation r of hold-out scores (each host
     demeaned, windows in time order), clipped to [0, 0.99].
  2. Deflate each host's window count by the AR(1) design effect (1 + r)/(1 − r).
  3. Apply the Kish host correction n_eff = n′ / (1 + (m′_w − 1)ρ̂), with ρ̂ the one-way ANOVA
     ICC of hold-out scores within hosts and m′_w = Σm′²/n′.
  4. Require ≥ 10 hosts; the ICC estimate is degenerate below that.
  5. Take the PAC exceedance count l for ⌊n_eff⌋ (ε = 2α, δ = 5%). The threshold is the order
     statistic at rank ⌈n(1 − l/(n_eff + 1))⌉ of all n hold-out scores, **but never a lower
     rank than T0's**.
  6. With fewer than 10 hosts or no l ≥ 1, abstain for the whole network.
- **Why the floor at T0:** at large n_eff the PAC rank targets "FPR ≤ 2% with 95% probability"
  and would otherwise be looser than the 1% target. For example, at n = 1,000 it allows 13
  exceedances against T0's 10. A unit test caught this in the first version.
- **M4:** M3, plus block-level abstention from an M2 model refitted with M3 thresholds, so the
  block-overrun target matches M4's own threshold.

## 6. What the design cannot do

- With 4 development network units, M2's coefficients rest on very few independent units. The
  episodes add calibration variety, not network variety.
- The simulation covers dependence and small calibration, not drift. Its Gaussian host effects
  and AR(1) errors are a stylised model; real tails may be heavier.
- Every rule judges a calibration against the hosts it has seen. When evaluation brings many
  hosts that are new and different, only the block-level "unseen host share" feature can
  notice.
