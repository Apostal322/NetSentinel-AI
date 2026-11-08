# Phase 8s Experiments A–C: sampling designs, two-dimensional budgets, weighted calibration

**Status:** REGISTERED (PREREGISTRATION §§ 2–7).
- Registration `16f564b`; results `a5161d9`; run on a clean tree.
- Run: 631 s, peak 0.6 GiB; output hash `27a89925…` (`reports/phase8s/experiments.sha256`).
- **Review is ORACLE-SIMULATED** (reviewer R0, perfect) from the calibration labels.
- Saved scores only. The frozen-score hashes were checked against Phase 8o at run time.
- Sources: `reports/phase8s/experiments.json`, `data/derived/phase8s/rows.parquet` (hashes in
  `derived_manifest.json`).

**References** reproduce Phase 8r exactly: U 0.372, T 0.656, P 0.869.

## 1. Registered decisions

| hypothesis / gate | verdict | basis |
|---|---|---|
| **H1 representative sampling** (gate B) | **SUPPORTED** (by rule; substantively on NF-CIC and NF-ToN only) | median \|calibration error\|: PPS + C1 0.32 pp macro vs random-host + C0 1.88 pp; better on 3 of 4 networks |
| **Calibration quality** (gate C) | **NOT SUPPORTED** | criteria (i) and (iv) pass; (ii) and (iii) fail on NF-ToN only: FPR 20.1 % vs 18.0 % allowed; p90 24.2 % vs 21.0 % |
| **Detection usefulness** (gate D) | **DEVELOPMENT NO-GO** | gate C not supported (the R₂₀ gain over U is +11.6) |
| H2 two-dimensional budgets | **NOT SUPPORTED** | the Kish n_eff tracks calibration error better than the verified-host count on 2 of 4 networks (NF-ToN, NF-BoT), not ≥ 3 |
| H3 design weighting | **SUPPORTED** (by rule; substantively on NF-CIC and NF-ToN only) | the median paired \|error\| change C1 − C0 under PPS is < 0 on 3 networks (NF-CIC −0.20 pp, NF-UNSW −0.11, NF-ToN −0.47) and 0 on NF-BoT. On census-limited NF-UNSW, half the pairs are exactly 0 and the rest reflect only the quantile definition (amendment S-3) |

**H1 caveat (EXPLORATORY, `posthoc.json`).**
- At k = 30, NF-UNSW (21 hosts) and NF-BoT (15) are reviewed in full by every design. There, the
  comparison differs only in the estimator's quantile definition (conformal rank vs Hájek
  inverted CDF). NF-UNSW counts as a "win" (0.21 vs 0.32 pp) for that reason alone.
- On the two networks where the design matters, PPS + C1 cuts the median error:
  - NF-CIC: by 21 % (0.49 vs 0.62 pp);
  - NF-ToN: by 94 % (0.37 vs 6.36 pp).
- The registered verdict stands, but **the design effect is shown on two networks, not three.**
- **No active or tail design beat the simple window-proportional controls.** At k = 30, tail + C1
  has the lowest NF-CIC error (0.27 pp) and FPR (1.3 %). On NF-ToN, PPS, random-window and tail
  all land at 20–22 % FPR. Budget mattered more than design.

## 2. Main table (k = 30 expected host reviews, R0; macro documented recall; per network recall / FPR)

| cell | macro | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | R₂₀ |
|---|---|---|---|---|---|---|
| U unlabelled | 0.372 | 0.503 / 1.2 % | 0.054 / 1.8 % | 0.001 / 0.4 % | 0.930 / 9.6 % | 16.0 |
| T oracle threshold | 0.656 | 0.503 / 1.2 % | 0.549 / 3.6 % | 0.640 / 16.0 % | 0.933 / 7.8 % | 27.3 |
| P full oracle | 0.869 | 0.807 / 1.2 % | 0.835 / 3.6 % | 0.884 / 16.4 % | 0.950 / 8.0 % | 37.0 |
| A0 random host + C0 (Phase 8r style) | 0.724 | 0.489 / 1.5 % | 0.549 / 3.6 % | 0.926 / **45.7 %** | 0.933 / 7.8 % | 28.9 |
| A1 random window + C1 | 0.682 | 0.500 / 1.8 % | 0.562 / 3.8 % | 0.734 / 22.2 % | 0.934 / 9.0 % | 27.8 |
| **A2 PPS + C1 (primary)** | **0.674** | 0.495 / 1.7 % | 0.562 / 3.8 % | 0.706 / **20.1 %** | 0.934 / 9.0 % | 27.6 |
| A3 stratified + C1 | 0.735 | 0.496 / 2.1 % | 0.562 / 3.8 % | 0.946 / 57.0 % | 0.934 / 9.0 % | 29.1 |
| A4 diversity + C0 | 0.626 | 0.475 / 1.3 % | 0.549 / 3.6 % | 0.546 / 12.8 % | 0.933 / 7.8 % | 26.8 |
| A5 tail + C1 | 0.683 | 0.503 / 1.3 % | 0.562 / 3.8 % | 0.732 / 21.4 % | 0.934 / 9.0 % | 27.8 |
| A2 PPS + C3 (conservative) | 0.144 | 0.396 / 1.1 % (abstains 21 %) | abstains 67 % | abstains 100 % | abstains 100 % | 11.4 |

**Reading:**
- **Window-proportional designs fix the Phase 8r failure on NF-ToN.**
  - Random-host vetting puts the threshold at the near-silent single-window hosts: FPR 45.7 % at
    k = 30, 68.9 % at Phase 8r's k = 10.
  - PPS, random-window and tail designs reach the heavy benign hosts that carry the tail:
    FPR 20–22 %, against the oracle threshold's 16.0 %.
- **Macro recall falls as calibration improves** (0.724 → 0.674). The A0 "recall" was bought by
  over-alerting, which is why recall alone cannot decide.
- **The stratified design (equal-mass strata, k/3 each) fails on NF-ToN** (57 % FPR). Its
  top-mass stratum is the heavy attackers, whose review yields MALICIOUS. The benign strata are
  then the near-silent hosts.
- **The conservative estimator C3 abstains wherever the tail lives on fewer than 5 hosts**
  (NF-UNSW, NF-ToN, NF-BoT; SAMPLING_ESTIMAND § 3). That is its registered purpose. **No
  registered cell supports a tail guarantee on those networks.**
- **NF-CIC needs no threshold rescue** (U = T recall 0.503). Its loss against P (0.807) is the
  destination memory (Phase 8q/8r), which no calibration fixes.

## 3. Budgets (EXPLORATORY reading of registered cells; `posthoc.json`)

**Cells whose FPR meets the registered limits on every network** (mean ≤ T + 2 pp and p90 ≤ T + 5 pp):

| design + C1 | k = 10 | k = 30 | k = 100 |
|---|---|---|---|
| random_host | no (NF-ToN 66 %) | no (46 %) | no (35 %) |
| random_window | no (53 %) | no (22.2 %, p90 25.3) | **yes** (16.2 %; macro 0.661) |
| pps | no (52 %) | no (20.1 %, p90 24.2) | **yes** (16.0 %; macro 0.659) |
| stratified | no (76 %) | no (57 %) | no (35 %) |
| tail | no (56 %) | no (21.4 %, p90 26.2) | **yes** (16.0 %; macro 0.660) |

**At about 100 expected host reviews per network, three window-proportional designs reproduce the
oracle threshold on all four networks.**
- That is about T's macro 0.656, which equals the gate-C criteria. It is **not** a registered
  result: the primary budget was k = 30.
- The reviews include the heavy attacker hosts, which the reviewer must identify correctly.
  Under realistic review errors this fails (CONTAMINATION_STUDY).

## 4. Two-dimensional budgets (H2) and acquisition (medians, k = 30, R0)

| network | design | reviews | benign verified | malicious found | trusted windows | Kish n_eff | cluster n_eff | weight CV | tail hosts | review success | simulated cost |
|---|---|---|---|---|---|---|---|---|---|---|---|
| NF-CIC | random_host | 30 | 30 | 0 | 156 | 156 | 5.1 | 0 | 2 | 1.00 | 32 |
| NF-CIC | pps | 30 | 29 | 0 | 1,700 | 168 | 29 | 3.0 | 7 | 1.00 | 48 |
| NF-ToN | random_host | 30 | 30 | 0 | 32 | 32 | 27 | 0 | 1 | 1.00 | 31 |
| NF-ToN | pps | 30 | 17 | 13 | 610 | 23 | 17 | 5.2 | 1 | 0.57 | 183 |
| NF-ToN | random_window | 31 | 18 | 13 | 546 | 24 | 17 | 4.6 | 1 | 0.59 | 180 |

**Reading:**
- **PPS spends 43 % of NF-ToN reviews on attackers.** Its successful-benign count is lower, and
  its SIMULATED cost (1 + 0.01 per reviewed window) is about 6× that of random-host review.
- **At equal attempts it is far better calibrated; at equal successful benign verifications, even
  more so.**
- **At equal SIMULATED cost** (about 180 units), random-host review would afford about 175 host
  reviews.
  - From the k = 100 trend (FPR 35 %), that would still not reach the window mass. This is an
    extrapolation, not a tested cell.
- **The improvement is better use of information, not just more information.** The Kish window
  n_eff is no larger (NF-ToN 23 vs 32). What changes is *which* windows are trusted.
- **Neither n_eff nor the host count alone predicts error well** (H2 not supported). The tail
  hosts, the hosts actually holding the benign 1 % tail, are the binding quantity.
  - On NF-ToN every design finds at most 1 such host.

## 5. Operational metrics (k = 30, R0, medians over draws)

| network | design | false alerts per active benign host-hour | top host's share of false alerts | false alerts per entity detected at 20 % |
|---|---|---|---|---|
| NF-CIC | random_host / pps / tail | 0.074 / 0.077 / 0.062 | 4 % | 804 / 899 / 877 |
| NF-ToN | random_host / pps / tail | 4.07 / 1.74 / 1.95 | 28 % / 36 % / 36 % | 288 / 154 / 172 |
| NF-UNSW | all (census) | 1.82 | 8 % | 115 |
| NF-BoT | all (census) | 1.31 | **100 %** | 12 |

**False alerts are host-concentrated on NF-BoT and NF-ToN.** One benign host on NF-BoT produces
every false alert. A per-host suppression list would change the workload more than any threshold.
This is an operational observation, not a tested intervention.
