# Phase 8k development experiments [E]

**Code:** `scripts/phase8k/dev_experiments.py`, output `reports/phase8k/dev_experiments.json`.
It re-thresholds the Phase 8j P1x scores (seeds 0–2; each network scored by a source model that
never saw it) and fits nothing on a target. It ran under the 3.4 GiB cap (574 MiB, 523 s).
Numbers are means over 3 seeds. Every row is development data, and three of these networks
shaped the Phase 8i checks, so none of this is confirmation.

## 1. Calibration construction: does source-aware calibration help?

Each cell is verified-benign FPR / window recall / entity recall, at α = 1%.

| domain | T0 (hold-out) | TX (all calibration) | HB (host-balanced) | HC5 (host share ≤ 5%) | PAC | HB+PAC |
|---|---|---|---|---|---|---|
| NF-CIC 02-14 | 1.3% / 1.00 / 1.00 | 1.0% / 1.00 / 1.00 | 2.3% / 1.00 / 1.00 | 1.3% / 1.00 / 1.00 | 1.3% / 1.00 / 1.00 | 1.3% / 1.00 / 1.00 |
| NF-CIC 02-16 | 1.2% / 0.96 / 1.00 | 1.0% / 0.96 / 1.00 | 2.3% / 0.96 / 1.00 | 1.2% / 0.96 / 1.00 | 1.2% / 0.96 / 1.00 | 1.2% / 0.96 / 1.00 |
| NF-CIC 02-20 | 1.3% / 0.08 / 0.90 | 1.0% / 0.08 / 0.90 | 2.5% / 0.08 / 0.90 | 1.3% / 0.08 / 0.90 | 1.3% / 0.08 / 0.90 | 1.3% / 0.08 / 0.90 |
| NF-CIC 02-21 | 1.6% / 0.99 / 1.00 | 1.1% / 0.99 / 1.00 | 2.8% / 1.00 / 1.00 | 1.6% / 0.99 / 1.00 | 1.6% / 0.99 / 1.00 | 1.6% / 0.99 / 1.00 |
| NF-CIC 02-22 | 1.3% / 0.10 / 0.17 | 0.9% / 0.09 / 0.16 | 2.1% / 0.10 / 0.17 | 1.3% / 0.10 / 0.17 | 1.3% / 0.10 / 0.17 | 1.3% / 0.10 / 0.17 |
| NF-CIC 03-02 | 1.0% / 0.36 / 1.00 | 0.7% / 0.20 / 0.95 | 2.0% / 0.62 / 1.00 | 1.0% / 0.36 / 1.00 | 1.0% / 0.36 / 1.00 | 1.0% / 0.36 / 1.00 |
| NF-UNSW | 3.7% / 0.97 / 1.00 | 0.8% / 0.16 / 1.00 | 2.3% / 0.42 / 1.00 | 2.3% / 0.42 / 1.00 | abstain | abstain |
| NF-ToN-IoT | 14.8% / 0.61 / 1.00 | 11.8% / 0.54 / 1.00 | **33.7%** / 0.97 / 1.00 | 14.8% / 0.61 / 1.00 | 14.8% / 0.61 / 1.00 | 14.8% / 0.61 / 1.00 |
| N4 | 11.9% / 0.88 / 1.00 | 8.0% / 0.87 / 1.00 | 11.9% / 0.88 / 1.00 | 11.9% / 0.88 / 1.00 | abstain | abstain |

**Ablation conclusions:**
- **Host-balanced weighting (HB) is the wrong target.** The operational FPR is counted over
  windows, so busy hosts dominate it. Equal host weights calibrate for the *average host*
  instead: FPR rises on every NF-CIC day (to 2.0–2.8%) and to 33.7% on NF-ToN-IoT. It helps
  only NF-UNSW (3.7% → 2.3%), at a recall cost (0.97 → 0.42).
- **Capping a host's share (HC5)** changes only NF-UNSW (the same 2.3% / 0.42). Elsewhere no host
  exceeds 5%, or every host does (N4).
- **All calibration windows (TX)** lower FPR everywhere, because the sample is larger. But they
  neither rescue NF-ToN-IoT (11.8%) nor N4 (8.0%), and cost recall on NF-UNSW (0.16) and
  NF-CIC 03-02 (0.20).
- **PAC** changes nothing where it accepts, and abstains on the two small calibrations.
- **Source-diversity-aware calibration (M4) is therefore not justified** by development data.
  It stays in the comparison as a registered negative, not as a candidate.

## 2. Why calibrations fail: decomposition at T0

| domain | benign windows from hosts unseen in calibration | false alerts from unseen hosts | FPR, seen hosts | FPR, unseen hosts | p95 score shift of seen hosts | calibration age (h) | largest host's share of false alerts | effective hosts | top host share |
|---|---|---|---|---|---|---|---|---|---|
| NF-CIC (6 days) | 20.6–24.9% | 8–13% | 1.1–1.9% | 0.4–0.7% | 0.00–0.02 | 1.4–2.3 | 4–8% | 477–651 | 0.4–0.5% |
| NF-UNSW | 4.1% | 23.9% | 2.9% | 21.2% | 0.00 | 4.5 | 8.2% | 12.3 | 8.8% |
| NF-ToN-IoT | 35.0% | **60.6%** | 9.0% | **25.7%** | 0.00 | 22.1 | 38.1% | 92.8 | 9.3% |
| N4 | 0.8% | 1.7% | 11.8% | 20.0% | **+0.28** | **309** | **98.3%** | 2.2 | 64.4% |

**Three mechanisms:**
- **Small calibration** (NF-UNSW): even seen hosts exceed 2%.
- **Population turnover** (NF-ToN-IoT): most false alerts come from hosts the calibration never
  saw.
- **Dominant-host change** (N4): one seen host's score tail moved up over almost 13 days.

The second and third happen *after* calibration, so no calibration-only statistic can observe
them. On NF-CIC, a quarter of benign traffic also comes from new hosts, but those are benign-like
(FPR 0.4–0.7%). Population turnover alone is not a failure signal.

## 3. Network-level reliability decisions (the real calibrations)

Each cell is the share of the 3 seeds in which the rule accepts. Adequacy is the realised
verified-benign FPR at the rule's own threshold ≤ 2%.

| rule | NF-CIC (adequate) | NF-UNSW (unsafe) | NF-ToN-IoT (unsafe) | N4 (unsafe) | false accepts / rejects (27 domain × seed rows) |
|---|---|---|---|---|---|
| M0 always accept | 1.0 | 1.0 | 1.0 | 1.0 | 9 / 0 |
| M1 fixed checks | 1.0 | 0.0 | 0.0 | 0.0 | 0 / 0 |
| M2 PAC | 1.0 | 0.0 | **1.0** | 0.0 | 3 / 0 |
| M3 PAC + temporal self-consistency | 1.0 | 0.0 | **1.0** | 0.0 | 3 / 0 |
| M4 PAC + host-balanced threshold | 1.0 | 0.0 | **1.0** | 0.0 | 3 / 0 |

- **M1 separates all 4 networks, but this is circular:** its checks were proposed after looking
  at these networks. It catches NF-ToN-IoT through the host-grouped exceedance (0.028 as a 3-seed mean, 0.030 at seed 0; > 2α).
- **M2–M4 falsely accept NF-ToN-IoT.**
- **The temporal self-consistency check (M3) does not see the turnover:** the internal
  exceedance is 0.1%. The change happens between calibration and evaluation, not within
  calibration.
- **Four network units cannot rank M1 against M2 with any confidence.** The exact 95%
  interval for 0 false accepts out of 3 unsafe networks is 0–71%.

## 4. Within-network stress tests (not independent evidence)

Each domain's calibration was re-drawn 33–86 times: 5, 10, 20, 50 or 200 hosts, and the last
3 h, 12 h or all of the hold-out. That gives 544 domain × seed × variant rows. Adequacy is that
of the episode's own threshold.

| rule | accepted | false accepts | false rejects (of 260 adequate episodes) | mean false-acceptance rate over domains | mean false-rejection rate over domains |
|---|---|---|---|---|---|
| M1 | 42 | 24 | 242 | 0.03 | 0.94 |
| M2 | 56 | 38 | 242 | 0.05 | 0.94 |
| M3 | 46 | 28 | 242 | 0.04 | 0.94 |
| M4 | 56 | 38 | 242 | 0.05 | 0.94 |

**Readings:**
- False acceptances occur only on NF-ToN-IoT (rates 0.28–0.42 there) and NF-UNSW (0.06),
  which is drift again.
- **All rules reject about 94% of the subsampled calibrations that happened to be adequate:**
  they are safe but very conservative, as the Phase 8j simulation predicted.
- No rule passes a calibration of only a few hosts, even when its threshold happens to work.
