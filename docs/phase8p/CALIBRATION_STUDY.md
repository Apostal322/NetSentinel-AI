# Phase 8p H4: deployment-realistic calibration

**Status:** REGISTERED DEVELOPMENT (PREREGISTRATION § 5).

**Detector:** S0, the source-only M2 construction, K = 5.

**Source:** `reports/phase8p/experiment_e.json` (`H4`).

**No scenario claims distribution-free FPR control.** The conformal rank holds only for
exchangeable hold-out and evaluation windows. The nominal α = 1 % is a target, not a bound,
under this shift.

## 1. Scenarios and the information each assumes

| scenario | assumes | fits |
|---|---|---|
| C0 P1x (oracle-assisted, the research reference) | every calibration-period attacker host is known and purged from the hold-out and the memory | 6 |
| C1 unlabelled | nothing: all calibration windows, and memory from all calibration flows | 6 |
| C2 delayed labels | an attacker is known only if its last calibration attack window ended ≥ 60 min before the calibration end | 3 (S0 base refits) |
| C3 host-balanced, unlabelled | nothing; each hold-out window is weighted 1 / (its host's windows) | 6 |

**Who C2 still labels:**
- every calibration attacker on NF-CIC 02-16, 02-20 and 02-21, and on NF-BoT;
- 230 of 316 on 02-22;
- 21 of 24 on NF-ToN;
- none on 02-14 (1 attacker), 03-02 (8) or NF-UNSW (4). Those attack until near the
  calibration end.

## 2. Results

| scenario | macro recall_doc | R₂₀,doc | NF-CIC recall / FPR | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|---|---|
| C0 | **0.869** | 37 | 0.807 / 1.17 % | 0.835 / 3.65 % | 0.884 / 16.5 % | 0.950 / 7.96 % |
| C1 | 0.372 | 16 | 0.503 / 1.16 % | **0.054** / 1.80 % | **0.001** / 0.39 % | 0.930 / 9.60 % |
| C2 | 0.387 | 16 | 0.506 / 1.13 % | 0.071 / 2.20 % | 0.017 / 1.95 % | 0.953 / 7.69 % |
| C3 | 0.613 | 26 | 0.506 / 1.65 % | 0.082 / 2.09 % | **0.933 / 34.3 %** | 0.930 / 9.60 % |

**Hold-out evidence** (windows / hosts / top-host share / independent host-hour blocks):

| network | C0 | C1 | calibration age at the evaluation midpoint |
|---|---|---|---|
| NF-CIC (per day) | 25,900–36,300 / 4,700–6,600 / ≤ 0.5 % / 5,700–8,500 | almost the same | 1.4–2.4 h |
| NF-UNSW | 443 / 17 / 8.8 % / 17 | 623 / 21 / 7.4 % / 21 | 4.4 h |
| NF-ToN | 4,572 / 3,635 / 9.3 % / 3,706 | 19,298 / 3,652 / 7.6 % / 3,895 | 36 h |
| NF-BoT | 781 / 7 / 64 % / 80 | 9,667 / 15 / 16 % / 221 | 211 h |

## 3. Decision and readings

**H4 (C3 preserves useful detection): NOT SUPPORTED.**
- macro recall_doc is 0.613, below 0.75 × C0 = 0.652;
- FPR rises more than 1 pp on NF-ToN (34.3 % vs 16.5 %) and on NF-BoT (9.6 % vs 8.0 %).

**What fails without labels (C1):**
- **NF-UNSW and NF-ToN lose almost all detection.** The calibration-period attackers stay in the
  hold-out and in the memory.
  - On NF-UNSW they are 4 of 21 hold-out hosts.
  - On NF-ToN, 14,700 of the 19,300 unlabelled hold-out windows are not in the P1x hold-out.
- **Phase 8o measured both mechanisms:** the threshold, and the memory absorbing the
  attackers' destinations.

**Delayed labels (C2) barely help.**
- Attackers are mostly active until near the calibration end, so a 60-minute verification lag
  leaves exactly the relevant ones unlabelled.
- On NF-ToN, 21 of 24 attackers are known, yet recall is 0.017. The three unverified ones are
  enough.

**Host balancing (C3) restores NF-ToN detection (0.933), but not for the reason it was designed
for** (corrected after review):
- **The design rationale:** a persistent attacker host cannot dominate the tail.
- **What happens on NF-ToN:** 3,652 hold-out hosts have very few windows, and they score near 0.
  Equal weight per host moves the quantile into their range: T0 = 0.0055 vs C1's 0.993 (base r6),
  and 55 % of hold-out windows lie above it.
- **The recall is bought with a near-zero threshold.** FPR 34 %, twice C0.
- **On NF-UNSW (21 hosts)** 4 attacker hosts carry about 19 % of the weight, well above α, so
  C3 cannot help.
- **On NF-BoT** C3's T0 equals C1's exactly (no change).
- **Host balancing therefore hands the tail to transient hosts.** It is not a contamination
  guard on these data.
- **The finite-sample conformal correction is not applied in C3** (minor).

**Operational consequence.** As evaluated, the detector requires verified calibration-period
labels: human review of the calibration period, or a vetted clean baseline. No tested
label-free procedure keeps both detection and the false-alert budget.

**Contamination stress:**
- **Real contamination** is what C1 and C2 test: attacks present during calibration, and
  persistent attacker hosts.
- **Not tested here:**
  - gradual injected attacks;
  - long periods without recalibration beyond the domains' own spans (NF-BoT's calibration is
    211 h old at its evaluation midpoint, and its FPR is 8 %).
