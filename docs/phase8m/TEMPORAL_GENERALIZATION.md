# Phase 8m: temporal stress (descriptive)

**Source:** `reports/phase8m/model_comparison.json`, fields `per_domain.<variant>.<domain>.<seed>`:
`by_age` and `by_host_seen`.

**Label:** EXPLORATORY and descriptive (PREREGISTRATION.md section 5). No decision rests on it.
Values are seed means; for NF-CIC they are the mean over its 6 days.

## Calibration age

Age is the time since the end of calibration. Verified-benign FPR / attack-window recall:

| network | age (h) | benign windows | B0 | B2 | B1u |
|---|---|---|---|---|---|
| NF-ToN-IoT | 0–1 | 88 | 0 % / 0.63 | 0 % / 0.00 | 0 % / 0.00 |
| | 1–6 | 252 | 0 % / 0.96 | 0.4 % / 0.47 | 0 % / 0.30 |
| | 6–24 | 3,443 | **22.4 %** / 0.96 | 0.35 % / 0.69 | 0 % / 0.24 |
| | 24–72 | 3,554 | 8.5 % / 0.15 | 2.3 % / 0.23 | 0 % / 0.00 |
| | > 72 | 110 | 29.4 % / 0.73 | 22.7 % / 0.31 | 0 % / 0.00 |
| NF-CIC | 0–1 | 26,355 | 1.09 % / 0.49 | 0.98 % / 0.12 | 0.93 % / 0.01 |
| | 1–6 | 81,942 | 1.35 % / 0.68 | 1.04 % / 0.14 | 1.08 % / 0.00 |
| NF-UNSW | 0–1 / 1–6 / 6–24 | 1,326 / 6,727 / 3,884 | 4.0 / 3.2 / 4.4 % ; recall 0.98 / 0.97 / 0.97 | 3.0 / 2.6 / 3.8 % ; 0.38 / 0.90 / 0.89 | 3.4 / 2.8 / 4.1 % ; 0.50 / 0.49 / 0.48 |
| NF-BoT-IoT | > 72 | 620 | 11.9 % / 0.88 | 26.3 % / 0.43 | 29.5 % / 0.73 |

**NF-ToN-IoT**
- **Age is where staleness shows.** B0's FPR is 0 % in the first 6 hours and 22 % at 6–24 h.
- **B2 removes most of that rise,** but its recall is lower at every age.
- **B1u, which learns every destination at once,** has no false alerts at all, and recall of at
  most 0.30 at any age.
- **The FPR rise with age is not monotone** (22 % → 8.5 % → 29 %); the bins differ in host mix.

**NF-CIC.** Each day covers only 0–6 h after calibration, so it cannot show long-horizon staleness.

## Hosts seen in calibration vs hosts first seen after it

**Corrected after review: the recall column of this split is not valid.**
- "Seen" means present in the P1x calibration windows, and P1x removes calibration-period
  attackers from them.
- So evaluation attackers that were active in calibration count as "new": NF-ToN-IoT 12 of 13,
  NF-BoT 8 of 8, NF-UNSW 4 of 4.
- The FPR column (verified-benign hosts, which never attack) is unaffected.

Verified-benign FPR / attack-window recall:

| network | hosts | benign windows | B0 | B2 | B1u |
|---|---|---|---|---|---|
| NF-ToN-IoT | seen | 5,186 | 8.7 % / 0.00 | 0.7 % / 0.00 | 0 % / 0.00 |
| | new | 2,261 | **29.0 %** / 0.61 | 3.8 % / 0.45 | 0 % / 0.14 |
| NF-CIC | seen | 86,521 | 1.48 % / 0.09 | 1.22 % / 0.00 | 1.24 % / 0.00 |
| | new | 21,776 | 0.48 % / 0.58 | 0.18 % / 0.11 | 0.19 % / 0.01 |
| NF-BoT-IoT | seen / new | 615 / 5 | 11.8 % / 20 % | 26.6 % / 0 % | 29.7 % / 0 % |
| NF-UNSW | seen | 11,937 | 3.7 % | 3.0 % | 3.3 % |

**What the valid FPR column shows: the effect of new hosts differs by network.**
- On NF-ToN-IoT, B0's FPR is 29 % on new hosts against 8.7 % on hosts seen in calibration.
- B2 lowers it to 3.8 % on new hosts, at the recall cost shown in MODEL_COMPARISON.md.
- On NF-CIC the pattern is reversed: B0's FPR is 0.48 % on new hosts against 1.48 % on seen hosts.
