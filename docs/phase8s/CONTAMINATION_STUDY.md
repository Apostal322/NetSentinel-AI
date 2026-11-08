# Phase 8s Experiment D: review under contamination and reviewer error

**Status:** REGISTERED (PREREGISTRATION §§ 4, 7). k = 30, 20 draws, C1. All reviewers are
SIMULATED: their error rates are assumptions, not measured analyst performance.

| reviewer | model |
|---|---|
| R0 | perfect |
| R1 | inconclusive 10 %; false benign 10 %; false malicious 2 %; host-level, so errors are perfectly correlated within a host |
| R2 | missing-not-at-random: inconclusive 40 % for hosts above the 90th activity percentile (10 % otherwise); false benign 25 %; false malicious 2 % |

**Three kinds of contamination are kept separate:**
- **The unlabelled candidate pool** is the real development data: calibration-attacker share
  0–10 % on NF-CIC, 29 % on NF-UNSW, 76 % on NF-ToN, 92 % on NF-BoT (Phase 8r).
- **Reviewer outcomes** follow the reviewer's error model.
- **The vetted-benign set's contamination** is HT-weighted.

**Decision H4** (PPS + C1 under R1: median trusted-set contamination ≤ 1 % on every network, and
criterion (ii)): **NOT SUPPORTED.**

## Results (PPS + C1 unless stated)

| network | R0 recall / FPR | R1 recall / FPR | R2 recall / FPR | median trusted contamination, R1 |
|---|---|---|---|---|
| NF-CIC | 0.495 / 1.7 % | 0.493 / 1.8 % | 0.498 / 2.0 % | 0 |
| NF-UNSW | 0.562 / 3.8 % | 0.378 / 3.2 % | 0.299 / 2.9 % | 0 |
| NF-ToN | 0.706 / 20.1 % | **0.409 / 11.6 %** | 0.304 / 9.5 % | **23 %** |
| NF-BoT | 0.934 / 9.0 % | 0.934 / **14.9 %** | 0.933 / 14.1 % | **20 %** |
| macro | 0.674 | 0.554 | 0.509 | — |

**Mechanisms:**
- **On the attack-dominated networks the designs that reach the benign tail also reach the heavy
  attackers.**
  - PPS reviews about 13 NF-ToN attackers per draw.
  - With a 10 % false-benign rate, one accepted heavy attacker contributes thousands of
    windows. The median trusted set is about 23 % attack windows, which drives the threshold up
    and recall down.
- **Missing-not-at-random review (R2) loses the heavy benign hosts that carry the tail.**
  - On NF-BoT, losing or misjudging one of the 7 benign hosts moves FPR from 9.0 % to 14 %.
- **Random-host review is barely affected (NF-ToN 46 % → 52 % FPR), because it rarely reaches the
  attackers. It is robust only because it is uninformative.**

**Auxiliary triage value** (kept separate from the calibration outcome):
- per draw, PPS finds about 13 malicious NF-ToN hosts and about 8 of NF-BoT's attackers;
- this is review output a SOC could use, but it is not evidence for calibration.

**Not covered:**
- Injected attack mechanisms (persistent, coordinated, burst, service-matched) were measured in
  Phase 8r Experiment B on trusted sets, and are not repeated here.
- "New benign hosts" and "service drift" are covered only through the temporal split
  (TEMPORAL_STABILITY).
