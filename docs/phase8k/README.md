# Phase 8k: calibration reliability and selective detection

**Status (2026-11-02):** design, development experiments and a frozen-candidate confirmatory
protocol are complete. The protocol was independently audited, and every finding was fixed before
the freeze. **No fresh data has been downloaded or opened. Phase 8j's registered
NO-GO is preserved unchanged.** Everything here is development-only [E].

**Question.** Can a detector identify when its target-network calibration is trustworthy,
abstain when it is not, and still keep useful attack detection where it operates?

| document | contents |
|---|---|
| [RESEARCH_DESIGN.md](RESEARCH_DESIGN.md) | adequacy prediction vs conditional detection; decision-time information; methods M0–M4 and controls; the new evaluation protocol |
| [DATASET_INDEPENDENCE.md](DATASET_INDEPENDENCE.md) | 4 development networks from 2 institutions; no further local network; F1/F2 re-verified; licences; compute |
| [DEVELOPMENT_EXPERIMENTS.md](DEVELOPMENT_EXPERIMENTS.md) | source-aware calibration ablation; why calibrations fail; network decisions; stress tests |
| [PREREGISTRATION.md](PREREGISTRATION.md) | K1 (primary, M1), K2, K3 (M2); units, criteria, NOT EVALUABLE conditions; order of work |
| [AUDIT.md](AUDIT.md) | the independent audit, statistical and reproducibility checks, chronology |
| [FREEZE_CANDIDATE.md](FREEZE_CANDIDATE.md) | commit and SHA-256 of every frozen file |

## Findings [E]

1. **Source-aware (host-balanced) calibration does not help.** The operational FPR is counted
   over windows, so equal host weights calibrate for the wrong quantity. FPR rises on every
   NF-CIC day and reaches 33.7% on NF-ToN-IoT. Pooling all calibration windows lowers FPR, but
   rescues neither NF-ToN-IoT nor N4, and costs recall.
2. **Calibrations fail for three different reasons:**
   - small calibration (NF-UNSW);
   - population turnover (NF-ToN-IoT: 61% of false alerts from hosts the calibration never
     saw);
   - dominant-host change (N4: 98% of false alerts from one seen host whose score tail moved
     over 13 days).

   Only the first is visible at decision time.
3. **Calibration-only decision rules catch small calibrations, not drift.**
   - The PAC rule (M2) and its temporal-consistency variant (M3) falsely accept NF-ToN-IoT.
   - The fixed checks (M1) separate all 4 networks, but they were designed on them.
   - In stress tests every rule rejects about 94% of adequate small calibrations.
4. **A learned network-level reliability classifier is not supportable:** 4 units, 2
   institutions, 1 adequate network.

## Recommendation: NOT EVALUABLE

The primary question, whether calibration reliability can be assessed usefully *across
networks*, cannot be answered with the data in hand:
- development has 4 networks from 2 institutions, and the one rule that separates them was
  designed on them;
- the untouched fresh families give about 13 correlated units in 2 emulated environments, with
  few hosts per network.

The prior expectation, written into the pre-registration before any download, is that M1
rejects most fresh units. That would make discrimination NOT EVALUABLE or fail on false
rejection.

**The only justified next step** is the pre-registered feasibility gate:
- download the two probes (24.5 MB), map the telemetry, and count calibration hosts;
- a full confirmation is worth running only if the probes show ≥ 10 calibration hosts per
  unit;
- every step needs your authorization.

**Not recommended:** building more methods on the same 4 networks.

**What would change the answer:** a source of many genuinely independent networks with
verified benign hosts. For example: several organisations' own traffic with scheduled,
authorised red-team exercises, or a much larger public multi-institution corpus.
