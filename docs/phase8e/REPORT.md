# Phase 8e report: evidence integrity, detection reliability and streaming security

**Evidence grades** (EVALUATION_METHODOLOGY.md):
- **[M]** measured: engineering tests, or real-data checks that make no detection claim;
- **[D]** development data;
- **[R]** retrospective or post-hoc on consumed data;
- **[A]** assumption;
- **[H]** hypothesis.

Frozen results (P8 H1–H7, P8b B1–B6, P8c X1–X5) are unchanged. Phase 8e changes no verdict
and no default detection policy. The system stays detection-only.

| mission | document | code / data |
|---|---|---|
| M1 label provenance | [LABEL_PROVENANCE.md](LABEL_PROVENANCE.md) | `scripts/phase8e/label_provenance.py`, `initiator_reinterpretation.py` |
| M2 streaming robustness | [STREAMING_ROBUSTNESS.md](STREAMING_ROBUSTNESS.md) | `streaming/live.py`, `scripts/phase8e/stream_robustness.py`, `ton_stream_regression.py` |
| M3 uncertainty states | [UNCERTAINTY_STATES.md](UNCERTAINTY_STATES.md) | `inference/assessment.py` + pipeline, API, store, CLI, dashboard |
| M4 FP budgets | [FP_BUDGETS.md](FP_BUDGETS.md) | `scripts/phase8e/population_windows.py`, `fp_budgets.py` |
| M5 methodology | [EVALUATION_METHODOLOGY.md](EVALUATION_METHODOLOGY.md), [PREREGISTRATION_TEMPLATE.md](PREREGISTRATION_TEMPLATE.md) | — |
| M6 hardening | [COMPATIBILITY.md](COMPATIBILITY.md) | `scripts/phase8e/compat_check.py` |

## 1. Research findings

### M1: ToN_IoT labels (files 1-4) **[R]**

- **Composition.** Only `scanning` attacks (3,776,528 flows) and normal traffic (223,472).
  The documented attacker range 192.168.159.30-39 appears nowhere in these files.
- **Initiators.** Every attack flow has one of three initiators as an endpoint:
  192.168.1.30, .31 and .32. They are 100% attack, scan about 250 targets each and see
  S0/REJ connection states.
- **The other 37 "attack sources" are responders.** Their flows go to the scanners, from
  service ports 111/23/5800/3306/5900. They inherit the label because labels are flow-level
  and direction-agnostic.
- **Labels are time-bounded.** Scanner .30 has 67 benign flows before its attack interval.
- **NAT is not verified.** The hypothesis remains unverified.
- **Reinterpretation of the frozen X result:**
  - attacker-level counts on ToN_IoT measure "sources with attack-labelled flows";
  - every policy detected 3 of 3 initiators;
  - initiator window recall: A 0.42, C2 0.43, E 0.56;
  - responders alerted: 8/37, 7/37, 6/37 respectively.

### M4: false-positive budgets per population **[D]**

The rule was committed before the results (8b70c94). Detail: FP_BUDGETS.md.

- **No policy kept every population within budget**, so nothing was selected.
- **The never-alert reference** met every budget and was rejected by the non-degeneracy
  guard, as intended.
- **Overruns come from calibration → evaluation shift**, not from threshold allocation.
  NF-UNSW local FPR was 39% at a 1% target; single-capture global and service spikes added
  to it.
- **Per-population thresholds** cut transient-external false alarms from a median of
  5.6/h to 0.06/h. They "lose" 4 attackers that the deployed policy flagged only at a
  25% FPR in that population.
- **Sample size:** 10 attackers in total, with wide intervals.

### M5: methodology

- **Metric levels.** Seven are defined: window, device, attacker, confirmed initiator,
  incident, burden and selective coverage.
- **Coarse frozen intervals.** The 49-1 and ToN_IoT intervals rest on 4 blocks (35 distinct
  resamples). They are reinterpreted as descriptive; their verdicts are unchanged.
- **Minimum evidence standard.** It requires:
  - ≥ 10 blocks;
  - ≥ 5 positive entities for rates;
  - a provenance audit;
  - burden reported with detection;
  - more than one environment.
- **A pre-registration template** was added.

## 2. Engineering changes

| change | verification |
|---|---|
| **M2** `WindowStream` clock state machine: quarantine, pending jump, ≥ 90% trigger, ≤ 2% interleave commit, reject, backward reset, explicit health flags, idle `advance()` + IDLE marker | **[M]** 10 adversarial scenarios: before, up to 83% genuine loss and 10,800 forged records emitted; after, 0 loss, 0 forged, peak ≤ 4,270 held records. **[R]** ToN_IoT real data: identical membership in all 5,820 windows |
| **M3** `assessment` on every prediction (9 states, qualifiers, `normality_supported`, `evidence_present`, reasons). Evidence takes precedence; verdicts are unchanged | **[M]** per-state, precedence, migration, API, CLI, monitor and dashboard tests |
| **M3** telemetry health → assessment: stream flags (monitor) and offline parse errors > 1% (benign skips excluded) | **[M]** the malformed-packet fixture yields `parse_errors`; stream scenarios yield the expected flags |
| **M3** event store `assessment_state` column (migrated on open), `/events?state=`, summary state counts; replay and API flows never `normal_valid_baseline`; behaviour-only monitor reports a period assessment | **[M]** tests; pre-8e store copies migrate without row loss |
| **M6** `analyze_capture` closes its store | **[M]** compat check (previously a Windows file lock) |
| **M6** compatibility audit | **[M]** both bundles load; Phase 6 `behavior-1.0.0` calibrations are refused with the explicit "recalibrate" error (policy since Phase 7); 0 of 400 old payloads fail the schema |

**Test suite:** 203 passed, 2 deselected (gpu/slow). Lint and format are clean.

## 3. Implemented and verified vs hypothesis

**Implemented and verified:**
- streaming loses no genuine records and leaks no forged ones in the tested scenarios;
- health degradation is explicit;
- memory is bounded by the buffer and quarantine caps;
- every output carries an uncertainty state;
- "no alert" is a claim of normality only under `normal_valid_baseline`;
- pre-8e artifacts migrate or fail loudly.

**Measured but limited:**
- the ToN_IoT label structure (files 1-4 only, consumed data) **[R]**;
- the population-budget behaviour (development data, 10 attackers) **[D]**.

**Assumptions and hypotheses (not established):**
- **[A]** The 24 h `calibration_expired` limit and the 1% parse-error limit are pre-declared
  defaults, not validated ones.
- **[A]** `normal_valid_baseline` means "the validated conditions hold", not "benign":
  local-device recall at the operating threshold remained low in Phases 8b and 8c.
- **[H]** The NAT explanation for the ToN_IoT address mismatch.
- **[H]** A shift-aware policy (suppressing normality claims under drift) could meet the
  budgets.
- **[H]** The streaming defence against an attacker who knows `resync_after` and stays below
  the 90% trigger. Reasoned to degrade to bounded, visible quarantine evictions; not tested.

**Not done:**
- No new confirmatory evaluation: no fresh data was acquired.
- No new model training.
- No Docker build on this machine (CI builds it).

## 4. Risks and recommended next steps

1. **Fresh data, pre-registered with the template, is the only route to new claims.**
   - The highest-value test is a second network with a confirmed-initiator list.
   - It would measure `normal_valid_baseline` coverage and recall at the window and initiator
     levels.
2. **Calibration shift is the binding problem**, not threshold allocation (M4, Phase 8d).
   - Next work belongs in drift detection and recalibration.
   - More threshold variants are unlikely to help.
3. **Operators should read `normality_supported_share`** before treating a quiet period as
   clean.
