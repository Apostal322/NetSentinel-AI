# Phase 8f report: drift-aware calibration and independent validation

**Evidence grades** (Phase 8e methodology):
- **[M]** engineering measurement / test;
- **[D]** development data;
- **[R]** post hoc on consumed data;
- **[A]** assumption;
- **[H]** hypothesis.

**Unchanged in Phase 8f:**
- the deployed detection policy, the 8e assessment rules and every frozen result;
- every verdict and alert (no alert is suppressed);
- the system is detection-only.

| mission | document | code / data |
|---|---|---|
| plan (pre-declared) | [PLAN.md](PLAN.md), commit 84e47ad | — |
| M1 calibration failure diagnosis | [SHIFT_DIAGNOSIS.md](SHIFT_DIAGNOSIS.md) | `scripts/phase8f/shift_diagnosis.py` |
| M2 shift-aware confidence | [CALIBRATION_VALIDITY.md](CALIBRATION_VALIDITY.md) | `behavior/validity.py`, `scripts/phase8f/validity_eval.py` |
| M3 + M5 recalibration, operational reliability | [RECALIBRATION.md](RECALIBRATION.md) | `scripts/phase8f/recalibration_sim.py` |
| M4 streaming robustness | [STREAMING_8F.md](STREAMING_8F.md) | `streaming/live.py`, `scripts/phase8f/stream_near_trigger.py` |
| M6 independent data protocol | [INDEPENDENT_VALIDATION_PROTOCOL.md](INDEPENDENT_VALIDATION_PROTOCOL.md) | — (not run) |
| M7 integration, M8 audit | this report | CLI, calibrate, monitor |

## 1. Research findings

### Why calibration shift inflates false positives (M1, [D])

- **Concentration.** The inflation is concentrated: pooled device FPR is 2.5%, or **0.35%**
  without the NF-UNSW development part.
- **Mechanism.** 385 of 428 false alerts come from sources seen in calibration with too few
  windows, scored against the pooled fallback (the Phase 8c mechanism, now quantified).
- **Correlate.** The share of evaluation windows from unseen entities is the strongest
  correlate across captures (ρ = 0.54, n = 21).
- **Shape of the shift.** It is in the feature tails, not the medians. No single feature is
  responsible: dropping any one changes false alerts by at most −22 of 428.
- **Non-causes.** Profile age within a capture, traffic intensity and calibration sample size
  showed no association.
- **Contamination** costs recall, not FPR. On 3-1 the threshold rose 3.4× and recall fell
  from 0.51 to 0.003, with no false-alarm symptom.

### Shift-aware confidence (M2, [D])

- **The new block-permutation shift test is statistically sound on these data.**
  - 0/16 false confirmations on interleaved calibration halves.
  - Segments it calls valid have 0.09% realised FPR, against 3.0% in flagged segments (33×).
- **It fails C4, and the full assessor also fails C3, under the pre-declared rule.**
  - Too many benign segments are untestable or genuinely shifted.
  - The precedence of `unreliable_threshold` hides the shift signal.
- **Not adopted for display.** It ships only as an opt-in shadow diagnostic.
- **The existing `baseline_state` remains the drift signal.** It passed C2–C4 (C1 not
  measured for it).
- **Wording.** A statistical shift is never presented as a benign change. Both drift signals
  fire mostly on attack segments.

### Recalibration (M3/M5, [D])

- **No deployable strategy met the success rule.**
- **Unvetted refresh hides attacks.** Periodic and drift-triggered refitting cut false alerts
  by learning the attacks: window recall 0.27 → 0.05 / 0.03.
- **Neither the current baseline's filter nor its validation gate can see what it misses.**
  The gate still absorbed 505 windows of a sustained sub-threshold attack.
- **Only vetted refresh improves reliability without hiding attacks.** The oracle-vetted
  refresh halved false alerts and lost no attacker.
- **Unlabelled (contaminated) calibration is the most damaging condition.** 4/10 attackers,
  0.6% window recall.

### Streaming (M4, [M])

- **Near the 90% trigger** (85–95% forged, oscillating, repeated cycles, sustained for 3 h,
  backward), nothing is lost, nothing forged is emitted, memory is bounded and health is
  explicit.
- **A silent vulnerability was found and fixed.** A single forged record inside the skew range
  dropped 82% of genuine traffic with health `ok`. The clock now needs a majority of recent
  records (median of 101): 0 loss, −18% throughput (244k records/s).
- **Real-data regression [R]:** the consumed ToN_IoT input (4M records, a genuine 460 h gap)
  gives identical record membership in all 5,820 windows. Counts: 0 late, 2 resyncs, 3,791
  replayed, 0 `uncorroborated_ahead`. Run time 3 min, peak 1.36 GB
  (`reports/phase8f/ton_stream_regression.json`).

## 2. Engineering changes and verification

| change | verification |
|---|---|
| `behavior/validity.py`: reference blocks, max-T block permutation, Holm, statuses and wording | **[M]** 8 unit tests: null level, tail and composition shifts, label alignment, untestable, Holm and merge, status precedence and mapping |
| calibration schema `behavior-1.2.0` with a validity reference; 1.1.0 still loads (shift test untestable); `parent_calibration` lineage; `calibration list` shows parent, period end, threshold reliability, reference blocks | **[M]** `test_validity_integration.py` (including a 1.1.0 artifact) |
| `analyze` / `monitor --validity-shadow`: labelled shadow output, default output unchanged | **[M]** monitor and analyze outputs identical with and without the flag, apart from the shadow block |
| `WindowStream` corroborated clock (`clock_quorum`), `uncorroborated_ahead` counter | **[M]** 12 parametrised near-boundary tests plus 2 targeted tests (the pre-8f clock reproduces the silent loss); all 8e scenarios unchanged |
| threat model T15 updated | — |

**Not integrated, by the pre-declared rule:**
- the shift test in the API, event store, dashboard and Phase 8e assessment;
- automatic recalibration of any kind.

The displayed signals already show when normality is not supported (Phase 8e
`normality_supported`, `drift_detected` from `baseline_state`).

**Final checks:**
- 229 tests pass, 2 deselected (gpu/slow); ruff lint and format are clean; the dependency
  gate is OK.
- CI (lint, tests, Docker build and smoke, pip-audit) runs on the push.
- The intermittent `test_demo` failure noted in Phase 8c now has a cause. CPython 3.12's
  `platform.platform()` raised on a Windows WMI timeout (`WinError 258`, then
  `KeyError: 'Architecture'`) inside the run ledger. Fixed (`ledger.platform_string`), with a
  regression test.

## 3. Implemented and verified vs not established

**Verified [M]:**
- the in-skew watermark fix;
- the near-trigger behaviour;
- the shadow diagnostic changes no detection output;
- the 1.1.0 calibration compatibility;
- lineage recording.

**Measured on development data only [D]:**
- every M1, M2 and M3 number.

The development set is dominated by one dataset (NF-UNSW: 90% of false alerts). It has 10
"attackers" (originators of labelled flows, not verified initiators) and no independent test.

**Not established:**
- **[H]** That vetted periodic refresh generalises (it rests on an oracle).
- **[H]** That the shift test would pass C4 elsewhere.
- **[A]** The 24 h expiry.
- **[A]** The KS 0.3 rule inside `baseline_state`. It worked here but has no rationale.

**Blocker:** no independent dataset with verified initiators is available locally. M6 prepares
the protocol; running it needs an approved download.

## 4. Recommendations

1. **Approve one dataset** for INDEPENDENT_VALIDATION_PROTOCOL.md: CTU-13, or an authorised
   red-team exercise on the target network. Every Phase 8f [D] claim stays provisional until
   then.
2. **Make vetting cheap.** Vetting is the only lever that improved reliability. A
   review-and-assert workflow for candidate baselines (the operator marks benign periods) is
   more promising than any automatic refresh.
3. **Redesign the validity precedence** (threshold reliability vs shift) as a new
   pre-registered variant, tested on independent data. Do not re-read the present results.
