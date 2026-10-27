# Phase 8f pre-declaration: calibration validity, recalibration, evaluation

> **Committed before any assessor or recalibration result was computed.** M1 (SHIFT_DIAGNOSIS.md)
> is development exploration and informed the design below. All evaluation data are development
> data **[D]**; no consumed capture is read. Nothing here changes the deployed detection policy.

## 1. Calibration-validity assessor (Mission 2)

### Reference stored at calibration time (per level)

- Cross-fit held-out windows, grouped into blocks of **10 windows** (5 min). M1: the
  autocorrelation falls below 0.1 at lag 3, so 10 is more than 3× that lag.
- Per block, the reference keeps:
  - windows;
  - windows with |z| > 3, per feature (12 features);
  - windows scored by the pooled fallback.
- |z| > 3 is the conventional robust-outlier cut. Held-out tail mass at that cut is about
  2–7% per feature, enough to estimate per block.
- Calibrations without a reference (behavior-1.1.0) still load. The shift test is then
  reported as `untestable`.

### Test

- **Statistics** for a scored period, per level:
  - the 12 per-feature tail rates;
  - the pooled-fallback share.
- **Max-T block permutation.** Each statistic is a two-sample difference of block means,
  standardized by the pooled block SD. The permutation statistic is the maximum over the 13,
  which controls the family-wise error across them. 999 permutations; a fixed seed per call.
- **Holm** across the levels present (global, device, service).
- **Minimum blocks:** ≥ 10 blocks on each side (the Phase 8e evidence standard). Otherwise
  the test is `untestable`.

### Validity status (single, by precedence) and conditions (all that hold)

| status | condition | rationale |
|---|---|---|
| `degraded_telemetry` | telemetry health is not `ok` | Phase 8e M2/M3 |
| `insufficient_history` | profile status not alerting, or < 10 reference blocks | evidence standard |
| `expired` | > 24 h after the calibration period | Phase 8e default (pre-declared, not validated) |
| `unreliable_threshold` | a level's threshold diagnostics are unreliable, or tail-dominated (Phase 8c) | Phase 7 / 8c diagnostics |
| `confirmed_shift` | Holm-adjusted p < **0.01** at any level | same α as the existing update gate and drift test |
| `possible_shift` | unadjusted p < 0.05 at any level, but not confirmed | conventional; shown as a caution only |
| `valid` | none of the above | — |

**Wording.**
- `confirmed_shift` means the scored period is statistically inconsistent with the
  calibration. It is **not** evidence of either a benign change or an attack.
- The assessor never changes a verdict or an alert.
- Mapping to the Phase 8e assessment:
  - `confirmed_shift` → `drift_detected`;
  - `expired` → `calibration_expired`;
  - `insufficient_history` / `unreliable_threshold` → `insufficient_calibration`;
  - `degraded_telemetry` → `telemetry_degraded`;
  - `possible_shift` → a reason only. Its uncorrected 5% level across up to 3 levels would
    flag about 14% of stationary periods.

## 2. Assessor evaluation and success criteria

- **Units:** 1 h evaluation segments (120 windows = 12 blocks) of every development capture.
- **Outcomes, from labels only:** the benign-window realised FPR at the device level (the
  deployed policy), and whether the segment contains attack windows.
- **Comparators:**
  - A0: always valid;
  - A1: age expiry only;
  - A2: the existing `baseline_state` (global alert-rate binomial or KS > 0.3);
  - A3: the new assessor.

| criterion | requirement |
|---|---|
| C1 null calibration | interleaved odd/even calibration blocks of every capture: share `confirmed_shift` ≤ 0.05 (nominal 0.01) |
| C2 valid means reliable | pooled benign FPR in segments assessed `valid` ≤ 2% (2× target), Wilson interval reported |
| C3 informative | pooled benign FPR in `confirmed_shift` segments ≥ 2× that in `valid` segments |
| C4 not abstain-everything | among benign-only (CTU-Normal) segments, the `valid` share is ≥ 0.5 |

- A3 is adopted for display (Mission 7) only if C1–C4 hold.
- In every case, it never alters alerts.
- Attack segments flagged as shift are reported descriptively. They are expected, and they
  are not a success or a failure.

## 3. Recalibration strategies (Mission 3)

**Simulation.** Each development capture's evaluation timeline is cut into 1 h segments. A
strategy may replace the baseline at a segment boundary, using only the windows seen so far.
Every new baseline is versioned, so the previous one can be restored (rollback).

| strategy | rule |
|---|---|
| S1 fixed | the clean calibration, never changed. The **Phase 8e negative-result baseline**, required. |
| S2 periodic | every 2 h, refit on the last 2 h of evaluation windows, unfiltered. 2 h: Phase 8d FPR rose within 2–4 h. |
| S3 drift-triggered | after a segment with `confirmed_shift`, refit on that segment (unfiltered) |
| S4 conservative | every 2 h, refit on the last 2 h, keeping only windows that are not anomalous under the current baseline and below the update gate's strong-outlier rule (2× the held-out maximum). Unlabelled. |
| S4o oracle-vetted | as S4, but only label-benign windows. An upper bound for "vetted benign observations"; not deployable. |
| S5 candidate + validation | every 2 h, build a candidate as in S4. Activate only if `update_check` passes (no rate review, no strong outlier) **and** the candidate's own threshold is reliable. Otherwise keep the current baseline and record `review_required`. |

**Common rules:**
- Suspicious windows are never absorbed silently. S2 and S3 absorb by design; they are the
  contrast that measures this.
- Drift never suppresses an alert.
- **Robustness to contamination:** S1 and S5 are also run from the *unlabelled* calibration.

## 4. Operational metrics (Mission 5)

Per strategy, pooled over captures:
- false alerts per hour: median and max over captures with ≥ 1 h of evaluation;
- window recall;
- attackers detected. On IoT-23 an attacker is the originator of attack-labelled flows; no
  development capture has a verified initiator list;
- median detection delay;
- coverage. No strategy abstains, so coverage is 1 by construction; the assessor's `valid`
  share is reported instead;
- calibration validity: the share of segments `valid`;
- attack windows absorbed into a baseline (contamination);
- false-negative cost: missed attack windows × c + false alerts, for c ∈ {10, 100};
- CPU time per refit and peak memory.

**Success, for "calibration becomes more reliable without hiding attacks".** A strategy
succeeds only if, against S1:
1. pooled FA/h is lower;
2. no attacker is lost;
3. window recall is ≥ 0.9 × S1's;
4. absorbed attack windows are ≤ 1% of attack windows.

If no deployable strategy (S2–S5) succeeds, that is the result. **No default changes** in
either case: confirmatory evidence needs the independent protocol (Mission 6).
