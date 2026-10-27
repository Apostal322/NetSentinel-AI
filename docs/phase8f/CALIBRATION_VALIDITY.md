# Calibration validity and shift-aware confidence (Phase 8f, Mission 2)

- Code: `src/netsentinel/behavior/validity.py`. The reference is built in
  `behavior/profile.py` and stored with every new calibration (schema `behavior-1.2.0`).
- Evaluation: `scripts/phase8f/validity_eval.py` → `reports/phase8f/validity_eval.json`.
- Rule: [PLAN.md](PLAN.md) section 2, committed before any result (84e47ad).
- **[D]** All results are development data.

## What the assessor does

**Validity statuses**, by precedence:
1. `degraded_telemetry`
2. `insufficient_history`
3. `expired`
4. `unreliable_threshold`
5. `confirmed_shift`
6. `possible_shift`
7. `valid`

Every condition that holds is listed. Design rationale (thresholds included) is in PLAN.md:
- 5 min blocks: more than 3× the measured decorrelation lag;
- |z| > 3 tails;
- max-T block permutation over 12 feature-tail rates plus the pooled-fallback share;
- Holm across levels;
- α = 0.01, the same as the existing update gate;
- ≥ 10 blocks on each side, from the evidence standard.

**Wording.** A `confirmed_shift` is reported as "a statistical inconsistency between the
scored period and the calibration; not by itself evidence of a benign change or of an
attack". The assessor never changes a verdict or an alert.

## Results (1 h segments of 22 development captures; 123 segments)

| comparator | segments not flagged: pooled benign FPR (Wilson 95%) | flagged: pooled FPR | flagged / not flagged | benign-only segments not flagged |
|---|---|---|---|---|
| A1 age only (24 h) | 2.51% [2.29, 2.76] (nothing expires within these captures) | — | — | 1.00 |
| A2 existing `baseline_state` (global alert rate or KS > 0.3) | 0.15% [0.06, 0.35] (47 segments) | 3.07% (66) | 20.8× | **0.64** |
| A3 full assessor | 0.20% [0.08, 0.51] (37) | 0.07% (`confirmed_shift`, 49) | 0.37× | 0.36 |
| A3s shift test alone | 0.09% [0.02, 0.33] (43) | 3.00% (62) | **33×** | 0.36 |

| criterion | A3 | A3s | A2 |
|---|---|---|---|
| C1 null (interleaved calibration halves, 16 captures): `confirmed_shift` ≤ 5% | **0/16** | **0/16** | not applicable (no permutation test; not measured) |
| C2 not flagged ⇒ FPR ≤ 2% | pass | pass | pass |
| C3 flagged ≥ 2× not flagged | **fail** (0.37×) | pass (33×) | pass (20.8×) |
| C4 ≥ 50% of benign-only segments not flagged | **fail** (0.36) | **fail** (0.36) | pass (0.64) |

**Outcome under the pre-declared rule:**
- The new assessor is **not adopted for display**. It does not feed the Phase 8e
  assessment, the API, the event store or the dashboard.
- It is available only as an opt-in, labelled shadow diagnostic: `analyze --validity-shadow`
  and `monitor --validity-shadow`. That output says "not adopted, changes nothing", and tests
  check that detection output is unchanged.
- The existing `baseline_state` (A2) remains the displayed drift signal. It passed C2–C4 on
  these data, although its KS 0.3 cut-off was never given a rationale.

## Why it failed (descriptive, post hoc **[R]**)

1. **C3 (full assessor) is a precedence effect.**
   - The NF-UNSW segments carry most of the false alerts. They are classified
     `unreliable_threshold` first, because the device threshold diagnostics are unreliable.
   - So the remaining `confirmed_shift` segments are mostly IoT-23 attack segments, with few
     false alarms.
   - The shift test itself separates well (A3s: 33×).
2. **C4 is driven by untestable short segments and by real benign shifts.**
   - Of the 16 non-valid benign-only segments, 9 were untestable: 8 were short final
     segments with fewer than 10 blocks.
   - 4 were confirmed shifts in benign CTU-Normal traffic, mostly at the service level. They
     came with zero false alerts: the distribution moved without moving the alert rate.
   - Post hoc, without the untestable segments, the A3s valid share would be 9/16 = 0.56. This
     is not used for any decision.
3. **Attack sensitivity.** 51 of the 62 A3s `confirmed_shift` segments contain attack windows,
   and so do 49 of 66 A2 flags. Both statistics respond to attacks. That is why a shift is
   never presented as a benign change, and why it must never suppress alerts (Phase 8d).

## Cost

- 0.14 s median per 1 h segment for the shift test (0.23 s max; 999 permutations).
- Peak memory of the evaluation: 170 MB.
- The reference adds about 15 integers per 5 min calibration block and level to the profile.

## What would change the decision

- V2 of [INDEPENDENT_VALIDATION_PROTOCOL.md](INDEPENDENT_VALIDATION_PROTOCOL.md): C1–C4 on a
  genuinely independent environment.
- A redesign of the precedence (separating threshold reliability from shift) would be a new
  pre-registered variant. It is not a re-reading of these results.
