# Safe recalibration and operational reliability (Phase 8f, Missions 3 and 5)

- Simulation: `scripts/phase8f/recalibration_sim.py` → `reports/phase8f/recalibration.json`.
- Rule: [PLAN.md](PLAN.md) sections 3–4, committed before the run.
- **[D]** Development data: 22 captures, device level, 1 h segments.
- An "attacker" on IoT-23 is the originator of attack-labelled flows. No development capture
  has a verified initiator list, so confirmed-initiator recall is **not available** here
  (INDEPENDENT_VALIDATION_PROTOCOL.md V3).

## Results

| strategy | FA/h pooled (max per capture) | window recall | attackers (Wilson 95%) | absorbed attack windows (share) | activations / reviews | segments valid (shift test) | cost c = 10 / 100 |
|---|---|---|---|---|---|---|---|
| **S1 fixed (8e baseline)** | 3.81 (46.2) | 0.269 | 9/10 [0.60, 0.98] | 0 | 0 / 0 | 0.41 | 63,658 / 632,728 |
| S2 periodic, unfiltered | 1.96 (22.3) | **0.047** | 8/10 | **8,224 (95%)** | 45 / 0 | 0.60 | 82,660 / 824,620 |
| S3 drift-triggered | 0.83 (8.4) | **0.030** | 7/10 | **1,753 (20%)** | 19 / 0 | 0.79 | 83,973 / 838,893 |
| S4 conservative (unlabelled filter) | 2.23 (24.7) | 0.248 | 8/10 | **5,841 (68%)** | 39 / 0 | 0.59 | 65,311 / 650,851 |
| S4o oracle-vetted (not deployable) | **1.88 (20.8)** | **0.288** | **9/10** | **0** | 29 / 0 | 0.43 | **61,811 / 616,211** |
| S5 candidate + gate | 3.80 (46.2) | 0.269 | 9/10 | 505 (5.8%) | 13 / 32 | 0.50 | 63,677 / 632,927 |
| S1u fixed, unlabelled calibration | 2.96 (35.4) | **0.006** | **4/10** | 0 | 0 / 0 | 0.67 | 86,332 / 860,332 |
| S5u gated, unlabelled start | 2.44 (28.9) | 0.025 | 5/10 | 4,256 (49%) | 23 / 22 | 0.63 | 84,624 / 843,774 |

- **Medians:** the median FA/h per capture is 0–0.08 for every strategy. The pooled and maximum
  figures come from NF-UNSW and one short capture.
- **Delay:** median detection delay is 0 s for every refitting strategy and 510 s for S1/S5.
  The detected attacker sets differ, so delays are not directly comparable.
- **Cost:** one refit takes at most 0.34 s. Peak memory of the simulation is 172 MB.

## Rule outcome: **no deployable strategy succeeds**

The success rule requires all four of: lower FA/h, no attacker lost, window recall ≥ 0.9 × S1,
and absorbed attack windows ≤ 1%.

| strategy | lower FA/h | no attacker lost | recall ≥ 0.9 × S1 | absorbed ≤ 1% |
|---|---|---|---|---|
| S2 | yes | no | no | no |
| S3 | yes | no | no | no |
| S4 | yes | no (NF-UNSW −2, 21-1 +1) | yes | no |
| S5 | yes, marginally (3.80 vs 3.81) | yes | yes | **no (5.8%)** |

## What it means

1. **Refitting on unvetted traffic hides attacks.**
   - Periodic (S2) and drift-triggered (S3) recalibration cut false alerts by learning the
     attacks: recall fell 83–89%, and 20–95% of attack windows entered a baseline.
   - Drift-triggered refitting is the worst case: the shift *is* the attack in most
     triggered segments (CALIBRATION_VALIDITY.md).
2. **Filtering by the current baseline is not vetting.**
   - S4 keeps window recall (0.248) but absorbs 68% of attack windows: those the current
     baseline already scores below threshold.
   - It loses two attackers on NF-UNSW (and gains one on 21-1).
3. **A validation gate built on the current baseline cannot see what that baseline misses.**
   - S5 rejected 32 of 45 candidates and behaves like S1.
   - It still absorbed 505 windows of the sustained 34-1 attack, which S1 detects at 1%
     window recall.
   - The gate protects against bursts (Phase 8 update gate), not against persistent
     low-signal attacks.
4. **Vetted refresh is what helps.**
   - The oracle (S4o) halves pooled false alerts, keeps 9/10 attackers, raises recall and has
     the lowest cost.
   - Vetting needs an operator or a trusted source of benign periods. NetSentinel can require
     and record it (`--assert-benign`, review-before-activate); it cannot automate it.
5. **Contaminated calibration is the most damaging condition measured.**
   - S1u drops to 4/10 attackers and 0.6% window recall, without any FPR symptom.
   - The gate (S5u) does not repair it.

## Product consequences (implemented)

- **No automatic recalibration** was added. Calibration stays an explicit `calibrate` run:
  the operator's benign assertion, the update gate, review before activation, and rollback
  (`calibration rollback`).
- **Lineage.** New manifests record `parent_calibration` (the baseline the update gate
  compared against). `calibration list` shows the parent, period end, device-threshold
  reliability and validity-reference blocks.
- **Drift never suppresses an alert.** The drift and validity states change only the
  assessment (Phase 8e rule).
