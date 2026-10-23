# Phase 8c external validation results: ToN_IoT (UNSW Canberra testbed)

- Plan: [EXTERNAL_VALIDATION_PLAN.md](EXTERNAL_VALIDATION_PLAN.md), frozen in `590f8d2`.
  Deviation D1 (UTF-8 BOM in the adapter, a software fix before any analysis) is documented
  there.
- Run: `scripts/phase8c/confirm_external.py` at `e7791de`.
- Raw output: `reports/phase8c/confirm_external_toniot.json` and `.log`.
- Cost: 17.4 min; peak RSS 3.29 GB inside the process (the external watchdog sampled 3.02 GB;
  limit 3.4 GB).

## The data, as found

- `Network_dataset_1-4.csv` (official source; hashes in DEVELOPMENT_LOG section 4): 4,000,000
  records.
- **Time structure.**
  - The midpoint split put 47 h of benign-only traffic into calibration: 183,599 flows, 0
    attack flows.
  - Then there is a **460-hour gap**.
  - Evaluation is **4 hours of data** (within a 15 h span): 3,797,795 flows, 99.4% labelled
    attack.
  - Device windows: 28,493 calibration; evaluation 1,352 attack and 1,377 benign. 40 source
    addresses carry attack flows.
  - Testable.
- **Streaming.**
  - 18,606 exact duplicate rows were dropped by the pre-registered deduplication (0.5%).
  - 0 late records.
  - The 460 h gap froze the watermark clock (software defect, see below), so 334 windows were
    force-closed at the 1.5M buffer cap. Because no record arrived late, no evidence was lost.
- **Tail diagnostic:** `tail_fallback_share` 0.08, no warning. The Phase 8b failure mode
  (transient external sources owning the threshold) is **absent** here.

## Pre-registered verdicts

| | Hypothesis | Result | Verdict |
|---|---|---|---|
| **X1** | deployed FPR <= 3x target | FPR **8.9%**, CI [7.4, 10.5]% (0.47 false alerts/h: few windows per hour) | **refuted** |
| **X2** | root-cause prediction: no warning, so C2 and A differ by <= 0.05 recall | diagnostic silent; window recall A 0.317 vs C2 0.314; attackers 11 vs 10 of 40 | **supported** |
| **X3** | LightGBM (trained without any UNSW data) PR-AUC > robust_z | 0.973 vs 0.695; delta 0.278, CI [0.136, 0.425] | **supported** |
| **X4** | LightGBM adds ranking beyond the scan signature (new_dst_frac) | delta 0.147, CI [0.035, 0.262] | **supported** |
| **X5** | incidents: window-weighted purity >= 0.8 and reduction >= 5 | purity **0.779**, reduction 11.2 (49 incidents, 22 single-window) | **refuted** (purity just below 0.8) |

**Uncertainty caveat.** The evaluation data fall into only **4** one-hour bootstrap blocks.
The intervals for X2-X4 therefore understate between-period variability and should be read
as rough.

## Operating points (secondary, pre-specified)

| policy | window recall | FPR | false alerts/h | precision | PR-AUC | attackers detected |
|---|---|---|---|---|---|---|
| A deployed | 0.317 | 0.089 | 0.47 | 0.779 | 0.695 | 11/40 |
| C2 address-class Mondrian | 0.314 | 0.089 | 0.47 | 0.776 | 0.693 | 10/40 |
| E LightGBM, local threshold | 0.337 | **0.002** | 0.01 | 0.994 | **0.973** | 9/40 |
| LightGBM, source threshold | 0.856 | 0.027 | 0.14 | — | 0.973 | 15/40 |

## What this external network shows

1. **The deployed local baseline does not keep its false-alert promise here** (8.9% at a 1%
   target). It also misses most attacking hosts (11/40 at the window level).
   - Calibration was benign but taken 19 days before evaluation. Evaluation is a short,
     attack-heavy period.
   - Drift between the two periods is a plausible cause. It is not separable from model
     failure with these data.
2. **The Phase 8c root-cause account made a correct prediction.**
   - The tail diagnostic stayed silent, and as predicted the address-class threshold changed
     nothing (X2).
   - Here the deployed detector fails for a different reason: a calibration/evaluation gap,
     not threshold pooling.
3. **Supervised window scoring transferred to a different lab and a broader attack mix**
   (X3), and it is **not just the scanning signature** (X4). This is the first evidence of
   that kind in the project.
   - With a local threshold it is very precise (FPR 0.2%) but finds only part of the attack
     windows.
   - With the transferred threshold it finds 86% of them at 2.7% FPR.
   - Training excluded NF-UNSW; label noise (IP-tagged labels) and the 4-block uncertainty
     remain.
4. **Incidents** concentrate evidence better than on IoT-23 (purity 0.78, reduction 11x),
   but miss the pre-registered 0.8.

## Software defect found by this run (fixed after the run)

- **The bug.** `WindowStream` ignored records starting more than `max_skew_s` (1 h) ahead of
  the watermark clock, to resist skewed sensor clocks. After a *real* gap of more than 1 h,
  every later record looked skewed, and the clock froze for the rest of the stream.
- **The fix** (`src/netsentinel/streaming/live.py`): after 1,000 consecutive "future" records,
  the clock re-synchronises to the earliest of them (`clock_resyncs`). Regression test:
  `tests/integration/test_streaming.py::test_clock_resyncs_after_a_real_time_gap`.
- **Effect on this result:** none. No record arrived late, so the window contents are the same
  as with the fix, and the frozen run is not repeated.
