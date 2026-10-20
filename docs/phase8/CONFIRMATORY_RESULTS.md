# Phase 8 confirmatory results: IoT-23 CTU-IoT-Malware-Capture-49-1

- Plan: [`RESEARCH_PLAN.md`](RESEARCH_PLAN.md), frozen in commit `d838738` and pushed before
  any content of the capture was read.
- Code: `scripts/phase8/confirm_49_1.py` at that commit.
- Raw output: `reports/phase8/confirm_49_1.json` and `.log`.
- Run: one pass, 18.2 min, peak RSS 2.99 GB (watchdog limit 3.4 GB; watchdog peak reading
  2.6 GB).
- Deviations from the plan: none.

## The data, as found

- 5,410,561 records over 7.3 h. **99.93% are labelled malicious**, almost all from one
  infected device.
- Partition at the time midpoint:
  - calibration: 2.70M flows;
  - evaluation: 2.71M flows over 3.66 h.
- Device level, evaluation:
  - 441 attack windows: every window of the infected device;
  - 823 benign windows: the other devices.
- Clean calibration: 1,233 device windows from benign-labelled flows.
- Both calibration variants met the testability conditions.
- No late, duplicated (file order), skewed or force-closed records. The buffer peaked at
  766k records (cap 1.5M).

## Hypotheses

| | Prediction | Result | Verdict |
|---|---|---|---|
| **H1a** | robust_z PR-AUC > guarded EWMA, clean calibration | 0.928 vs 0.676; delta 0.252, 95% CI [0.219, 0.295] | **supported** |
| **H1b** | guarded EWMA PR-AUC > robust_z, unlabelled calibration | 0.638 vs 0.723; delta -0.084, CI [-0.119, -0.035] | **refuted** |
| **H2** | product FPR <= 0.03 and CP upper bound <= 0.05 | FPR 0.0109 (9/823), CI [0.005, 0.021]; recall 1.00 | **supported** |
| **H3** | alert reduction >= 5 and mean incident purity >= 0.8 | reduction 45x (450 alerts -> 10 incidents); purity 0.10 | **refuted** |
| **H5** | consistency abstention: (a) accuracy within 0.005; (b) unknown-protocol abstention +0.05 | 25 reference flows (need 500), 1 unknown-protocol flow (need 100) | **not testable** |
| **H6** | streamed file order == jittered + 1% duplicates | 2,290 windows identical (max diff 0.0), same 18 incident IDs, 27,346 duplicates counted exactly, 0 late | **supported** |
| **H7** | peak RSS < 3.5 GB and >= 20k records/s | 2,985 MB; 24,758 records/s | **supported** |

## What it means

**H1a / H1b: the static robust baseline beats the adaptive temporal candidate, with or
without contamination.**
- The development hint that a guarded EWMA copes better with contaminated calibration did not
  replicate. It came from 3 units and was labelled weak in the plan.
- With unlabelled calibration, both methods lose the attacker:
  - recall at the threshold is 0.018 (robust_z) and 0.009 (EWMA);
  - the infected device's traffic is half of the calibration data and becomes "normal".
- This repeats the Phase 6 finding that calibration does not restore detection when attack
  traffic is in the calibration period.
- Caveat: the evaluation half spans only 3.66 h, so the block bootstrap had 4 one-hour blocks.
  The intervals understate between-period variability.

**H2: the product thresholds held their false-alert promise on a fresh network.**
- The FPR was 1.09% against a 1% target.
- The vetted calibration detected every window of the infected device. This is easy here:
  the device sends nothing but attack traffic.

**H3: incidents cut analyst load 45-fold, but most incidents were false.**
- The infected device produced exactly one incident: purity 1.0, no fragmentation.
- The 9 false alerts on benign devices became 9 separate single-window incidents (2.46/h).
- Mean purity over incidents is therefore 0.10. The criterion counts every incident equally,
  so it penalises a design that turns each isolated false alert into its own incident.
- That reading of the criterion is the pre-registered one, and the verdict stands.
- The practical implication is a product finding: single-window, low-ratio incidents should
  rank below sustained ones.
  - Today they get `medium` severity, because score/threshold >= 1.5 is common.
  - The `insufficient_evidence` status applies only below 1.25x.

**H5: not testable.**
- The capture has almost no traffic with a Zeek service label: 25 dns/http flows and 1 dhcp
  flow. The rest is unanswered telnet scanning.
- Descriptively, on the 25 flows: the port table was right on 18, ML-only on 2, and the hybrid
  policies accepted 9 (2 correct). This is too small to mean anything.

**H6 / H7: the streaming path is exact and fits the machine on 5.4M real records.**
- Streaming also reproduced the main pass's window keys exactly (exploratory check).

## Claims this supports, and claims it does not

- **Supported:** on one fresh IoT malware capture:
  - the production scorer (robust median/MAD with cross-fit thresholds) kept its false-alert
    rate near target and detected the infected device under vetted calibration;
  - it ranked windows better than the adaptive EWMA candidate;
  - the streaming implementation is exact and bounded.
- **Not supported:**
  - any statement about other networks, malware families or attack types (n = 1 capture);
  - detection under contaminated calibration;
  - the analyst-load benefit of incidents beyond the reduction factor;
  - application-ID behaviour on this capture.
