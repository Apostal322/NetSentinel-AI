# Phase 8d development log: operating-point reliability and streaming validation

Data roles (unchanged):
- The Phase 8b captures (1-1, 60-1, 9-1), 49-1 and ToN_IoT are **consumed**. They are only
  used for labelled post-hoc or retrospective analyses, never for choices or new claims.
- All choices are made on development data: IoT-23 x9 (Phase 6 set), NF-UNSW-v3 development
  part, CTU-Normal x12.
- The frozen X1-X5 verdicts (docs/phase8c/EXTERNAL_RESULTS.md) are not changed.

## Mission 2: operating-point rule (fixed before running scripts/phase8d/operating_points.py)

**Policies.**
- Robust (deployed profile): A pooled cross-fit, B device-specific, C Mondrian own/pooled,
  C2 Mondrian address class.
- LightGBM (leave-one-capture-out, trained on other development captures):
  - E_local: split-conformal on target calibration;
  - E_source: 1% FPR on source benign windows;
  - E_device: per-device conformal for devices with >= 100 held-out windows, otherwise local;
  - E_c2: Mondrian by address class.
- Selective abstention (`+abst`): a policy issues no decision on a capture when its
  calibration is unreliable. Robust: cross-fit threshold diagnostics `reliable = False`, or
  the tail diagnostic warns. LightGBM: fewer than 100 held-out calibration windows. Missed
  attackers in abstained captures count as missed; abstention coverage is reported.

**Budget (as Phase 8c):** max FPR <= 0.03 on every covered development capture with >= 30
benign windows, and median false alerts/h <= 1.

**Selection rule:** among within-budget policies, the highest attacker-level recall. Ties go
to the simpler policy (robust before LightGBM; no abstention before abstention). A selected
policy is a candidate only; it is not validated.

## Results (2026-10-24)

See [REPORT.md](REPORT.md):
- **M1:** membership identical in all 5,820 windows; forged-timestamp defect fixed.
- **M2:** the rule selects A + abstention (within budget at 11/22 coverage). Every LightGBM
  policy breaks the budget.
- **M3:** robust-z FPR roughly doubles within hours. Unlabelled drift alarms cannot separate
  drift from attacks.
- **M4:** X3/X4 direction is robust to the block size.

Resources:
- the first post-hoc window rebuild was stopped by the memory watchdog at 3.43 GB;
- it was repeated with a 1.0M buffer cap, which is a stricter equivalence test;
- the other analyses peaked below 1.5 GB.
