# Phase 8c: root cause of the 0-of-4 detection failure (development log)

Roles:
- The fresh Phase 8b captures (1-1, 60-1, 9-1) and 49-1 are **consumed**. They are used here
  only for *retrospective explanation*, labelled as such, and never for any choice.
- All choices are made on development data: IoT-23 x9 (Phase 6 set), NF-UNSW-v3 development
  part, CTU-Normal x12.

## 1. Trace (scripts/phase8c/trace.py, tail_composition.py)

Deployed path for the device level:
- per-device median/MAD profile when a source address has >= 30 calibration windows,
  otherwise the pooled profile;
- window score = mean of the 2 largest |z|;
- **one** threshold per level: the conformal 99th percentile of cross-fit held-out scores of
  **all** source addresses together.

| capture | role | calibration "devices" | external | threshold | tail from pooled-fallback windows | attacker's attack-window score (median / max) |
|---|---|---|---|---|---|---|
| 1-1 | retrospective | 11,972 | 11,968 | 18.4 | **100%** | 4.5 / 17.7 (own profile) |
| 9-1 | retrospective | 919 | 917 | 17.4 | **100%** | 6.3 / 6.7 (own profile) |
| 60-1 | retrospective | 3 | 1 | 48.6 (228 held-out windows, about the maximum) | 33% | 33 / 47 (own), 18 (external attacker, pooled) |
| 3-1 | dev | 508 | 506 | 7.1 | 0% | 8.6 / 14.1: detected (51% of windows) |
| 34-1 | dev | 2 | 0 | 21.8 | 10% | 9.6 / 45: 1% of windows |
| NF-UNSW | dev | 36 | 30 | 11.5 | 70% | about 6 / 14 (external attackers, pooled): recall < 1% |

**Mechanism.**
- Every originating address is a "device". Internet hosts that contact an exposed device
  (scanners, peers) appear as thousands of transient sources with a few windows each.
- They are scored against the pooled fallback profile, which they do not resemble, so their
  scores are heavy-tailed.
- One level-wide conformal threshold over that mixture places the whole 1% budget on them.
- The infected local device, scored against its own profile, ranks above benign evaluation
  windows (good PR-AUC) but stays below a threshold set by strangers.
- In 60-1 the cause is different: too little calibration data (the threshold is about the
  maximum of 228 scores).

**Classification.**
- Not a coding defect: the implementation matches its documentation, and offline and
  streaming are identical (P8-H6 on 5.4M records; integration tests).
- It is a **design defect** in how entities are defined (originator = device) and how the
  threshold is pooled across populations with different score distributions. Plus, in 60-1,
  an insufficient-calibration limitation that the status `baseline_provisional` flags.

## 2. Policy comparison: rule fixed before running scripts/phase8c/policies.py

**Operational budget** (all policies; target FPR 1% per entity-window):
- realised FPR <= 0.03 in every development capture with >= 30 benign evaluation windows;
- median false alerts per hour <= 1 over those captures.

A policy outside the budget is reported but cannot be recommended.

**Candidates:**
- A: deployed;
- B: per-device thresholds (own cross-fit held-out scores, >= 100 needed, else the group
  threshold);
- C: Mondrian thresholds per scoring group (own profile vs pooled fallback);
- C2: Mondrian per address class (private/link-local vs external);
- D1/D3/Dall: top-1, top-3 and mean |z| aggregation with the deployed threshold method;
- E: LightGBM (leave-one-capture-out, trained on other development captures) with a local
  split-conformal threshold;
- F_or: alert if C or E fires, each at 0.5%;
- F_and: alert only if both fire, each at 1%.

**Primary:** attacking-entity recall pooled over development captures. Secondary: window
recall, precision, PR-AUC, observable delay.

**Recommendation rule:** among within-budget policies, the highest attacking-entity recall.
Ties go to the simpler policy (A < B, C < D < E < F). It must also not lower window-level
PR-AUC by more than 0.02 relative to A. Being best on development data does NOT make a policy
validated: it becomes a candidate for a new pre-registered test on independent data.

## 3. Results

See [ROOT_CAUSE.md](ROOT_CAUSE.md):
- conclusion 2 (scoring useful, threshold selection inadequate);
- the policy table;
- the LightGBM audit;
- the diagnostic.

The external validation plan is [EXTERNAL_VALIDATION_PLAN.md](EXTERNAL_VALIDATION_PLAN.md),
frozen; the data is not downloaded.

## Open engineering issue

`tests/integration/test_demo.py::test_demo_runs_offline_and_separates_injected_traffic` failed
once in a full-suite run on 2026-10-23, with no traceback captured. It passed in the 5
following runs (4 isolated, 1 full suite). It is not reproduced, and the cause is unknown.
Watch for it in CI.
