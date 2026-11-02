# Phase 8k research design: calibration reliability and selective detection

**Date:** 2026-11-02. **Builds on:** Phase 8j (development NO-GO, preserved unchanged;
[../phase8j/DEVELOPMENT_RESULTS.md](../phase8j/DEVELOPMENT_RESULTS.md)).

## 1. Question and rationale

**Question:** can an intrusion detector identify when its target-network calibration is
trustworthy, abstain when it is not, and still keep useful attack detection where it operates?

Phase 8j showed why this needs its own design. Its success rule asked every development unit
for ≥ 50% coverage. With 3 of 4 development networks whose calibration is inadequate, a method
that abstains *correctly* must fail that rule. Phase 8j's verdict stands as registered. Phase 8k
asks the question again with a protocol that scores the decision and the detection separately.

## 2. Two prediction problems, kept apart

| | A. Calibration adequacy prediction | B. Conditional attack detection |
|---|---|---|
| decision | accept or abstain, per network (unit) | – |
| available at decision time | P1x calibration windows and their scores only: size, hosts, effective n, host shares, within-host dependence, grouped exceedance, the internal temporal hold-out | – |
| never available | evaluation labels, the unit's future verified-benign FPR, attack labels of the evaluation period | – |
| outcome (evaluation only) | adequacy: realised verified-benign FPR at T0 ≤ 2α (needs ≥ 200 verified-benign windows, else indeterminate) | on accepted units: window and entity recall, detection delay, false alerts per hour |
| metrics | false acceptance of unsafe units; false rejection of adequate units; coverage of all units and conditional on adequacy | recall, attack-window and attack-entity coverage, delay, alert burden |

**Rules that follow from this:**
- **Abstention is never success.** Abstained units raise no alerts, and their attacks count
  as missed in every overall recall figure.
- **Each decision uses the unit's own threshold.**

## 3. Methods

| id | Phase 8k method | decision-time information | threshold | origin |
|---|---|---|---|---|
| M0 | existing detector, no rejection | none | T0 (split-conformal on the P1x hold-out) | Phase 8i A1 / 8j M0 |
| M1 | fixed eligibility checks 1–3 | session effective n ≥ 199; effective hosts ≥ 10 and top host ≤ 25%; host-grouped exceedance ≤ 2α | T0 | Phase 8i audit section 10.4: checks 1–3. 8j M1 also had check 4 (block recency), which Phase 8k reports separately as K4 |
| M2 | dependence-aware calibration | ≥ 10 hosts and a PAC rank at the dependence-adjusted effective n | max(T0, PAC) | 8j M3 |
| M3 | simple interpretable score | M2 and temporal self-consistency: T0 fitted on the first 70% of calibration, exceedance of the last 30% ≤ 2α | max(T0, PAC) | new |
| M4 | source-diversity-aware | M2's decision | max(host-balanced threshold, PAC) | new |
| – | learned reliability classifier | – | – | **not attempted.** 4 development networks from 2 institutions cannot support training and out-of-domain validation (DATASET_INDEPENDENCE.md); Phase 8j's attempt was degenerate |
| controls | always accept (= M0), always abstain, random selection at each rule's acceptance count | – | – | – |

## 4. Evaluation protocol (replaces the Phase 8j per-unit coverage rule for new work only)

Every rule is evaluated on **every** unit, accepted and rejected alike. The report always
gives the underlying measurements, not only a verdict:
- **Decision quality:**
  - counts of true and false acceptances and rejections;
  - false-acceptance and false-rejection rates with exact intervals;
  - the exact hypergeometric probability that random selection of the same number of units does
    at least as well.
- **Coverage:**
  - units accepted;
  - coverage conditional on adequacy;
  - accepted share of evaluation windows, attack windows and attack entities;
  - attack entities on adequate units that are covered.
- **Accepted units:**
  - pooled verified-benign FPR and its two-level (unit, host) bootstrap upper bound;
  - window and entity recall, median delay, false alerts per hour.
- **All units:**
  - overall window and entity recall, with abstained units counted as missed;
  - alerts per hour.

**No claim of overall success is allowed if** the rule accepts almost no adequate unit
(false rejection > 50%), or detects almost no attack (entity recall on accepted units < 0.5,
or < 50% of the attack entities on adequate units covered).

## 5. Why some variables are in and others out

The development failure decomposition (DEVELOPMENT_EXPERIMENTS.md section 2) found three
mechanisms:
1. **Small calibration** (NF-UNSW: 12 effective hosts). It is visible at decision time.
2. **Dominant-host change** (N4: 98% of false alerts from one host seen in calibration, whose
   tail moved by +0.28 over 309 h). It is invisible at decision time, but co-occurs with tiny
   host diversity (2.2 effective hosts), which is visible.
3. **Population turnover** (NF-ToN-IoT: 61% of false alerts from hosts absent from calibration).
   It is invisible at decision time.

Calibration-only rules can therefore address mechanism 1 and, indirectly, mechanism 2, but not
mechanism 3. Mechanisms 2 and 3 are evaluation-period changes. Detecting them needs online,
label-free monitoring of the evaluation traffic. Phase 8j's learned version of that failed with
4 networks. It is left to a phase with many more independent networks.
