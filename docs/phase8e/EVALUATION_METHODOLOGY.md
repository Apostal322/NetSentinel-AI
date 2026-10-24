# Evaluation methodology (Phase 8e, Mission 5)

This document fixes what NetSentinel's evaluation numbers mean and when they may support a
claim.

- Frozen results (Phase 8 H1–H7, 8b B1–B6, 8c X1–X5) are unchanged. Where this document
  reinterprets one, the reinterpretation is marked and the original verdict stands as recorded.
- Template for new confirmatory work: [PREREGISTRATION_TEMPLATE.md](PREREGISTRATION_TEMPLATE.md).

## 1. Metric levels

Each number must name its level. Levels are not interchangeable: a good window-level result
can coexist with zero detected attackers (Phase 8d), and vice versa.

| level | unit | positive when | needs | typical metrics | main pitfall |
|---|---|---|---|---|---|
| window-level detection | one (entity, 30 s) window | any flow in it is attack-labelled | flow labels | window recall, FPR, PR-AUC | dominated by one long attacker; time-correlated windows |
| device-level anomaly | the windows of one source over the evaluation | the device has any attack window | flow labels + the entity key | per-device hit rate, devices alerted | "device" = source address; NAT and DHCP merge or split devices |
| attacker detection | a source with attack-labelled flows | at least one alert in its attack windows | labels + **label provenance** | attackers detected / attackers, delay | on IoT-23 and ToN_IoT this is not a confirmed initiator: labels are flow-level and direction-agnostic, and responders inherit the label (LABEL_PROVENANCE.md) |
| confirmed-initiator detection | a source verified as initiating the attack | as above | provenance audit (role analysis, documented attacker list) | initiators detected, initiator window recall | needs an audit per dataset; retrospective only so far (ToN: 3/3 initiators, M1) |
| incident level | an aggregated incident (windows merged with a gap of ≤ 300 s) | it overlaps an attack interval | incident aggregation + labels | incidents/h, attack incidents found | merging can hide a second attack; splitting inflates counts |
| alert burden | evaluation hour | — | none (benign periods) | false alerts/h per population, incidents/h | per-capture hours are short; report median and max, not only the mean |
| selective prediction | a flow or window with a decision | it is not abstained | assessment states (UNCERTAINTY_STATES.md), HX-type policies | coverage, recall over **all** windows (abstained = missed), risk on covered windows | a policy can meet any FP target by abstaining: always report coverage next to burden |

**Rules:**
- **Report both burden and detection.** A recall figure without its FA/h (or FPR) and
  coverage is incomplete, and so is the reverse.
- **Use the lowest defensible level for headline claims.** Window level is the most
  defensible on flow-labelled data. Attacker level needs a provenance audit first.
- **Name the population of each FA/h figure** (local, external transient, external profiled,
  global, service; FP_BUDGETS.md).

## 2. Confidence-interval audit (block bootstrap)

A block bootstrap with n blocks has only C(2n−1, n) distinct resamples. With few blocks, the
"95% interval" is a coarse summary of a handful of configurations, not an inference.

| evaluation | blocks | distinct resamples | status under the standard below |
|---|---|---|---|
| Phase 8 H (IoT-23 49-1, confirmatory) | 4 (1 h) | 35 | **insufficient**: the interval is descriptive only |
| Phase 8 dry run (IoT-23 3-1) | 19 | about 1.8 × 10^10 | sufficient |
| Phase 8b B (IoT-23 1-1) | 56 | > 10^15 | sufficient |
| Phase 8b B (IoT-23 60-1) | 12 | 1,352,078 | sufficient (borderline) |
| Phase 8b B (IoT-23 9-1) | 12 | 1,352,078 | sufficient (borderline) |
| Phase 8c X3/X4 (ToN_IoT, frozen 60 min blocks) | 4 | 35 | **insufficient**: descriptive. Phase 8d post-hoc: the direction holds with 12 / 31 blocks (15 / 5 min) |

**Reinterpretation, not a change of verdict:**
- The frozen 49-1 and ToN_IoT intervals stay as recorded. They are read as descriptive.
- Their supporting evidence is the point estimate and the sign stability under finer
  post-hoc blocks (Phase 8d), not the interval width.
- No block size fixes the deeper limit: one dataset, one period, one network.

## 3. Minimum evidence standard

A **confirmatory** claim about detection quality needs **all** of the following. Anything
less is reported with a lower grade.

1. **Pre-registration.**
   - Template completed and committed before the evaluation data is opened.
   - Frozen code SHA, metric level, population, primary metric, decision thresholds, and the
     list of consumed data.
2. **Fresh data.** The capture or dataset was never used for any choice, and is recorded as
   consumed after use. Test data is touched once.
3. **Label provenance audited** before choosing the level: direction, time bounds, roles
   (LABEL_PROVENANCE.md method). Attacker-level claims need a confirmed-initiator list.
4. **Baselines.** The trivial policy (never alert) and the deployed policy are reported on the
   same windows.
5. **Burden with detection.**
   - FA/h per population, with ≥ 1 h of evaluation time and ≥ 30 benign windows per
     population, or the figure is labelled "insufficient".
   - Coverage whenever anything abstains.
6. **Intervals.**
   - Block bootstrap with **≥ 10 blocks** of at least 15 min, so there are ≥ 92,378 distinct
     resamples; otherwise the interval is descriptive only.
   - Entity-level proportions get a Wilson interval and their raw counts.
   - With < 5 positive entities, give counts only, with no rate claim.
7. **More than one environment** for any general claim. A single capture supports a claim
   about that capture only.
8. **Reproducibility.** Run ledger (config, git SHA, package versions, peak memory),
   deterministic seeds and the result JSON committed.

**Evidence grades used in reports:**

| grade | meaning |
|---|---|
| **[M]** | measured under this standard on fresh data |
| **[D]** | development data (choices were made on it) |
| **[R]** | retrospective or post-hoc on consumed data (explanation, not validation) |
| **[A]** | assumption |
| **[H]** | hypothesis (untested) |

## 4. How earlier phases rate against the standard (post-hoc, for reading only)

| result | met | missing |
|---|---|---|
| Phase 8 H (49-1) | pre-registration, fresh data, baselines | blocks (4), multiple environments, provenance audit |
| Phase 8b B (1-1, 60-1, 9-1) | pre-registration, fresh data, blocks | provenance audit; attacker level on flow labels |
| Phase 8c X (ToN_IoT) | pre-registration, fresh data | blocks (4), provenance (the documented attacker IPs were absent; resolved post hoc in M1), one environment |
| Phase 8e M4 (FP budgets) | pre-declared rule, baselines, burden with coverage | development data only (**[D]**) |
