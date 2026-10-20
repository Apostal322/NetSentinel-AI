# Phase 8 research plan (pre-registration)

Written and committed **before** any content of the confirmatory data was read. The only facts
known about the data at freezing time are its name, size (853,630,635 bytes) and SHA-256
(`12e12cd6d01cb0f2b5330c217069ab4de103aa2044a97dd60d8af5f0d3cfa54f`). The analysis code is
`scripts/phase8/confirm_49_1.py`, committed together with this plan; its git SHA is the freeze
point. Any later deviation is listed under "Deviations" with its reason. Results that the
plan did not specify are labelled exploratory.

## Data and roles

| data | role | status |
|---|---|---|
| CIC-IDS2018 test, NF-v3 final test | spent in Phases 4-5 | never reused for claims |
| IoT-23 9 scenarios, CTU-Normal, NF dev parts | development (inspected) | model choice, rules |
| **IoT-23 CTU-IoT-Malware-Capture-49-1 `conn.log.labeled`** | **confirmatory** | fresh |

- Source: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/
  CTU-IoT-Malware-Capture-49-1/bro/conn.log.labeled (Stratosphere Lab, CTU).
- Labels: the dataset authors' per-flow `label`. A flow is an attack flow if the label starts
  with "Malicious". An entity-window is an attack window if any of its flows is one.
  Labels are used only for metrics and for the oracle "clean" calibration variant.
- One capture is one network, one malware family and one time period. **Results are
  evidence about this capture, not about generalisation in general.** No previously spent test
  data is used for any claim here.

## Partition (fixed)

- Time span = [min, max] flow END time over all parsed records.
- Calibration = flows ending before the midpoint; evaluation = flows ending at or after it.
  This is the same protocol as the development studies.
- Window 30 s; levels device (source address) and service; target FPR 1%.
- Calibration variants:
  - clean: calibration flows labelled benign (an oracle for operator-vetted traffic);
  - unlabelled: all calibration flows (natural contamination).
- Processing is streamed (`netsentinel.streaming.live.WindowStream`, lateness 3,700 s, buffer
  cap 1.5M records; late or force-closed records are reported) with chunked aggregation. Calibration windows use the expanding destination set (prior destinations
  carried across chunks); evaluation windows use the frozen calibration destination set.

## Testability (decided before results)

A hypothesis that needs a calibration variant is **not testable** (and is reported as such,
never re-interpreted) if:
- that variant has fewer than 60 device-level calibration windows; or
- the evaluation set has fewer than 5 attack or fewer than 30 benign device-level windows.

H5 needs at least 500 reference flows (Zeek service dns/ssl/http) for (a), and at least 100
flows whose Zeek service names a protocol outside the model's classes for (b).

## Confirmatory hypotheses

Uncertainty: moving-block bootstrap over the evaluation period (blocks of 1 h of window end
time, 2,000 resamples, seed 0), percentile 95% intervals. Proportions use Clopper-Pearson 95%
intervals. The bootstrap intervals for H1a/H1b are two-sided; "supported" requires the whole
interval on the predicted side.

**H1a (temporal model, clean calibration).** The robust median/MAD baseline (`robust_z/base`)
reaches a higher device-level PR-AUC than the development-selected temporal candidate
(`guarded_ewma/base`, rule in DEVELOPMENT_LOG 8B).
- Dev evidence: 0.846 vs 0.723.
- Statistic: delta = PR-AUC(robust_z) - PR-AUC(guarded_ewma), using the
  scripts/phase8/compare_temporal.py protocol (fit on the first 70% of calibration windows,
  split-conformal threshold on the rest, evaluation scored with full calibration history).
- Supported: 95% CI of delta > 0. Refuted: 95% CI < 0. Otherwise inconclusive.

**H1b (temporal model, unlabelled calibration).** Under natural contamination the guarded EWMA
reaches a higher device-level PR-AUC than robust_z.
- Dev evidence: 0.737 vs 0.672 (3 units; weak).
- Supported: 95% CI of PR-AUC(ewma) - PR-AUC(robust_z) > 0. Refuted: CI < 0. Otherwise
  inconclusive.

**H2 (calibration reliability, product path).** Product calibration (`calibrate_windows`,
cross-fit thresholds, clean, vetted_benign) gives a realised device-level FPR on benign
evaluation windows <= 3x target (0.03).
- Supported: point estimate <= 0.03 AND Clopper-Pearson upper bound <= 0.05.
- Refuted: lower bound > 0.03.
- Otherwise inconclusive.

**H3 (incidents reduce analyst load).** With the H2 product scores and incident gap 300 s,
device-level incidents/h are at most one fifth of anomalous windows/h (alert reduction >= 5),
and the mean incident purity is >= 0.8.
- Dev evidence: 6.5 (demo) to about 1,200 (8-1); purity 1.0 on attack captures.
- Supported: both criteria met. Refuted otherwise; reported with values.
- Not testable if fewer than 5 incidents.

**H5 (application abstention).** On 49-1 flows with a Zeek service reference, the Phase 8
product policy (hybrid + class consistency, `appid-portable-20261020T201432Z`) compared with
the Phase 7 policy (hybrid, `appid-portable-20261020T184500Z`):
- (a) accepted accuracy does not drop by more than 0.005, with references dns -> dns,
  ssl -> tls, http -> http;
- (b) abstention on flows whose Zeek service is a protocol outside the model's classes (e.g.
  ssh, ftp, smtp, irc, telnet) rises by >= 0.05.

Supported: (a) and (b). Port-only and ML-only are reported descriptively.

**H6 (streaming equivalence on real data).** The evaluation half streamed in file order, and
streamed after a seeded jitter of +/-20 s with 1% duplicated records, yields identical device
and service window scores (|diff| < 1e-9) and incident IDs, with the inserted duplicates
counted exactly. Both runs use lateness 3,700 s and a 1.5M-record buffer: Zeek writes
connections after their inactivity timeout, and development logs need up to 3,595 s
(`reports/phase8/zeek_lateness.json`).
- Supported: all equal. Refuted: any mismatch.

**H7 (resources).** Processing 49-1 (both passes) stays below 3.5 GB peak RSS on the 8 GB
development machine, and the streaming window path sustains >= 20,000 records/s
(all records read from the file per second in H6 run A: parse + filter + window + score;
single process, CPU).
- Supported: both. Refuted otherwise.

## Exploratory analyses (labelled as such in all reports)

- service-level versions of H1-H3;
- incident fragmentation (incidents per attacking device);
- time-of-day dependence of FPR;
- calibration drift (binomial/KS state) on the evaluation half;
- per-class application accuracy;
- recall at 1% FPR;
- detection delay.

## Threats to validity

- One capture, single malware family: no generalisation claim.
- The labels are the dataset authors' heuristics.
- The "clean" variant uses labels to remove attack flows and is an optimistic upper bound for
  operator vetting.
- Mirai-style captures often consist mostly of attack flows, so PR-AUC depends strongly on
  the base rate. It is reported next to the base rate, and comparisons are within-capture
  only.
- Zeek `service` is an imperfect reference for H5.
- The development comparison that chose `guarded_ewma` had only 3 eligible units.

## Pre-freeze corrections (from a dry run on inspected scenario IoT-23 3-1, before 49-1 was read)

- The draft used 60 s lateness for H6 and 600 s for the main pass. The dry run showed records
  arriving later than that (99 records at 600 s), and a lateness study on 22 development logs
  showed up to 20% of records later than 60 s. Both are now 3,700 s.
- H7 throughput was defined over evaluation records only, although every record of the file
  is parsed. It now counts all records read.

## Deviations

None at freezing time.
