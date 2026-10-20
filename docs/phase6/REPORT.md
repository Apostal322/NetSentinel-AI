# Phase 6 research report: local behaviour baselines, calibration, application intelligence

Status: 2026-10-20.
- Hypotheses and criteria: `IMPLEMENTATION_PLAN.md` §4 (frozen before evaluation).
- Decisions and changes: `DEVELOPMENT_LOG.md`.
- Each section names its evidence file under `reports/phase6/`.

**What counts as evidence here.**
- **Confirmatory:** H1 and H7 on CTU-Normal-20..32 and CTU-26, which were never used for any
  model choice. H1 uses vetted mode only.
- **Exploratory:** IoT-23 (independent, but with few attack windows in most scenarios); NF
  development data (the first 78% of each day, excluding all consumed test rows); and
  everything decided after seeing results (unlabelled mode).
- **Not evidence of detection quality:** synthetic fixtures.

## 1. What was built

| Capability | Where | Status |
|---|---|---|
| Causal entity-window features (global / device / service; 30 s default; a flow is assigned by end time) | `behavior/windows.py` | implemented, verified (causality and end-time tests) |
| Robust hierarchical profiles (median/MAD; device -> pooled fallback; split-conformal thresholds; percentile severity; explanations) | `behavior/profile.py` | implemented, verified |
| `netsentinel calibrate` (vetted_benign with operator assertion; unlabelled with fit trimming; cold start; versioned SHA-256 artifact; schema/feature checks; supervised-model domain check) | `behavior/calibrate.py`, CLI | implemented, verified (tests + real CTU logs) |
| Baseline state (monitoring / drift_suspected / stale; explicit recalibration instead of online learning) | `behavior/monitor.py` | implemented, verified on synthetic drift only |
| Application intelligence (ML nDPI-proxy protocol with abstention: low_confidence / OOD / missing_features / unsupported_protocol; separate transport, port-heuristic service; application identity always null) | `appintel/model.py` | implemented; quality: §5 |
| Evidence-aware decisions (threat_status, behavior, application; supervised verdicts suppressed in unsupported domains; an anomaly is never "suspicious") | `inference/pipeline.py` | implemented, verified (integration test) |
| analyze / API / event store / dashboard integration | CLI `analyze --calibration --appid`, `/behavior`, `/models`, `behavior_events` table, 3 new dashboard pages | implemented; dashboard not browser-verified |

## 2. H1: local calibration on unfamiliar benign traffic (confirmatory, vetted mode)

`reports/phase6/h1_ctu.json`. Setup: 13 benign CTU captures. Each capture's first half
calibrates and its second half is evaluated. Every alert is a false alert.

- Median false-alert windows per hour: **2.3 with the local profile vs 120 for the
  uncalibrated Phase-5 bundle**, whose window FPR was 0.54–1.00. That is a 52x reduction.
  Device and service levels: 1.1 and 0.5 per hour.
- The global-window FPR stayed within 3x the 0.01 target in only **7 of 12** captures. Five
  captures reached 0.033–0.042, and CTU-21 (0.3 h) was correctly reported as
  `insufficient_history`.
- **H1 is not supported** under its pre-registered two-part criterion. Calibration reduces
  false alerts by more than an order of magnitude, but its FPR guarantee does not survive
  within-capture drift. Thresholds come from only about 100–230 held-out windows.
- Unlabelled mode was redesigned after seeing these captures: fit-only trimming, threshold
  from all held-out windows. It then reached 1.4 false alerts/h, but that number is
  exploratory.

## 3. Labelled independent data: IoT-23 (exploratory)

`reports/phase6/iot23.json`; 9 scenarios, the first 50% of each calibrates.
- **Oracle-clean calibration** (dataset-labelled benign flows) on the attack-dominated
  scenarios: global recall 0.97 (3-1, 8-1); Isolation Forest recall 1.00 on 34-1. FPR
  <= 0.04 throughout.
- **Unlabelled calibration** where 72–97% of calibration traffic is malicious: recall
  0.00–0.02. Persistent malicious behaviour is learned as normal, and trimming cannot
  prevent it.
- Low-contamination scenarios have 0–2 attack windows; nothing can be concluded from them.
- **Detection delay.** Zeek logs a connection when it ends, so long-lived C&C sessions can
  only alert hours after they start (up to about 12 h in 20-1). Connection-log monitoring
  has this blind spot by construction.

## 4. Context conditioning and model choice on NF development data (exploratory)

`reports/phase6/nf_dev_{unsw,ids}.json`; one seed. NF-IDS2018 run: 20 min, **4.56 GB
peak, which exceeded the 3.5 GB budget** (cause documented).

| | NF-IDS2018 | NF-UNSW | Verdict |
|---|---|---|---|
| H2 service vs global FPR at matched recall | met (robust-z 0.0006 vs 0.0996; IF 0.116 vs 0.311) | degenerate (global recall 0) | partially supported |
| FPR at recall 0.5 (secondary): global / service / device | 0.47–0.55 / 0.22–0.31 / 0.065–0.073 | 0.70–1.0 / 0.14–0.18 / 0.054–0.087 | conditioning helps ranking |
| H3 device recall >= global + 0.05 at <= 1.5x FPR | met for IF (0.60 vs 0.22); not for robust-z | FPR clause unattainable | not supported (IoT-23: device worse) |
| H4 IF ROC >= robust-z + 0.05 | service +0.069 | device +0.038 | weakly supported (also IoT-23 34-1 +0.09) |
| H5 contamination <= 5% keeps >= 0.8x recall | IF device 0.60 -> 0.14 (natural), unstable across injection levels | 0.33 -> 0.02–0.05 | not supported |

Readings:
1. Device-level baselines rank attacks far better than global ones, on both datasets.
2. At the conformal operating threshold, robust-z rarely alerts (recall about 0), while
   Isolation Forest alerts more but **misses its FPR target badly** on NF-IDS2018 (0.31
   global).
3. Calibration quality, not model class, is the binding constraint. Contaminated calibration
   destroys recall in every setting tested.
