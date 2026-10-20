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
| Baseline state (monitoring / drift_suspected / stale; explicit recalibration instead of online learning) | `behavior/monitor.py` | implemented; verified on synthetic drift; on CTU-26 it reported `drift_suspected` (score KS 0.36) at a low alert rate |
| Application intelligence (ML nDPI-proxy protocol with abstention: low_confidence / OOD / missing_features / unsupported_protocol; separate transport, port-heuristic service; application identity always null) | `appintel/model.py` | implemented; quality: §5 |
| Evidence-aware decisions (threat_status, behavior, application; supervised verdicts suppressed in unsupported domains; an anomaly is never "suspicious") | `inference/pipeline.py` | implemented, verified (integration test) |
| analyze / API / event store / dashboard integration | CLI `analyze --calibration --appid`, `/behavior`, `/models`, `behavior_events` table, 3 new dashboard pages | implemented; dashboard smoke-tested in a browser on real CTU-26 events (one bug found and fixed) |

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

## 5. Application classification (6D)

`reports/phase6/appid_v2.json` (run 3; runs 1–2 discarded after diagnosing LightGBM
multiclass divergence, see `DEVELOPMENT_LOG.md`) and `reports/phase6/h7_ctu_appid.json`.
Benign flows, nDPI master protocol (a proxy label), episode train / validation; validation B
reported.

| Feature set | NF-IDS2018 macro-F1 | NF-UNSW macro-F1 |
|---|---|---|
| port lookup (protocol, dst port) | 0.840 | 0.634 |
| full (nf_flow) | 0.952 | 0.728 |
| full without port class | 0.940 | 0.730 |
| no TTL / TCP window (no shortcut) | 0.944 | 0.735 |
| PCAP-safe (also no `*_SECOND_BYTES`) | 0.945 | 0.731 |
| **portable** (15 Zeek/PCAP-common fields + protocol + port class), the product model | **0.945** | 0.702 |
| portable without port class | 0.828 | 0.700 |

- **H6 (no-shortcut retains >= 0.9x full): supported** (0.944 vs 0.952). TTL and window
  fields were not needed for the in-dataset proxy label.
- **Shift between datasets** (shared classes dns/http/unknown).
  - IDS->UNSW: accuracy 0.51–0.75 at coverage about 1.0. The model is confidently wrong,
    and the validation-chosen threshold does not abstain.
  - UNSW->IDS: abstention helps (e.g. 0.81 -> 0.97 accepted accuracy at 76% coverage).
- **H7, independent real traffic** (13 CTU Zeek logs, 374k flows; Zeek's own `service` for
  dns/ssl/http as reference): **not supported.**
  - Accuracy 0.925, coverage 0.9996; selective prediction changes nothing.
  - A port rule scores 0.999, because these services run on their standard ports.
  - Per class: DNS >= 0.96, TLS 0.92–0.98, HTTP 0.42–0.72.
- **Conclusion.** The ML classifier reproduces nDPI's protocol labels inside a dataset, works
  without host-stack shortcuts, and runs on Zeek/PCAP-common fields. Under real shift it is
  confidently wrong on HTTP, and its abstention does not catch that. It is integrated as an
  explicitly labelled proxy-label prediction next to the port heuristic, not as a validated
  application identifier.

## 6. Real traffic end to end (6F)

`scripts/phase6/demo_ctu26_pcap.sh` -> `reports/phase6/ctu26_pcap_{phase6,uncalibrated}.json`.
CTU-26 PCAP: calibrate on flows ending before 03:15, analyse the 3.26 h after it, using only
the product CLI (81 s for three commands, <= 0.4 GB).

| Configuration | benign | unusual | suspicious |
|---|---|---|---|
| Phase-5 bundle, uncalibrated | 0 | 10,331 (99.0%) | 102 |
| + local calibration + application classifier | 10,214 | 117 (1.1%) | 102 |

- Behaviour windows anomalous: global 1/389, device 8/706, service 7/1,008.
- Baseline state: `drift_suspected` (score distribution shift, KS 0.36).
- **The 102 "suspicious" flows are false alerts** (benign capture), about 31/h. The
  supervised model's domain check passed on PCAP-extracted flows (flag rate 0.54% against
  the 1% limit), but failed on the Zeek log of the same capture (1.48%). The check is too
  lenient to catch this case; `--threat-policy unsupported` removes these verdicts.
  Detection-quality claims for the supervised model on new networks remain unsupported
  (Phase 5).

## 7. Hypotheses summary

| ID | Data role | Verdict | Key number |
|---|---|---|---|
| H1 local calibration reduces false alerts on unfamiliar benign traffic | confirmatory (CTU) | **not supported** (FPR part) | 52x fewer false-alert windows (2.3 vs 120/h), but FPR <= 3x target in only 7/12 captures |
| H2 service-conditioned < global FPR | exploratory (NF dev) | partially supported | IDS met; UNSW degenerate; FPR at recall 0.5 favours service on both |
| H3 device context improves detection | exploratory (NF dev, IoT-23) | not supported as specified | IF device recall 0.60 vs 0.22 on IDS; robust-z no; IoT-23 device worse; ranking favours device |
| H4 learned model beats robust statistics somewhere | exploratory | weakly supported | IF ROC +0.069 (IDS service), +0.092 (IoT-23 34-1); IF misses its FPR target |
| H5 calibration robust to <= 5% contamination | exploratory (NF dev, IoT-23) | **not supported** | IF device recall 0.60 -> 0.14 (IDS), 0.33 -> 0.02–0.05 (UNSW) |
| H6 app classification without shortcuts | exploratory (NF dev validation) | supported | 0.944 vs 0.952 |
| H7 selective prediction improves app ID under shift | confirmatory (CTU, Zeek reference) | **not supported** | coverage 0.9996, accuracy 0.925 vs port rule 0.999 |

**Not done.** Behaviour baselines conditioned on the *ML* application class (rather than
the port heuristic), and temporal or forecasting models (H4 used only Isolation Forest).
Both are open.
