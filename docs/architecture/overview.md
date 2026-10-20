# Architecture

Status labels:
- **verified**: exercised by automated tests and, where stated, on real captures;
- **research**: experiment code, not part of the product path;
- **not implemented**.

## Two halves

```
RESEARCH PIPELINE (benchmarks; offline, reproducible)          PRODUCT PATH (local, detection-only)
-------------------------------------------------------        -----------------------------------
public datasets (CIC-IDS2018 CSV, NetFlow v3, CTU, IoT-23)     authorised capture: PCAP/pcapng or Zeek conn.log
  | data verify / ingest / ingest-nf      data/                   | readers + flow assembler       telemetry/   [verified, real CTU-26]
  v                                                               v
typed Parquet, causal context features   features/             canonical NF-v3-style flow frame telemetry/frames.py
  | splits + leakage checks              data/splits.py           |
  v                                                               +--> netsentinel calibrate      behavior/    [verified]
training stages (baseline, anomaly, openset, temporal,                 causal entity windows (global/device/service)
  transfer, adapt, appid)                training/                     robust profiles, cross-fit thresholds,
  | run ledger per run                   ledger.py                     diagnostics, statuses, registry + rollback
  v                                                               |
reports/, runs/, pre-registered one-shot tests                     v
                                                                 netsentinel analyze / API / dashboard
model bundle (supervised threat model,                                 AnalysisPipeline          inference/pipeline.py [verified]
  anomaly reference, evidence)          inference/bundle.py  ---->  1 supervised evidence (bundle) - policy-gated
app classifier artifact (+ port table, policy) appintel/      ---->  2 behaviour vs local baseline
                                                                      3 application protocol (ML / port / unknown)
                                                                       -> evidence-aware Prediction  inference/schema.py
                                                                  |
                                                                  v
                                                                 SQLite event store (flows + behaviour windows)  storage/
                                                                  |
                                                                  +--> FastAPI (localhost)   api/app.py         [verified, tests + real process]
                                                                  +--> Streamlit dashboard   dashboard/app.py   [verified, AppTest + browser]
```

## The decision contract (per flow)

| Field | Source | Semantics |
|---|---|---|
| `threat_status` | supervised bundle, gated by policy | Default `unverified_domain`: scores are shown but never escalate. `suspicious` / `known_attack_category` only under `--threat-policy trust`, or `auto` with a passed domain check v2 |
| `behavior` | local calibrated profile | `anomaly_score` is a percentile among held-out calibration windows, type `normalized_non_probability`. `behavior_status` is normal / anomalous / insufficient_history / not_calibrated; `baseline_status` includes `baseline_provisional` and `drift_suspected` |
| `application` | ML + training-data port table | `app_protocol` with `app_method` (ml / ml_port_agree / port_estimate) or an abstention (`app_status`). `service_category` is a port heuristic. `application_identity` is always null |
| `verdict` | `decide_verdict` | attack / suspicious only from trusted supervised evidence; unusual = behaviour anomaly; insufficient_data when nothing supports a normality claim; benign otherwise |

## Key design decisions

| Decision | Reason |
|---|---|
| A flow is assigned to the window containing its END time | The record exists only when the flow ends; nothing reads the future (causality tests) |
| No online learning; explicit recalibration with review/rollback | Continuous learning would absorb persistent attack traffic into "normal" |
| Supervised verdicts unverified by default | Phase 5: no cross-network transfer; Phase 6: a lenient domain check produced false alerts |
| Cross-fitted thresholds by default | Phase 6 FPR misses were small-sample threshold noise (Phase 7 P2); costs recall in some IoT-23 scenarios |
| Port evidence can override the ML protocol | The portable model sees only a coarse port class; long HTTP on port 80 looked like TLS |
| Every artifact hash-checked and schema-versioned | Refuses corrupted or incompatible models, calibrations and classifiers |
| One heavy framework per process, lazy imports | 8 GB RAM development machine |

## Not implemented

- Live packet capture or streaming monitoring. The system is offline only, by design.
- Zeek or Suricata execution: NetSentinel reads Zeek logs, it does not run Zeek.
- Behaviour baselines conditioned on the ML application class (they use the port
  heuristic).
- Blocking or any network change: detection only.
