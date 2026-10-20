# Phase 8 development log (recovery log)

Start state: `main` = `a4f1ea5` (in sync with origin), 116 tests, CI green.
User authorisations:
- download IoT-23 CTU-IoT-Malware-Capture-49-1 conn.log.labeled (854 MB);
- fast-forward pushes to `main` during Phase 8.

## 8A: zero-friction demo

- `netsentinel demo [--workspace DIR]`.
  - Fixtures: `src/netsentinel/demo/fixtures.py`, deterministic and synthetic.
  - Stages: ingest -> features -> LightGBM threat model + IForest anomaly reference -> bundle
    -> tiny application classifier -> calibrate on minutes 0-15 -> analyse minutes 15-25
    (SSH brute force from 18, port scan from 21) -> events -> explanation.
  - Offline, no downloads, CPU only: 56 s, < 1 GB.
- **Found by the demo, fixed in the product path:**
  1. **Global-window anomalies were stamped onto every flow of the window.** 80% of analysed
     flows were "unusual", most of them benign flows that merely co-occurred with the attack.
     Now a flow is "unusual" only through its own device or service window. Global anomalies
     remain behaviour events (and feed incidents in 8C).
  2. **Unknown protocols (SSH, scan) were labelled "dns"** by a classifier that only knew
     dns/http/tls: no port support, and the OOD check did not trigger.
     - New class-consistency abstentions (`appintel.model.class_consistency`; per-class
       training transport and port profiles stored in the artifact):
     - `class_transport_mismatch`: >= 99% of the class's training flows used another
       transport.
     - `class_port_mismatch`: a well-known port outside the ports carrying >= 95% of the
       class's training flows.
- Result after the fixes, verified by `tests/integration/test_demo.py`:
  - 2,400 of 2,400 injected flows are "unusual";
  - 12 of 1,200 benign flows are "unusual";
  - the protocols of benign flows are correct (tls/dns);
  - the injected flows abstain;
  - no supervised verdict is escalated (default `unverified`).
- These are synthetic numbers that check software behaviour. They are not detection
  performance.

## 8B: temporal scorers (exploratory, development data only)

Module `netsentinel.behavior.temporal`: RobustZ (production baseline), GuardedEWMA, LagIForest,
GRU and TCN next-window forecasters, all causal (unit tests: scoring a prefix gives the same
scores as scoring the full sequence; multi-scale context uses only completed coarse windows).

**Selection rule, fixed before the development comparison was run**
(`scripts/phase8/compare_temporal.py`; IoT-23 inspected scenarios + NF-UNSW development part;
device level, clean calibration, 30 s windows, target FPR 1%):
1. Eligible units: scenario/level combinations with >= 5 attack and >= 30 benign evaluation
   windows.
2. Primary: mean PR-AUC over eligible units. Guard rails: median realised FPR at the
   conformal threshold <= 3x target; scoring cost <= 1 ms per window.
3. The single candidate carried into the confirmatory test is the eligible non-baseline
   configuration with the highest primary score. It becomes the product default only if it
   also wins the confirmatory test; otherwise the simpler robust baseline stays.
4. Exploratory findings on these data are reported as such (they have been inspected).

**Development result** (`reports/phase8/temporal_{iot23,unsw,selection}.json`; 132 s + 166 s,
peak 1.4 / 2.0 GB, CPU). Eligible device-level units: IoT-23 3-1, 34-1 (both about 97%
attack windows, so PR-AUC is dominated by the base rate) and NF-UNSW development data.

| config (device, clean) | mean PR-AUC | median FPR | us/window |
|---|---|---|---|
| robust_z/base (production) | **0.846** | 0.0035 | 1.6 |
| robust_z/ms (+300 s context) | 0.829 | 0.0008 | 1.9 |
| guarded_ewma/base | 0.723 | 0.0053 | 27 |
| gru/base (4.9k params) | 0.707 | 0.0088 | 22 |
| tcn/base | 0.703 | 0.0053 | 23 |
| lag_iforest/base | 0.705 | 0.20 (ineligible) | 19 |

- No temporal model beats the static robust baseline with clean calibration (also at the
  service level: 0.905 vs 0.780 for the best alternative). The GRU/TCN forecasters train in
  under 1 s per scenario, but forecast error is a weaker signal than distance to the per-entity
  median on these data. Multi-scale context does not help.
- **Unlabelled (contaminated) calibration reverses the order**: guarded EWMA 0.737 vs robust_z
  0.672 (device). This is exploratory (inspected data, 3 units) and it becomes the confirmatory
  hypothesis for the fresh scenario.
- Selected candidate per the rule: `guarded_ewma/base`. The product default stays `robust_z`.

## 8C: incidents

`netsentinel.incidents`: windows of one entity with gaps <= 300 s form an incident with a
stable hash ID, a severity band, an automatic status of new or insufficient_evidence, and the
lifecycle new/investigating/acknowledged/resolved. Analyst status changes are preserved across
re-analysis, and new evidence re-opens a resolved incident. There is a SQLite `incidents` table,
and incidents are produced by `analyze_capture`. Flows carry `behavior.level/entity` to link
them to their incident.

Evaluation (`scripts/phase8/eval_incidents.py`, `reports/phase8/incidents_all.json`, robust_z,
clean calibration; device level):
- demo: 26 alerts -> 4 incidents. Each attacker is exactly 1 incident (high severity), with
  window recall 1.0. There are 2 benign incidents (low; 1 insufficient_evidence).
- IoT-23 3-1: 61.2 alerts/h -> 0.55 incidents/h, purity 1.0, but up to 10 incidents per
  attacking device (intermittent activity with gaps > 300 s).
- IoT-23 8-1: 99.7 alerts/h -> 0.08 incidents/h, purity 1.0, 1 incident.
- benign-only captures (honeypots 4-1, 5-1; 42-1): 0.09-1.1 incidents/h.
