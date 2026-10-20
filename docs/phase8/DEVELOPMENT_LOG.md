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

## 8D: application-ID abstention (development data)

Adoption rule, fixed before running `scripts/phase8/app_abstention.py`: a variant replaces the
product policy if, against `hybrid`:
- (a) NF-IDS2018 val B accepted accuracy drops by <= 0.005 and coverage by <= 0.02;
- (b) NF-UNSW val B (shared classes) accepted accuracy does not drop;
- (c) abstention on NF-UNSW flows of classes unknown to the model rises by >= 0.05.

If both qualifying variants pass, the simpler one wins.

Result (`reports/phase8/app_abstention.json`, 84 s, 1.1 GB):

| variant | IDS val B cov / acc | UNSW shared cov / acc | unknown-class abstention |
|---|---|---|---|
| port_only | 0.939 / 0.966 | **0.856 / 0.990** | 0.387 |
| ml_only | 0.997 / 0.988 | 0.991 / 0.519 | 0.010 |
| hybrid (Phase 7) | 0.993 / 0.992 | 0.660 / 0.779 | 0.010 |
| hybrid+consistency | 0.989 / **0.996** | 0.660 / 0.779 | **0.406** |
| hybrid+consistency+pcthr | 0.966 / 0.998 | 0.621 / 0.828 | 0.467 (fails a: coverage -0.027) |

- Adopted: `hybrid+consistency`. New product artifact `appid-portable-20261020T201432Z`
  (same weights, port table and policy; plus class profiles from IDS training flows). Unknown
  classes in UNSW: ssh, smtp, imap, ftp, nfs, bittorrent, edonkey and others.
- Honest note: **across datasets, the port table alone beats every ML variant on UNSW**
  (0.990 accepted accuracy at 0.856 coverage). The ML model adds value in-domain (IDS) and on
  non-standard ports, not for cross-network protocol identification. The dashboard and API keep
  `app_method`, so users can see which evidence was used.

## 8E: streaming monitor

- `netsentinel monitor --zeek-log FILE [--follow]`: opt-in, read-only, detection only. It reads
  a conn.log written by the operator's own Zeek. There is no capture, interception, scanning
  or blocking.
- `streaming/live.py`:
  - event-time windows; watermark = max flow start - lateness;
  - late records are counted and dropped;
  - duplicates are dropped per window;
  - clock-skew guard and bounded buffer with forced closes;
  - a context lookback of whole closed windows for supervised context features;
  - incidents and events stored per closed batch.
- Verified (tests):
  - in-order and jittered (+/-20 s, lateness 60 s) streams with 50 duplicates reproduce the
    offline window scores and incident IDs exactly;
  - the full demo pipeline (bundle + calibration + app classifier) streamed gives the same
    verdict counts and incident IDs as offline `analyze`;
  - a log whose scan records arrive an hour late reports exactly those 800 records as late.
- Found while building the confirmatory run: `load_capture` materialises all records. The
  fresh 49-1 log (853,630,635 bytes, SHA-256 `12e12cd6...fa54f`, contents not yet inspected)
  must therefore be processed through the bounded streaming path.

## 8J / 8I: pre-registration and confirmatory test

- Plan frozen and pushed in `d838738`.
- Two dry runs on inspected scenarios before 49-1 was read. They fixed the lateness setting
  and the H7 throughput definition, both recorded in the plan.
- Run: 18 min, 2.99 GB. Results in [CONFIRMATORY_RESULTS.md](CONFIRMATORY_RESULTS.md):
  - supported: H1a, H2, H6, H7;
  - refuted: H1b, H3;
  - not testable: H5.

## 8F: robust local normality (development, exploratory)

`scripts/phase8/robust_normality.py`, `reports/phase8/robust_normality.json`: 12 benign
CTU-Normal captures.

- **Sample size.**
  - 15 min of calibration: insufficient history in 12/12 captures.
  - 30-60 min: provisional status. Realised device FPR has median 0, and 19/19 runs are within
    3x the target.
  - 120 min: baseline ready (4/4 captures long enough).
- **Time of day:** per-hour FPR is recorded per capture. On 49-1 (exploratory) it ranged
  0-1.6% across the 5 UTC hours.
- **Drift:** 1 of 12 benign evaluation halves was flagged `drift_suspected` (a false drift
  alarm).
- **Contamination and safe updates.** This study found a real gap.
  - The update gate tested only the global alert RATE, so a 60 s port scan (800 SYNs) injected
    into a candidate period was flagged in **0/12** captures. The device level saw the scan,
    but a short burst barely moves a rate.
  - Gate v2 adds a strong-outlier rule: any window >= 2.0x the largest held-out calibration
    score of its level requires review.
  - A fixed 1.5x-threshold rule falsely flagged every synthetic normal period, because the
    maximum of hundreds of windows exceeds a 1% threshold.
  - Result: 7/12 contaminated periods flagged and 0/12 clean ones; with a 1.5x factor, 10/12
    and 3/12.
  - The factor was chosen on these data and is unvalidated. Five of 12 bursts still pass.

## 8G: API and dashboard

- API:
  - `GET /incidents` (filters, pagination with total / next_offset) and
    `GET /incidents/{id}`;
  - `POST /incidents/{id}/status` (admin token; history kept);
  - `GET /baseline` (calibration metadata with threshold uncertainty);
  - `/behavior` offset.
- Flow predictions carry `behavior.level`, `behavior.entity` and
  `behavior.threshold_fpr_upper95`.
- Dashboard sections:
  - Live traffic;
  - Behavior intelligence (with baseline metadata);
  - Application intelligence;
  - Incident explorer (filters, paging, evidence, lifecycle changes);
  - Traffic explorer, Anomalies, Threats, Analyze capture;
  - Model management;
  - Research & diagnostics.
- Covered by the Streamlit AppTest and TestClient tests.

## 8H: model-backed Docker smoke test (CI)

- The CI `docker` job now builds the synthetic demo artifacts on the runner. It mounts them
  read-only into the image and checks:
  - `/ready`;
  - `/baseline`;
  - the `/predict/flow` schema and the safe default (`unverified_domain`);
  - `/incidents` paging;
  - the admin requirement on status changes;
  - that a tampered bundle keeps `/ready` at 503;
  - container cleanup in an `always()` step.
- The same calls were checked locally against demo artifacts through the API.
- Performance on real data is H7: 24.8k records/s, 2.99 GB peak, for 5.4M records.
