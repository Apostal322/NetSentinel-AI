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
