# Changelog

## 0.8.0 (2026-10-21): Phase 8

Added
- `netsentinel demo`: offline end-to-end walkthrough on synthetic traffic.
- `netsentinel monitor --zeek-log [--follow]`: opt-in, read-only streaming of a local Zeek
  conn.log with event-time windows, lateness (default 360 s), deduplication, clock-skew guard
  and a bounded buffer.
- Incidents: per-entity grouping with stable IDs, severity, lifecycle and evidence; SQLite
  table; `GET /incidents`, `GET /incidents/{id}`, `POST /incidents/{id}/status` (admin).
- `GET /baseline`; `behavior.level`, `behavior.entity`, `behavior.threshold_fpr_upper95` on
  predictions; `/behavior` offset.
- Dashboard: Live traffic, Behavior intelligence (baseline metadata), Incident explorer,
  Research & diagnostics.
- Application ID: class-consistency abstention (`class_transport_mismatch`,
  `class_port_mismatch`).
- Research code: temporal scorers (`behavior/temporal.py`), Phase 8 scripts, pre-registered
  confirmatory evaluation.
- CI: model-backed Docker smoke test.

Changed
- A flow is "unusual" only through its own device or service window; global-window
  anomalies no longer mark every flow of the window.
- Calibration update gate v2: also requires review for strong single-window outliers.

Results: `docs/phase8/CONFIRMATORY_RESULTS.md`, `docs/phase8/FINAL_AUDIT.md`.
