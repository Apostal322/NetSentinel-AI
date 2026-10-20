# Threat model and privacy

Scope: NetSentinel v0.1 as shipped in this repository: offline ingestion, training, the
model bundle, the local API (`netsentinel serve`), offline replay, the SQLite event store and
the Streamlit dashboard. **Detection only**: no component blocks traffic, isolates hosts or
changes network state. Live capture is not implemented.

## Assets

| Asset | Why it matters |
|---|---|
| Flow metadata (ports, timing, volumes; IPs only in the 2018-02-20 raw file) | Can reveal behaviour of people and devices |
| Model bundles (`models/bundle-*`) | Pickled Python objects: loading one executes code |
| Event store (`artifacts/events.sqlite`) | Accumulates verdicts about traffic |
| Admin token (`NETSENTINEL_ADMIN_TOKEN`) | Controls replay jobs |

## Threats and mitigations

| # | Threat | Mitigation in this repo | Residual risk |
|---|---|---|---|
| T1 | Exposure of network metadata | Payloads never ingested (CICFlowMeter statistics only); IP columns excluded from features, events and replay output; data under git-ignored `data/`; event retention via `EventStore.purge_older_than` | IDs in the raw 2018-02-20 CSV remain on disk; anonymisation of real deployments not implemented |
| T2 | Malicious file uploads / captures | `POST /analyze` requires the admin token, caps size while streaming (50 MB default; 413 beyond, tested), writes to a random temp name and deletes it afterwards; the dashboard upload uses the same parser with Streamlit's 50 MB cap. Captures are parsed only by NetSentinel's pure-Python readers (no external tools, no shell); every length field is bounds-checked, corrupt records stop parsing cleanly, payload bytes are never kept (tested with corrupt/oversized/non-pcap inputs). Replay accepts only a `YYYY-MM-DD` day name inside the replay directory (path traversal rejected, tested) | Parser not fuzzed; decompression bombs are not applicable (no compressed formats accepted). CPU/memory of a 50 MB capture is bounded but not rate-limited |
| T3 | Model artifact tampering | Bundles carry a SHA-256 manifest checked before unpickling, and a feature-schema version check (tested) | An attacker who can write the bundle directory can also rewrite the manifest. Only load bundles from trusted, write-protected locations; signing is future work |
| T4 | Dependency compromise | `uv.lock` pins all versions with hashes; CI runs `pip-audit` and gitleaks | Not run locally in this environment; supply-chain risk of the ML stack remains |
| T5 | Sensitive log leakage | Logs contain counts, run ids and metrics, never flow records or tokens | Debug-level third-party logs not audited |
| T6 | Dashboard / API access | API binds to 127.0.0.1 by default; the Docker image listens on 0.0.0.0 *inside* the container but docker-compose publishes it on 127.0.0.1 only, runs as a non-root user with a read-only root filesystem, no capabilities and `no-new-privileges`; admin endpoints disabled unless a token is set; constant-time token compare; bounded request bodies (`extra=forbid`, batch <= 1000, port/protocol ranges); dashboard opens SQLite read-only for browsing (the "Analyze capture" page writes events) | No TLS, no user accounts, no rate limiting: not suitable for network exposure as is. The dashboard has no authentication: keep it on localhost |
| T7 | Dataset poisoning | Training data is a fixed public benchmark with checksum-verified files; label-quality audit documented | Benchmark labels contain documented errors (see dataset card); online learning is not implemented, so live poisoning does not apply |
| T8 | Incorrect automated decisions | Verdicts separate `unusual` from `suspicious`/`attack`; anomaly alone never yields `attack`; abstention to `unknown` attack type; detection only, human review expected | Validation metrics come from one benchmark and do not transfer to other networks without re-validation |

## Privacy by design

* Metadata only; no plaintext content is read or stored.
* Minimise identifiers: IPs and source ports are not features and are dropped before replay.
* Retention: `EventStore.purge_older_than(cutoff)`; operators should schedule it.
* Authorised data only: the shipped workflows use a public research dataset. Applying NetSentinel
  to other traffic requires authorisation to monitor that network.

## Phase 6–7 additions (2026-10-20)

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T9 | Authoritative attack verdicts on a network the supervised model does not fit (false alarms that look like attacks) | Default `--threat-policy unverified` on `analyze`, the API (including `/predict/*`) and the dashboard. Escalation needs `trust` (operator assertion) or `auto` with a passed domain check v2 (vetted calibration, >= 10/FPR flows, binomial test). Regression tests in `tests/unit/test_threat_policy.py` | An operator can still pass `trust` wrongly. `replay` uses the engine directly and is meant only for the bundle's own training-domain data |
| T10 | Baseline poisoning: attack traffic in a calibration period becomes "normal" | No online learning. `calibrate --previous active` scores the new period under the active baseline and marks it `review_required` if it is significantly anomalous; such artifacts activate only with `--reviewed`. Rollback keeps history. Unlabelled mode warns explicitly | A slow, low-rate attack present in every calibration period is undetectable by design; vetted-benign calibration relies on the operator's assertion |
| T11 | Calibration and classifier artifact tampering | Same SHA-256 manifest + schema-version checks as bundles (`load_profile`, `load_classifier`), tested; the API refuses to become ready with a corrupt artifact (`/ready` 503) | Same as T3: whoever can write the directory can rewrite the manifest |
| T12 | Device addresses in stored outputs | Behaviour windows key devices by source address; flow events carry it only in `behavior.model_scope` for device-level profiles; retention purges both tables | No pseudonymisation of addresses; keep the event store local |
| T13 | Over-trusting application labels | `app_protocol` is an nDPI-proxy label with `app_method` / `app_evidence`; `application_identity` is always null; conflicts between ML and port evidence are explicit | Port-based estimates are wrong for services on non-standard ports |
