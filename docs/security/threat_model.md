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
| T2 | Malicious file uploads | No upload endpoint. Replay accepts only a `YYYY-MM-DD` day name resolved inside the configured replay directory (path traversal rejected, tested) | - |
| T3 | Model artifact tampering | Bundles carry a SHA-256 manifest checked before unpickling, and a feature-schema version check (tested) | An attacker who can write the bundle directory can also rewrite the manifest. Only load bundles from trusted, write-protected locations; signing is future work |
| T4 | Dependency compromise | `uv.lock` pins all versions with hashes; CI runs `pip-audit` and gitleaks | Not run locally in this environment; supply-chain risk of the ML stack remains |
| T5 | Sensitive log leakage | Logs contain counts, run ids and metrics, never flow records or tokens | Debug-level third-party logs not audited |
| T6 | Dashboard / API access | API binds to 127.0.0.1 by default; admin endpoints disabled unless a token is set; constant-time token compare; bounded request bodies (`extra=forbid`, batch <= 1000, port/protocol ranges); dashboard opens SQLite read-only | No TLS, no user accounts, no rate limiting: not suitable for network exposure as is |
| T7 | Dataset poisoning | Training data is a fixed public benchmark with checksum-verified files; label-quality audit documented | Benchmark labels contain documented errors (see dataset card); online learning is not implemented, so live poisoning does not apply |
| T8 | Incorrect automated decisions | Verdicts separate `unusual` from `suspicious`/`attack`; anomaly alone never yields `attack`; abstention to `unknown` attack type; detection only, human review expected | Validation metrics come from one benchmark and do not transfer to other networks without re-validation |

## Privacy by design

* Metadata only; no plaintext content is read or stored.
* Minimise identifiers: IPs and source ports are not features and are dropped before replay.
* Retention: `EventStore.purge_older_than(cutoff)`; operators should schedule it.
* Authorised data only: the shipped workflows use a public research dataset. Applying NetSentinel
  to other traffic requires authorisation to monitor that network.
