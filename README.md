# NetSentinel AI

**Leakage-aware machine-learning research on network-flow intrusion detection, plus a local,
detection-only tool that learns a behavioural baseline from your own PCAP or Zeek data.**

The main contribution is *evaluation honesty*, not a new model. The repository measures:
- where near-perfect benchmark scores come from;
- what survives pre-registered, leakage-aware testing;
- what does not transfer to another network;
- what a local, calibrated baseline can and cannot do instead.

> **Status (v0.7.0, 2026-10-20): research prototype, detection only, offline.**
> - Supervised models score almost perfectly on the network they were trained on and fail on
>   other networks (pre-registered test).
> - The product path therefore treats them as *unverified* by default. It reports deviations
>   from a locally calibrated baseline and an abstaining protocol classifier, never
>   unsupported attack verdicts.
> - This is not a production IDS. Read [Limitations](#limitations) and the
>   [release-readiness audit](docs/RELEASE_READINESS.md).

## What is validated and what is research

| Capability | Status | Evidence |
|---|---|---|
| PCAP/pcapng and Zeek `conn.log` ingestion, flow assembly | **Validated**: matches Zeek on a real 199k-packet capture (TCP flow count equal, 99.8% packet/byte agreement) | `reports/audit/pcap_vs_zeek.json` |
| `netsentinel calibrate`: local behaviour baseline (global / device / service, causal 30 s windows) with diagnostics, provisional/insufficient-history states, review-before-activate and rollback | **Implemented and tested** (unit, integration, real CTU captures) | `docs/phase7/RELIABILITY.md` |
| Evidence-aware decisions: behaviour anomaly vs supervised evidence vs known attack; supervised verdicts unverified by default | **Implemented and tested** | `tests/unit/test_threat_policy.py` |
| Protocol identification: ML (nDPI proxy labels) + training-data port evidence, abstains on conflict | **Implemented**; validated on development data; descriptive check on real traffic | `docs/phase7/RELIABILITY.md` P3 |
| FastAPI service, SQLite event store, Streamlit dashboard | **Implemented and tested** (TestClient, real `serve` process, Streamlit AppTest, browser check) | `tests/integration/` |
| Supervised attack detection (LightGBM, CIC-IDS2018 / NetFlow v3) | **Research**: in-domain only | `docs/RESULTS.md` |
| Unknown-attack detection by anomaly models | **Research, negative result** | `docs/phase6/REPORT.md` |
| Live capture, blocking, multi-network deployment | **Not implemented** | — |

## Headline results

Full tables with sources and data roles: [`docs/RESULTS.md`](docs/RESULTS.md).

| Question | Answer |
|---|---|
| In-domain supervised detection | recall 0.983 (CIC test, once) and 1.000 (NetFlow test, both datasets) at FPR about 1e-3. Without 4 CICFlowMeter artefact fields: 0.735 |
| Does it transfer to another network? | **No.** ROC 0.37–0.66 IDS2018 <-> UNSW-NB15 on identical nProbe features; source thresholds flag 35–99% of benign flows (pre-registered) |
| Does a local baseline reduce false alerts on an unfamiliar benign network? | Yes: about 120 -> 2.3 false-alert windows/h (13 CTU captures). Its pre-registered FPR guarantee failed in 5/12 captures with Phase 6 thresholds; cross-fitted thresholds fixed that on the same data (exploratory) at a recall cost elsewhere |
| Does calibration restore attack detection? | **No.** With attack traffic in the calibration period, recall collapses (IoT-23, NetFlow development data) |
| ML protocol ID vs port lookup | Better in-dataset (macro-F1 0.945 vs 0.840). Confidently wrong under shift (HTTP on port 80 called TLS), so the product combines it with port evidence and abstains on conflicts |

## Quick start

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). Tests need no data download.

```bash
uv sync --extra dashboard
```

```bash
uv run --extra dashboard pytest
```

A synthetic walkthrough (generated traffic, a software demo, not evidence of detection
quality):

```bash
uv run python scripts/make_demo_pcap.py artifacts/demo.pcap
```

```bash
uv run netsentinel calibrate artifacts/demo.pcap --mode vetted_benign --assert-benign --window 5 --out models/calibrations --activate
```

Analysis needs a supervised model bundle. Bundles are not shipped: build one with
`netsentinel bundle build` after the NetFlow pipeline below.

```bash
uv run netsentinel analyze artifacts/demo.pcap --bundle models/<bundle-id> --calibration active --events-db artifacts/events.sqlite --out summary.json
```

```bash
uv run --extra dashboard streamlit run dashboard/app.py -- --events-db artifacts/events.sqlite
```

### Using it on your own capture

Only analyse traffic you are authorised to analyse.

1. **Calibrate** on a period you believe to be normal. `--assert-benign` records that
   assertion; without it, use `--mode unlabelled` and treat the baseline with suspicion.
   Calibrate with `--until <time>`, then analyse a later period with `--since <time>`.
2. **Update safely.** `calibrate --previous active --activate` refuses to activate a new
   baseline whose period looks anomalous under the current one (possible attack traffic)
   until you pass `netsentinel calibration activate <id> --reviewed`.
   `netsentinel calibration rollback` restores the previous baseline.
3. **Read the outputs.**
   - `behavior.anomaly_score` is a percentile among held-out calibration windows, *not* a
     probability.
   - `threat_status` is `unverified_domain` unless you pass `--threat-policy trust` (you assert
     the network matches the model's training data), or use `auto` with a calibration whose
     domain check v2 passed.
   - `application.app_protocol` comes with `app_method` and `app_evidence`.
     `application_identity` is never inferred.

The API (`netsentinel serve`, localhost only) and the dashboard expose the same fields.

![Network behaviour (device level, real CTU-26 capture)](docs/images/phase6_behaviour_device_ctu26.jpg)
![Application intelligence (real CTU-26 capture)](docs/images/phase6_appintel_ctu26.jpg)

## Architecture

The research pipeline (datasets -> features -> leakage-checked splits -> training ->
pre-registered tests) is separate from the product path (capture -> flows -> calibration ->
evidence-aware analysis -> store -> API/dashboard). Details:
[`docs/architecture/overview.md`](docs/architecture/overview.md).

```
capture (PCAP / Zeek) -> flows -> causal windows -> local baseline (calibrate, registry)
                                        |
supervised bundle (policy-gated) -------+--> evidence-aware Prediction -> SQLite -> API / dashboard
protocol classifier (ML + port) --------+
```

## Research methodology

- **Leakage control.**
  - Causal features: a flow counts at its end time.
  - Episode-chronological splits with purge gaps.
  - Preprocessing fit on train only.
  - Automated leakage checks on every run.
  - Group/time-aware splits, saved split indices.
- **Pre-registration.** Both test sets were evaluated once, after written protocols:
  [`test_preregistration.md`](docs/experiments/test_preregistration.md) and
  [`final_preregistration_nf.md`](docs/experiments/final_preregistration_nf.md), the latter
  with a documented deviation. They are now spent; later phases use development or
  independent data and label each result confirmatory or exploratory.
- **Negative results are reported.** Several examples:
  - a twin-class leak that inflated early open-set results;
  - anomaly detectors that detect nothing at operational FPR;
  - autoencoder "success" driven by TTL artefacts;
  - failed pre-registered hypotheses (Phase 6 H1, H5, H7).
- **Audits.**
  - [`docs/audit/validity_audit_2026-10-19.md`](docs/audit/validity_audit_2026-10-19.md)
  - [`docs/FINAL_AUDIT.md`](docs/FINAL_AUDIT.md)
  - [`docs/phase6/FINAL_AUDIT.md`](docs/phase6/FINAL_AUDIT.md)
  - [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md)

Reports by phase:
- [`report_v1.md`](docs/experiments/report_v1.md) (1–4);
- [`report_phase5.md`](docs/experiments/report_phase5.md) (transfer, adaptation, final test,
  PCAP/Zeek validation);
- [`docs/phase6/REPORT.md`](docs/phase6/REPORT.md) (local baselines, application ID);
- [`docs/phase7/RELIABILITY.md`](docs/phase7/RELIABILITY.md) (safe defaults, calibration
  reliability, protocol policy).

## Reproducing the research

Data provenance, licences and hashes: [`docs/datasets/README.md`](docs/datasets/README.md).
Downloads go to the git-ignored `data/` folder.

```bash
bash scripts/download_ids2018.sh
```

```bash
uv run netsentinel data verify
```

```bash
uv run python scripts/download_nf_v3.py
```

```bash
uv run netsentinel data ingest-nf nf-cicids2018-v3
```

```bash
uv run netsentinel features build --schema nf --interim data/interim/nf_cicids2018_v3 --out data/processed/nf_cicids2018_v3
```

Experiment batches are `scripts/run_batch_v{1..5}.py` and `scripts/phase6/*`,
`scripts/phase7/*`. Each run writes its config, git SHA, package versions, metrics and split
indices under `runs/`. Development machine: 4-core CPU, 8 GB RAM, GTX 1050 Ti. Runtimes and
peak memory are recorded in the development logs.

## Limitations

- **No cross-network generalisation** of the supervised models. Without local labels, no
  configuration tested is both quiet and able to detect attacks.
- Calibration controls false alarms only. It assumes the calibration period is benign, and
  persistent malicious behaviour in that period is learned as normal.
- Cross-fitted thresholds (default) trade recall for reliable FPR; split thresholds remain
  available.
- Protocol labels are nDPI proxy labels (nDPI version of the training data undocumented). On
  standard ports the policy is mostly a port lookup confirmed by the ML.
- Zeek logs a connection only when it ends: long-lived C&C appears hours late.
- The PCAP extractor matches Zeek, but its field-level agreement with nProbe is unverified.
- Benchmark labels contain documented errors; the test partitions are spent; the CIC test is
  single-seed.
- The API has no TLS, accounts or rate limiting (localhost only). Threat model:
  [`docs/security/threat_model.md`](docs/security/threat_model.md).
- Docker and CI status: see the [release-readiness audit](docs/RELEASE_READINESS.md).

## Repository layout

```
src/netsentinel/   telemetry/ behavior/ appintel/ inference/ api/ storage/   (product path)
                   data/ features/ training/ models/ evaluation/ temporal/      (research)
dashboard/         Streamlit app
scripts/           batches, audits, phase6/, phase7/, release/
configs/           dataset and experiment configs
reports/           measured results (JSON/Markdown/figures) referenced by the docs
docs/              reports, audits, dataset cards, architecture, security
tests/             unit / integration / ml  (gpu, slow, data tests excluded by default)
```

## License and citation

Code: MIT, see [LICENSE](LICENSE). Datasets keep their own terms:
- CSE-CIC-IDS2018: cite Sharafaldin, Lashkari, Ghorbani, ICISSP 2018.
- NetFlow v3 (UQ): re-use with commercial restriction; cite Luay et al. 2025,
  arXiv:2503.04404.
- CTU-Normal and IoT-23 (Stratosphere Lab): cite "Garcia, Sebastian. Malware Capture Facility
  Project, https://stratosphereips.org" and Garcia, Parmisano, Erquiaga 2020 (IoT-23).

Label-error literature: Liu, Engelen et al., IEEE CNS 2022, doi:10.1109/CNS56114.2022.9947235.
Literature review: [`docs/research/literature_review.md`](docs/research/literature_review.md).
