# NetSentinel AI

Leakage-aware machine learning for network-flow intrusion detection on CSE-CIC-IDS2018:
causal temporal context, normal-behaviour (anomaly) modelling, abstaining attack-type
classification, an offline replay pipeline, a local API and a dashboard.

The project's main contribution is **evaluation honesty** rather than a new model. It shows,
with measured numbers, where the near-perfect scores commonly reported on IDS2018 come from,
and which parts survive a leakage-aware protocol.

> Status (2026-10-19): research prototype, v0.1. Detection only. All results come from one
> public benchmark, one seed and a stratified sample; see [Limitations](#limitations).

## Key findings (measured)

Full tables with run ids: [`reports/experiments/results_v1.md`](reports/experiments/results_v1.md).
Discussion: [`docs/experiments/report_v1.md`](docs/experiments/report_v1.md).

| Finding | Evidence |
|---|---|
| The IDS2018 CSV timestamps use a **12-hour clock without AM/PM**. Without correction, afternoon traffic is sorted before the morning and every temporal feature is wrong | Attack windows match the UNB schedule only after +12 h for clock hours 01-07 ([dataset card](docs/datasets/cse_cic_ids2018.md)) |
| 7 of 10 CSVs are truncated at Excel's 1,048,575-row limit; 84.5 % of Infiltration rows on 02-28 are byte-identical to benign rows; FTP-BruteForce and DoS-SlowHTTPTest are the same failed port-21 traffic | `reports/eda/label_quality.json` |
| Tree ensembles reach **PR-AUC 1.000 on attacks seen in training**, under random *and* episode-chronological splits | validation, E1 / H5 |
| On the pre-registered **test split** (used once): LightGBM recall **0.983** [0.93, 1.00] at FPR 0.0009, i.e. ~91 false-alert flows/hour | `runs/.../test_metrics.json` |
| Removing 4 known collection-artefact fields drops test recall to **0.735**; HOIC detection falls from 1.00 to **0.07** | shortcut ablation |
| With an attack family **held out of training**, adding causal 5/30/300 s context raises recall at FPR 1e-3 from 0.23 to **0.97** (DoS), 0.51 to **0.998** (brute force), 0.004 to **0.61** (botnet); web attacks stay undetected | E6 |
| Label-free anomaly detectors (Isolation Forest, robust z), global or service-conditioned, have recall ~0 at FPR 1e-3; OR-fusing them with the classifier **lowers** recall | E3, E6 |

## Architecture

```
public CSVs --verify/ingest--> per-day Parquet --context + sample--> dataset
   --> split protocols + leakage checks --> training stages (ledger per run)
   --> model bundle (hash-checked) --> inference engine --> replay / API --> SQLite --> dashboard
```

Details: [`docs/architecture/overview.md`](docs/architecture/overview.md).

**What is implemented and tested**

* Data: ETag-verified download, streaming ingest (bounded memory), EDA, label-quality probes.
* Features: versioned schema; causal multi-scale context features (exact against brute force,
  no look-ahead test); causal per-port flow sequences.
* Splits: random, blocked, chronological, **episode-chronological** (default), leave-day-out;
  automated leakage checks on every run.
* Models: dummy, logistic regression, random forest, HistGB, LightGBM (binary, attack type,
  family); robust-z and Isolation Forest anomaly models (global / service-conditioned);
  leave-one-family-out evaluation; GRU / MLP temporal models (code and tests; **not yet
  trained**, see roadmap).
* Inference: one prediction contract that separates calibrated P(malicious), attack-type
  confidence with `unknown` abstention, a 0-100 anomaly score (benign-tail percentile, not a
  probability), verdicts `benign | unusual | suspicious | attack`, evidence derived from
  measured feature deviations, and model versions.
* Serving: offline replay in event-time order, SQLite event store with retention, FastAPI
  (`/health /ready /models /predict/flow /predict/batch /events /metrics/summary /replay/*`),
  Streamlit dashboard.
* Engineering: uv lockfile, 52 CPU tests (unit, ML, integration), ruff, a GitHub Actions
  workflow with dependency and secret scanning (written but **not yet executed**: the repo has
  no remote yet), run ledger with git SHA, versions and peak memory.

## Quick start

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). The tests need no data download.

```bash
uv sync
```

```bash
uv run pytest
```

Reproduce the data pipeline (6.9 GB download; verify + ingest + EDA + feature build took about
20 minutes on a 4-core / 8 GB machine, plus download time):

```bash
bash scripts/download_ids2018.sh
```

```bash
uv run netsentinel data verify
```

```bash
uv run netsentinel data ingest
```

```bash
uv run netsentinel data eda
```

```bash
uv run netsentinel features build
```

Run the experiment batch (about 25 minutes, peak about 2.7 GB RAM) and aggregate:

```bash
uv run python scripts/run_batch_v1.py
```

```bash
uv run python scripts/aggregate_results.py
```

Build a bundle from runs, replay a recorded window, serve and explore:

```bash
uv run netsentinel bundle build --threat-run runs/<threat_run> --anomaly-run runs/<anomaly_run> --type-run runs/<type_run>
```

```bash
uv run netsentinel replay --bundle models/<bundle-id> --path data/interim/ids2018/2018-02-14.parquet --start 2018-02-14T14:55:00 --end 2018-02-14T15:40:00
```

```bash
uv run netsentinel serve --bundle models/<bundle-id>
```

```bash
uv run --extra dashboard streamlit run dashboard/app.py
```

### API example

```bash
curl -s -X POST http://127.0.0.1:8000/predict/flow -H "content-type: application/json" -d "{\"timestamp\": \"2018-02-14T15:00:00\", \"dst_port\": 22, \"protocol\": 6, \"flow_duration\": 1000, \"features\": {\"tot_fwd_pkts\": 20, \"tot_bwd_pkts\": 2}}"
```

A single flow carries no traffic history, so context features are listed in
`missing_features`. Batch scoring with `compute_context=true` treats the batch as a stream.

## Dashboard (replay demonstration)

The screenshots are from the running application, replaying **recorded** IDS2018 flows from
2018-02-14 14:53-15:17, which lies mostly in the validation/test parts of the SSH brute-force
episode (the first minutes overlap the training part). This is a pipeline demonstration, not
an evaluation, and not live traffic.

![Overview](docs/images/dashboard_overview_replay.jpg)
![Threats](docs/images/dashboard_threats_replay.jpg)

## Evaluation protocol

* Thresholds are chosen on validation at a prevalence-weighted benign FPR of 1e-3.
* The test split is touched once per run, for runs pre-registered in
  [`docs/experiments/test_preregistration.md`](docs/experiments/test_preregistration.md).
* Metrics: PR-AUC, ROC-AUC, recall at fixed FPR, precision, ECE, macro and weighted F1,
  per-class recall, false-alert flows per hour, and block-bootstrap 95 % CIs on test.
* Every reported number traces to a `runs/<run id>/` directory (config, environment, git SHA,
  metrics, split indices, leakage report).

## Limitations

* One benchmark with documented label errors; original labels were used. Results do not
  transfer to other networks without re-validation.
* Per-host baselines and application identification are **not possible** on this data: no
  host addresses (except one day) and no application labels. "Service" is a port heuristic.
* No live capture, Zeek or Suricata integration; Docker is not set up (neither tool was
  available in the development environment).
* Single seed; no repeated-training variance. The temporal deep-learning experiment is
  implemented but has not been run.
* The API has no TLS, accounts or rate limiting; it binds to localhost and is detection-only.
  See [`docs/security/threat_model.md`](docs/security/threat_model.md).

## Roadmap

1. Train and evaluate the GRU-vs-MLP temporal experiment on the same split.
2. Run 5 seeds for the main comparisons.
3. Cross-dataset validation (corrected IDS2018 relabelling or CICIoT2023).
4. Learned, out-of-fold fusion instead of the OR rule.
5. Dockerfile, plus Zeek `conn.log` ingestion for real deployments.

## References

The literature review with verified sources is in
[`docs/research/literature_review.md`](docs/research/literature_review.md). Dataset:
Sharafaldin, Lashkari, Ghorbani, *Toward Generating a New Intrusion Detection Dataset and
Intrusion Traffic Characterization*, ICISSP 2018. Label errors: Liu, Engelen et al., IEEE CNS
2022, doi:10.1109/CNS56114.2022.9947235.

## License

MIT, see [LICENSE](LICENSE). The dataset is subject to its own terms (UNB/CIC).
