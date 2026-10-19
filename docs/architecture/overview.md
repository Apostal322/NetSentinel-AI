# Architecture

Everything on this page exists in the repository and is exercised by tests unless it is
explicitly marked *not implemented*.

```
 CSE-CIC-IDS2018 processed CSVs (public S3, ETag-verified)
          | netsentinel data verify / ingest        src/netsentinel/data/
          v
 per-day typed Parquet (12h-clock fix, invalid rows dropped, labels canonicalised)
          | netsentinel data eda, scripts/label_quality.py
          v
 causal context features (5 s / 30 s / 300 s trailing windows, chunked)   features/context.py
 + stratified sample with inverse-probability weights                       features/build.py
          | netsentinel features build
          v
 split protocols + leakage checks (random | blocked | chronological | episode | leave-day-out)
          |                                                                 data/splits.py
          v
 training stages (separate processes, run ledger per run)                   training/
   baseline  - dummy / logreg / random forest / HistGB / LightGBM (binary, label, family)
   anomaly   - robust-z, Isolation Forest; global vs service-conditioned
   openset   - leave-one-attack-family-out, supervised vs anomaly vs OR-fusion
          | netsentinel evaluate --final  (test split, once per run)
          v
 model bundle (threat + anomaly + attack type + evidence baselines + thresholds,
               isotonic calibration, SHA-256 manifest)                      inference/bundle.py
          v
 inference engine -> Prediction contract (inference/schema.py)              inference/engine.py
   service (port heuristic) | anomaly score 0-100 | P(malicious) | attack type or unknown
   | verdict benign/unusual/suspicious/attack | measured evidence | model versions
          |
          +--> offline replay (event-time order, pacing, idempotent ids)    streaming/replay.py
          +--> FastAPI (localhost; admin-token replay control)              api/app.py
          v
 SQLite event store (indexed, retention purge)                              storage/events.py
          v
 Streamlit dashboard (read-only on the same store + reports)                dashboard/app.py
```

## Key design decisions

| Decision | Reason |
|---|---|
| Event time = flow start + duration; context uses only complete seconds before it | A flow record exists only once the flow ends; no look-ahead (tested against brute force and a truncation test) |
| Context computed on the full day stream before sampling | Matches what a sensor sees; sampling would otherwise change the features |
| Episode-chronological split by default | Each IDS2018 attack is mostly one contiguous session per day; random 15-min blocks put whole attacks in one partition (measured), random rows put identical neighbours on both sides |
| Purge 150 s around partition boundaries | Rows of different partitions are >= 300 s apart, the longest context window |
| Inverse-probability `sample_weight` | Metrics estimate the prevalence of the available data, not of the sample |
| Anomaly score as benign-tail percentile | Interpretable, threshold maps to an expected benign alert rate; explicitly not a probability |
| Decision layer separates `unusual` from `suspicious`/`attack` | An anomaly is not an attack; unknown attack types abstain to `unknown` |
| One heavy framework per process, lazy imports | 8 GB RAM development machine |

## Not implemented

* Live packet capture, Zeek/Suricata ingestion (Zeek and Docker are not installed on the
  development machine; see docs/limitations).
* Per-host baselines: the processed IDS2018 CSVs carry no host addresses (except one day).
* Application identification: only port-derived service categories are available on IDS2018.
