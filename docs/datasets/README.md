# Dataset provenance

No dataset, capture or derived Parquet file is committed. Everything is downloaded by the
documented scripts into `data/` (git-ignored) and verified against recorded hashes.

| Dataset | Source | Licence / terms | Size | Integrity | Used for | Status |
|---|---|---|---|---|---|---|
| CSE-CIC-IDS2018, processed CSVs (CICFlowMeter) | UNB/CIC, public AWS bucket `cse-cic-ids2018` ([details](cse_cic_ids2018.md)) | cite Sharafaldin et al., ICISSP 2018 | 6.9 GB | S3 multipart ETags (`netsentinel data verify`) | Phases 1–3 development; one pre-registered test (2026-10-19) | test **spent** |
| NF-CICIDS2018-v3, NF-UNSW-NB15-v3 (nProbe NetFlow v3) | UQ Research Data Manager ([details](nf_v3.md)) | "Permitted Re-Use with Commercial Use Restriction"; cite Luay et al. 2025, arXiv:2503.04404 | 0.9 GB zips | BagIt SHA-1 + SHA-256 (`reports/audit/dataset_hashes_2026-10-20.txt`) | Phases 4–7 development; one pre-registered test (2026-10-20); app-ID training | test **spent** (last 20% of every day) |
| CTU-Normal-26 (PCAP + Zeek conn.log) | Stratosphere Lab, MCFP ([details](ctu_normal_26.md)) | free use with citation: Garcia, Sebastian. Malware Capture Facility Project, https://stratosphereips.org | 113 MiB + 1.7 MB | MD5 matches the published value; SHA-256 recorded | PCAP/Zeek validation (Phase 5); real-capture demos | inspected |
| CTU-Normal-20..25, 27..32 (Zeek conn.log) | Stratosphere Lab, MCFP | as above | 47 MB | SHA-256 (`reports/audit/phase6_external_data_sha256.txt`) | Phase 6 H1/H7; Phase 7 diagnosis | inspected |
| IoT-23, 9 labelled scenarios (Zeek conn.log.labeled) | Stratosphere Lab, IoT-23 (Garcia, Parmisano, Erquiaga 2020) | free use with citation | 30 MB | SHA-256 (same file) | Phase 6 H3–H5 (exploratory); Phase 7 trade-off check | inspected |

**Terminology.**
- *Spent*: the test partition was used once for a pre-registered evaluation and must not be
  used for model selection again.
- *Inspected*: results on it have been seen, so it no longer supports a new confirmatory
  claim.
- A new confirmatory claim needs a capture that has never been looked at.

**Privacy.** The public captures contain lab IP addresses (e.g. 10.0.2.15, 192.168.1.x).
In NetSentinel's event store, flow events have no endpoint fields. The originating device's
address appears only in `behavior.model_scope` (e.g. `device:10.0.0.1`) when a device-level
profile was used. Behaviour-window rows store it as their entity key. Retention purge applies to both tables. No packet payloads are stored.
