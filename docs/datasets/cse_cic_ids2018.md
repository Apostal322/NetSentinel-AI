# Dataset card: CSE-CIC-IDS2018 (processed CICFlowMeter-V3 CSVs)

All numbers on this page are **measured** on the files listed in
`configs/datasets/cse_cic_ids2018.yaml`, unless marked otherwise. Machine-readable versions:
`reports/eda/eda.json`, `reports/eda/label_quality.json`, `reports/eda/summary.txt`,
`reports/eda/clock_check.txt`.

## Provenance

| | |
|---|---|
| Source | UNB / CIC dataset page https://www.unb.ca/cic/datasets/ids-2018.html; files from the public AWS bucket `cse-cic-ids2018`, prefix `Processed Traffic Data for ML Algorithms/` |
| Retrieved | 2026-10-19 with `scripts/download_ids2018.sh` |
| Integrity | All 10 files match the bucket's sizes **and** S3 multipart ETags (16 MiB parts), recomputed locally by `netsentinel data verify` |
| Citation required by UNB | Sharafaldin, Lashkari, Ghorbani, ICISSP 2018. Note: that paper describes CICIDS2017; there is no dedicated peer-reviewed paper for IDS2018 (see `docs/research/literature_review.md`, sections 2.1-2.2) |
| Not in git | Raw CSVs (6.9 GB) and Parquet stay under `data/` (git-ignored) |

## Ingestion (`netsentinel data ingest`)

Streaming CSV -> typed Parquet per capture day (pyarrow block reader, Polars typing; peak RAM
is a few 64 MB blocks). Strict numeric casts: any malformed cell aborts ingestion. Unknown
labels abort ingestion. Canonical snake_case names (`Flow Byts/s` -> `flow_byts_per_s`).

### Corrections applied at ingestion

1. **12-hour clock without AM/PM.** Every day's timestamps lie in clock hours 01-12, and hours
   06-07 are (almost) empty. Attack windows match the UNB schedule only when clock hours 01-07
   are read as 13-19 h: e.g. SSH brute force on 2018-02-14 appears at 02:01-03:32 (UNB: 14:01-15:31),
   DoS-Hulk on 2018-02-16 at 01:45 (UNB: 13:45), HOIC on 2018-02-21 at 02:11 (UNB: ~14:05), XSS
   on 2018-02-22 at 01:51 (UNB: 13:50); morning attacks match as-is (FTP brute force 10:33,
   GoldenEye 09:27, LOIC-UDP 10:08, web brute force 10:13). File row order cannot confirm this
   (most files are shuffled; 2018-03-01 is string-sorted, which places "01:.." before "08:.."),
   so the correction rests on the schedule match and the empty 06-07 h gap. Clock hours < 8 get
   +12 h, flagged per row in `clock_corrected`. **Without this fix, event-time ordering and every
   trailing-window feature would mix morning and afternoon traffic.**
2. **Invalid timestamps.** 14 rows (2018-02-14: 5, 2018-02-22: 9) carry 1970 dates together with
   negative durations; they are dropped and counted in `ingest_report.json`.
3. **Repeated header rows** inside files are dropped and counted.

### Kept as-is (handled downstream)

* `Infinity` / `NaN` in `flow_byts_per_s`, `flow_pkts_per_s` (zero-duration flows), kept as IEEE
  values; models map them to NaN explicitly.
* `-1` sentinel in `init_fwd_win_byts`, `init_bwd_win_byts` (not observed); very common.
* The 2018-02-20 file has `Flow ID`, `Src IP`, `Src Port`, `Dst IP`; kept only for leakage
  analysis, never as features.

## Findings that shape the evaluation

| Finding (measured) | Consequence |
|---|---|
| 7 of 10 files hit the Excel limit of 1,048,575 lines below the header (02-14, 02-15, 02-16 counting its one repeated header line, 02-21, 02-22, 02-23, 03-02) | Those days are **truncated** exports (02-21 ends at 14:33, inside the HOIC attack; 02-16 ends at 13:48, inside Hulk). Volumes on those days are not true capture volumes, so prevalence-weighted metrics are "per available data", not per real day. |
| Each attack type occurs on one or two days only | Attack family is confounded with capture day. Leave-day-out tests are therefore open-set tests by construction. |
| On 2018-02-20, 10 source IPs produce 100 % of the 576,191 attack flows | Source IP is a perfect label proxy -> excluded from features. |
| Exact duplicate feature vectors are common (e.g. 2018-02-16: 456,673 duplicate rows of 1,048,574) | Random row splits place identical vectors in train and test; measured in the leakage report of each run. |
| Identical feature vectors with conflicting labels: 51,384 groups on 2018-02-28 and 8,227 on 2018-03-01 (Infiltration vs Benign) | Infiltration labels are not learnable from flow features as given; see label-quality section. |
| 8 columns are constant over all days (`bwd_psh_flags`, `bwd_urg_flags`, 6 bulk-rate columns) | Dropped from the feature schema (enforced by a data test). |
| Strongest single-feature separator is `fwd_seg_size_min` (univariate ROC-AUC 0.75, benign vs attack, 50k-row/day sample) | Known collection artefact (Engelen et al. 2021); evaluated with and without via the `flow_noshortcut` feature set. |

## Label quality (measured by `scripts/label_quality.py` -> `reports/eda/label_quality.json`)

| Probe | Result | Decision |
|---|---|---|
| FTP-BruteForce (02-14) vs DoS-SlowHTTPTest (02-16) | 54 and 55 distinct feature vectors respectively; 52 are shared and cover 193,353 / 193,360 FTP rows and 139,884 / 139,890 SlowHTTPTest rows | Consistent with the documented failed attacks on closed port 21. Merged into one class `port21_failed_conn` for attack-type tasks; kept as malicious in the binary task. Per-label recall reported separately, because these trivially repeated vectors inflate aggregate metrics. |
| Infiltration rows identical to a benign row of the same day | 58,208 / 68,871 (84.5 %) on 02-28; 16,319 / 93,063 (17.5 %) on 03-01 | Labels not learnable as given. Excluded from supervised training and headline metrics (`drop_labels: [infiltration]`); kept for a separate noisy-slice evaluation. |
| Web brute force on 02-23: protocol/port | 211 TCP/80, 126 UDP/500, 21 protocol 0, 2 UDP/67 (151 of 362 non-HTTP = 41.7 %, matching Liu et al. 2022) | Label cleaning v1: web attacks and LOIC-HTTP must be TCP/80; other rows with those labels are dropped (counts recorded per run in `leakage_report.json`). |
| LOIC-HTTP on 02-20 | 575,394 of 576,191 (99.9 %) TCP/80 | Same rule removes the remainder. |
| Infiltration ports | DNS/53 (28-36 %), 443, 3389, 445, 135, 139 ... | Mostly ordinary-looking traffic from the infected host, consistent with the above. |

Corrected relabellings exist (DistriNet 2023, LycoS-Unicas-IDS2018) but use re-generated
features and were **not** used here; results on the original labels carry this caveat.

## Attack labels and families

| canonical label | family | day(s) |
|---|---|---|
| ftp_bruteforce, ssh_bruteforce | bruteforce | 02-14 |
| dos_goldeneye, dos_slowloris | dos | 02-15 |
| dos_slowhttptest, dos_hulk | dos | 02-16 |
| ddos_loic_http | ddos | 02-20 |
| ddos_loic_udp, ddos_hoic | ddos | 02-21 |
| web_bruteforce, web_xss, web_sql_injection | web_attack | 02-22, 02-23 |
| infiltration | infiltration | 02-28, 03-01 |
| bot | botnet | 03-02 |

There is **no port-scan class** (an Nmap scan inside the Infiltration stage is labelled
Infiltration) and **no exfiltration class**; NetSentinel does not claim to detect either.
