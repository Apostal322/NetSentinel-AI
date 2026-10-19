# Dataset card: NetFlow v3 (NF-UNSW-NB15-v3, NF-CSE-CIC-IDS2018-v3)

Measured on 2026-10-19 unless marked otherwise. Machine-readable: `configs/datasets/nf_v3.yaml`
(provenance, sizes, ETags), `configs/datasets/nf_v3_ingest.yaml` (time zones, label/family
maps), `data/interim/*/ingest_report.json`, `reports/audit/nf_vs_cic.json`.

## Provenance and integrity

| | NF-UNSW-NB15-v3 | NF-CSE-CIC-IDS2018-v3 |
|---|---|---|
| Source | UQ Research Data Manager (open access), via https://staff.itee.uq.edu.au/marius/NIDS_datasets/ | same |
| License | "Permitted Re-Use with Commercial Use Restriction" | same |
| Citation | Luay et al., *Temporal Analysis of NetFlow Datasets for NIDS*, arXiv:2503.04404 (2025) | same |
| Archive | 110,825,147 bytes, S3 multipart ETag verified | 780,113,687 bytes, ETag verified |
| CSV | 577,360,958 bytes, BagIt SHA-1 verified at ingest | 4,222,783,755 bytes, SHA-1 verified |
| Flows ingested | 2,365,424 | 20,115,529 |
| Extractor | nProbe, 53 NetFlow v3 features incl. epoch-ms start/end timestamps, IPs, nDPI L7 protocol | same |

## Ingestion decisions

* Timestamps: epoch ms (UTC) converted to naive local time. IDS2018: UTC-4 (AST) - **verified**
  below. UNSW-NB15: UTC+11 (AEDT) - **assumption**; traffic is generated around the clock
  (flows in every hour of day), so the offset cannot be confirmed from activity patterns. It
  only affects day boundaries used for splits (captures fall on 2015-01-22/23 and 2015-02-18).
* Empty cells in non-core float fields become null and are counted (UNSW: 63,425 empty
  `SRC_TO_DST_SECOND_BYTES`); any other malformed value aborts ingestion.
* Labels: NF-IDS2018 attack names are renamed to the same canonical labels as the CIC CSVs
  (e.g. `DoS_attacks-Hulk` -> `dos_hulk`). Families as for IDS2018. UNSW families: exploit
  (exploits, backdoor, shellcode, worms), recon (reconnaissance, analysis), fuzzing, generic, dos.
* Never features: IPs, source port, timestamps, `L7_PROTO` (nDPI label), DNS/FTP app fields.
  TTL and TCP max-window fields are flagged shortcut suspects (`nf_flow_noshortcut` ablation).

## Label distribution (full data)

NF-UNSW-NB15-v3: benign 2,237,731; exploits 42,748; fuzzers 33,816; generic 19,651;
reconnaissance 17,074; dos 5,980; backdoor 4,659; shellcode 2,381; analysis 1,226; worms 158.

NF-IDS2018-v3: benign 17,514,626; HOIC 1,032,311; FTP-BF 386,720; LOIC-HTTP 288,589;
bot 207,703; SSH-BF 188,474; infiltration 188,152; SlowHTTPTest 105,550; Hulk 100,076;
GoldenEye 61,300; Slowloris 36,040; LOIC-UDP 3,450; web BF 1,618; XSS 480; SQLi 440.

## Cross-check with the CIC CSVs (same 2018 traffic, different extractor)

* **12-hour-clock correction independently confirmed.** First-flow local times of every main
  attack agree to the second between NF (epoch-derived) and our corrected CIC times: e.g.
  SSH-BF 14:01:21 (NF 14:01:21.199), Hulk 13:45:27 (13:45:27.826), HOIC 14:11:08
  (14:11:08.829), FTP-BF 10:33:26 (10:33:26.718); 0-minute difference for all 10 main attack
  labels. Without the correction the afternoon attacks would be 12 h off.
* **Flow counts differ substantially between extractors**: CIC/NF ratio 0.50 for FTP-BF,
  4.6 for Hulk, 2.0 for LOIC-HTTP, 1.4 for Bot; NF has 1.5-2.0 M benign flows on every day
  (CIC: 0.24-1.0 M on truncated days, 7.4 M on 02-20). The CIC truncation is real, and flow
  construction differs (timeouts, FIN handling).
* **Labelling differs**: NF has **no web-attack labels on 2018-02-23**; on 02-22 its web
  brute-force / XSS labels start at 08:24-08:25 (CIC: 10:13 / 13:51); Infiltration windows
  differ by up to ~2.5 h. Results on the two releases are therefore not label-identical.
