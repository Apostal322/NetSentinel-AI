# Phase 8k dataset independence, licensing and compute

**Date:** 2026-11-02. Re-checked at the publishers' pages on this date; nothing downloaded.

## 1. Development data: how many independent units?

| network | institution / lab | testbed, year | exporter | P1x hold-out hosts (effective) | adequate at T0? (3-seed FPR) | role |
|---|---|---|---|---|---|---|
| NF-CIC-IDS2018-v3 (6 day-domains) | UNB CIC (Canada) | AWS testbed, 2018 | nProbe v3 | 4,736–6,557 (477–651) | yes (1.0–1.6%) | development |
| NF-UNSW-NB15-v3 | UNSW Canberra Cyber Range | IXIA testbed, 2015 | nProbe v3 | 17 (12.3) | no (3.7%) | development |
| NF-ToN-IoT-v3 | UNSW Canberra Cyber Range | IoT/IIoT testbed, 2019 | nProbe v3 | 3,635 (92.8) | no (14.8%) | development |
| NF-BoT-IoT-v3 | UNSW Canberra Cyber Range | IoT testbed, 2018 | nProbe v3 | 7 (2.2) | no (11.9%) | consumed in Phase 8i; development only |

- **Independent network units: 4. Institutions: 2.** Three networks share one lab, and all
  four share one exporter and one feature pipeline (UQ NetFlow v3).
- **NF-CIC's 6 days are one environment.** They count as one unit in every cross-network
  statement. Day-level rows are shown only as within-network replication.
- **Adequacy is 1 vs 3:** one adequate network and three unsafe ones. Any discrimination
  statistic over 4 networks has an exact 95% interval spanning most of [0, 1].
- **Seeds, hosts, days, subsampled calibrations and synthetic shifts are NOT independent network
  samples.** The within-network stress tests (DEVELOPMENT_EXPERIMENTS.md section 4) are stress
  tests only.

**Other local data** (`data/raw`), checked for further development networks:

| data | why it is not another independent development network |
|---|---|
| CSE-CIC-IDS2018 CICFlowMeter CSVs | the same network as NF-CIC |
| ToN_IoT network CSVs | the same network as NF-ToN-IoT |
| CTU-13 scenarios 9 and 10 | consumed (Phase 8g) |
| IoT-23 (13 scenarios) | single infected device or honeypot per capture; few hosts; Zeek telemetry |
| CTU-Normal 20–32 | one benign host per capture, recorded at different times: pooling them would build an artificial "network", not observe one |

**Conclusion:** no further genuinely distinct multi-host development network exists locally. A
learned network-level reliability classifier is not supportable: 4 units, 2 institutions,
1 adequate.

## 2. Fresh families (untouched; status preserved)

| | F1: AIT Netflow Data Set v2 | F2: UWF-ZeekData24 |
|---|---|---|
| publisher | AIT Austrian Institute of Technology; Zenodo 10.5281/zenodo.13168643, v2, 2024-08-02 (re-checked: live, no newer version listed) | University of West Florida, datasets.uwf.edu (re-checked: live) |
| licence | CC BY 4.0 (record page) | CC BY 4.0 per the portal statement; no licence file in the dataset folder |
| files and sizes (verified on the listing pages) | 8 zips: 20.8 (russellmitchell), 25.7, 25.9, 31.2, 34.6, 37.8, 41.2, 56.4 MB = 273.7 MB | 7 weekly snappy parquet files: 3.7 (2024-03-03), 7.8, 12.3, 18.8, 27.8, 33.2, 36.6 MB = 140.2 MB; also a `csv/` copy |
| telemetry | Tstat flows from server-side and attacker captures (README) | Zeek `conn` |
| labels | per-flow labels from the attack logs; `label_info.txt` (a 1 kB text file read online in Phase 8j, not a dataset file): 13 benign TCP, 39 malicious TCP, 1 malicious UDP category | flow-level label columns inside the parquet (expected; not yet seen). **No separate mission or attack logs are published** at the dataset root (`csv/`, `parquet/` only) |
| environment | 8 separately generated emulated small enterprises; simulated users | VMware cyber range; VM background traffic; earlier reports suggest 50/50 benign sampling (unverified) |
| decision units | 7 networks (russellmitchell is the probe) | 6 weeks (2024-03-03 is the probe); one environment |
| independence | 1 family: its networks share a generator | 1 family: its weeks share hosts and range |

**What remains unverified, and is checked only at the probes:**
- the per-direction and RST fields in the AIT CSVs;
- benign host counts at the server-side vantage point;
- UWF benign sampling and its label columns;
- the AIT DNS-exfiltration host from the start of each simulation.

**Fallback for F2:** DARPA OpTC (about 1 TB, separate approval) if the UWF probe fails.

## 3. Compute and download budget

| step | size / time | memory | approval |
|---|---|---|---|
| development experiments (done) | 523 s, re-thresholding only | 574 MiB | ran under the Phase 8k task |
| confirmatory analysis, development dry run (done) | 142 s (final version) | 861 MiB | – |
| probes A1 + A2 | 20.8 + 3.7 MB | < 1 GiB | **required** |
| Tstat / Zeek mapping on the probes, and probe feasibility checks | minutes | < 1 GiB | with A1/A2 |
| source models for confirmation (4 NF-v3 networks × 3 seeds) | ~4–5 min | ~1.6 GiB | **required** (> 2 min) |
| confirmation downloads A3 + A4 | 252.9 + 136.5 MB | – | **required** |
| ingest, P1x windows, scoring, analysis | ~20–30 min in total | ≤ 2.7 GiB (the N4 P1x build peaked at 2,664 MiB) | **required** (the protected run) |

All steps run under `scripts/run_capped.py` (3.4 GiB). No GPU, paid or remote compute.
