# Phase 8c external validation plan (pre-registration, ToN_IoT)

Frozen with `scripts/phase8c/confirm_external.py` and `scripts/phase8c/toniot.py` in the
commit that adds this file. **The data has not been downloaded**: no ToN_IoT content, label or
statistic has been seen. The script was dry-run only on an inspected development capture
(IoT-23 34-1) converted to the ToN_IoT CSV format
(`reports/phase8c/confirm_external_DRYRUN_dev34-1.json`; a software check, not evidence).

## Why this dataset

| Requirement | ToN_IoT network data |
|---|---|
| Different environment from IoT-23 | UNSW Canberra Cyber Range / IoT Labs (Industry 4.0 testbed: IoT, cloud and edge hosts on Windows, Linux and Kali), not the Stratosphere lab |
| Feature compatibility | Zeek-generated CSV (ts, src/dst ip and port, proto, duration, src/dst_ip_bytes, src/dst_pkts, conn_state), mapped to the same records as our conn.log reader (`toniot.py`; resets from `conn_state` because there is no `history` column) |
| Attack diversity | scanning, DoS, DDoS, ransomware, backdoor, injection, XSS, password and MITM classes, not only scanning-heavy malware |
| Licence | "Free use ... for academic research purposes is hereby granted in perpetuity"; commercial use only after asking the author; cite the eight listed papers (Moustafa et al.). This open-source research project qualifies as academic research use |
| Provenance | https://research.unsw.edu.au/projects/toniot-datasets; SharePoint folder linked there |

**Label reliability.**
- Ground truth was created by tagging the attacker source IPs (192.168.159.30-39) with their
  timestamps. Every flow from those hosts in an attack period is "attack".
- This is coarse: background or response traffic of attacker hosts is labelled attack.
- Results are therefore reported at the window and attacker-host level, and label noise is a
  stated threat.

**Independence.** ToN_IoT comes from the same institution as UNSW-NB15, whose NF-v3 version is
part of our development data. The LightGBM trained for this test **excludes NF-UNSW** (and
49-1); it is trained on IoT-23 x9 + CTU-Normal x12 only.

## Data selection (decided now)

- Network-dataset CSV files from the "Processed" network folder ("Network_dataset_*.csv"),
  taken in numeric order. Stop after 4 files or once the files together reach 2 GB on disk,
  whichever comes first.
- No file is opened before the run, except by the script.
- If the folder layout differs from this description, the run is not started. The deviation
  and the new selection are written here first, without looking at labels.

## Protocol

- Identical to Phase 8b: `scripts/phase8b/harness.py` WindowBuilder.
  - Device level, 30 s windows by flow end time.
  - Calibration = flows ending before the time midpoint; clean variant (benign-labelled
    calibration flows).
  - Streaming with lateness 3,700 s and a 1.5M-record buffer cap.
- Testability: >= 60 calibration windows, >= 5 attack and >= 30 benign evaluation windows.
- Policies:
  - A = deployed;
  - C2 = Mondrian threshold per address class (private/link-local vs external);
  - E = LightGBM with local split-conformal threshold.
  - Definitions as in `scripts/phase8c/policies.py`.
- Uncertainty: 1 h moving-block bootstrap (2,000 resamples, seed 0) for PR-AUC differences;
  Clopper-Pearson for FPR.

## Hypotheses

| ID | Statement | Supported if | Basis |
|---|---|---|---|
| **X1** | The deployed policy keeps FPR <= 3x target on an external network | FPR <= 0.03 and CP upper <= 0.05 (refuted if lower > 0.03) | B4 replicated on 4 IoT-23 captures |
| **X2** | Root-cause prediction | If the tail diagnostic warns (tail_fallback_share > 0.5): C2 window recall > A window recall with C2 FPR <= 0.03. If it does not warn: \|recall(C2) - recall(A)\| <= 0.05 | Phase 8c mechanism (ROOT_CAUSE.md) |
| **X3** | LightGBM trained without any UNSW data ranks better than robust_z | bootstrap CI of PR-AUC(E) - PR-AUC(robust_z_product) > 0 (refuted if < 0) | B1 replicated within IoT-23 |
| **X4** | LightGBM adds ranking power beyond the scanning signature | CI of PR-AUC(E) - PR-AUC(new_dst_frac) > 0 (refuted if < 0) | Phase 8c audit: a single feature matched LightGBM on IoT-23 and beat it on NF-UNSW |
| **X5** | Incidents (deployed policy): window-weighted purity >= 0.8 and alert reduction >= 5 | both (not testable with < 5 incidents) | B6 refuted twice |

Secondary, no verdict:
- attacker-host recall per policy;
- false alerts per hour;
- observable delay;
- LightGBM with the transferred source threshold;
- per-attack-type recall: exploratory, because `type` is read only for this report.

## Resources

- Disk: <= 2 GB for the CSV files.
- Memory: expected < 3 GB peak; the run is guarded by the 3.4 GB watchdog.
- CPU only: expected < 30 min.
- The download needs a browser (SharePoint) and the owner's approval. NetSentinel never
  downloads it automatically.

## Threats to validity

- Testbed (emulated) traffic, not a production network.
- IP-tagged labels.
- Same institution as a development dataset; mitigated by excluding it from training.
- One dataset.
- Attack periods may dominate parts of the timeline, so PR-AUC depends on the base rate
  (comparisons are within-dataset).

## Deviations

**D1 (2026-10-24): adapter BOM bug; software fix only, before any analysis.**
- **What happened.** The first frozen run (frozen code, commit `590f8d2`) stopped before any
  analysis. `toniot.py` yielded 0 records, so the time span was undefined
  (`ValueError: cannot convert float NaN to integer`). No window, label, statistic or verdict
  was produced, and no cache was written.
- **Diagnosis.** Only the header line of each file was read (column names; no data rows). The
  official files begin with a UTF-8 byte-order mark (`EF BB BF`), so the first column name
  was read as `﻿ts`, and every row was skipped for lacking `ts`.
- **Header check.** All four files share the identical header, and every column the plan
  relies on is present with the expected names (ts, src_ip, src_port, dst_ip, dst_port,
  proto, service, duration, src/dst_bytes, conn_state, missed_bytes, src_pkts, src_ip_bytes,
  dst_pkts, dst_ip_bytes, ..., label, type).
- **Fix.** The CSV is opened with `encoding="utf-8-sig"`. A regression test was added.
- **Unchanged:** the adapter's field mapping, the harness, scorers, policies, thresholds,
  hypotheses and criteria.

**After the run (not a deviation):** results are in [EXTERNAL_RESULTS.md](EXTERNAL_RESULTS.md).
The run exposed a streaming clock-freeze defect after real time gaps. It was fixed afterwards
in the product, with no effect on this run's windows (0 late records), and the frozen result
was not repeated.
