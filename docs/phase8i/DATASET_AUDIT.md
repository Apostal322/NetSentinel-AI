# Phase 8i dataset audit

**Date:** 2026-11-02. **Sources:** the dataset README, the hypothesis ledger, the phase
development logs and the confirmatory reports. Every "used for" entry below was checked against
those documents, not inferred from file names.

## 1. Previously used data

| dataset / partition | used for | status for Phase 8i |
|---|---|---|
| CSE-CIC-IDS2018 CICFlowMeter CSVs, development days | Phases 1–3 development | development permitted |
| CSE-CIC-IDS2018 CIC test split | one pre-registered test (2026-10-19) | **consumed**: never used |
| NF-CIC-IDS2018-v3, first 78% of each day | Phases 4–8h development; Phase 8h LODO | development permitted (inspected) |
| NF-CIC-IDS2018-v3, last 20% of each day | one pre-registered test (2026-10-20) | **consumed**: never read (`read_day` cuts at 78%) |
| NF-UNSW-NB15-v3, first 78% / last 20% | development / consumed test (2026-10-20) | development permitted / **consumed** |
| ToN_IoT network CSVs, files 1–4 | Phase 8c external evaluation (X1–X3) and retrospective audit | **consumed** (network inspected) |
| IoT-23: 9 Phase 6 scenarios (incl. 3-1, 8-1, 34-1, 20-1, 21-1, 42-1, honeypots 4-1, 5-1) | Phases 6–8h development | development permitted (inspected) |
| IoT-23 49-1 | Phase 8 confirmatory | **consumed** |
| IoT-23 1-1, 60-1, 9-1 | Phase 8b confirmatory | **consumed** |
| CTU-Normal-20..32 (26 incl. PCAP) | Phases 5–8h benign units | development permitted (inspected) |
| CTU-13 scenarios 9, 10 | Phase 8g confirmatory | **consumed** |
| CTU-13, other scenarios | never downloaded | protected unused (not needed here) |

No "uncertain provenance" entries: every file under `data/raw` matches a manifest hash
(`reports/audit/*sha256*`, `configs/datasets/*.yaml`).

## 2. Candidates for a fresh evaluation network

| candidate | schema fit | independence | labels / benign | size | decision |
|---|---|---|---|---|---|
| **NF-BoT-IoT-v3** (UQ, nProbe v3) | identical to development (53 NetFlow v3 fields) | never opened. Same institution as UNSW-NB15 and ToN_IoT (UNSW Canberra Cyber Range); different testbed (IoT, 2018), devices and attack tooling | DDoS, DoS, reconnaissance, theft; 51,989 benign of 16.99M flows (0.3%) | 73.0 MB zip | **protected confirmatory test** |
| NF-ToN-IoT-v3 (UQ, nProbe v3) | identical | the ToN_IoT network was inspected in Phase 8c (files 1–4) | 61% benign; Phase 8c found label/initiator problems | 417.5 MB zip | **development network N3** (a third network for development folds), never confirmatory |
| CIC-IDS2017 (CICFlowMeter; improved WTMC-2021 re-extraction) | different flow exporter: a telemetry shift on top of the network shift | different network, same lab group as CIC-IDS2018 | known labelling errors (Engelen et al. 2021) | size not verified | not chosen: it confounds exporter and network shift |
| UGR'16, LITNET-2020, CIDDS-001 | unidirectional NetFlow: no reply bytes, so no `no_reply_frac` or `log_down_bytes` | independent organisations | partly synthetic or blacklist-based labels | not checked | not chosen: feature incompatibility |

**Why NF-BoT-IoT-v3:** the same exporter and feature set as development removes telemetry
incompatibility as an explanation, it is small, and no phase has opened it. Its weaknesses are
stated in [PREREGISTRATION.md](PREREGISTRATION.md) section 8: a shared institution, few
attacker hosts, and very little benign traffic.

## 3. Integrity of the new archives

Downloaded on 2026-11-02 with operator approval (`scripts/download_nf_v3.py
configs/datasets/nf_v3_phase8i.yaml`). Both match the S3 size and multipart ETag recorded
before download (`netsentinel data verify`: 2/2 ok).

| file | bytes | SHA-256 |
|---|---|---|
| NF-ToN-IoT-v3.zip | 417,476,635 | `b3b6256e970a8986d87716edea4bfd436d68f04058bf5c26cf67e6d839c83698` |
| NF-BoT-IoT-v3.zip | 72,956,946 | `cd0d3eab5b2da73a377561492aafae078432e69c7932b6302a9fbd7f51429eca` |

**Licence:** "Permitted Re-Use with Commercial Use Restriction". Cite Luay et al.,
arXiv:2503.04404 (2025). The NF-BoT-IoT-v3 archive has not been extracted or read. Its ingest
label map was written from the published category names before opening
(`configs/datasets/nf_v3_ingest.yaml`).

## 4. Protected-data controls

- `scripts/phase8i/build_windows.py nfbot` exits unless `docs/phase8i/FREEZE.md` exists and
  `--protected-confirm` is passed.
- FREEZE.md records the frozen commit and the outcome of the development selection rules.
  It is written only after all development runs.
- Before freeze, nothing may compute a label count, score or feature distribution from N4.
