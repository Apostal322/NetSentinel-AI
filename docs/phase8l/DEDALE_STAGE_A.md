# Phase 8l DEDALE Stage A: download and gate outcome

**Date:** 2026-11-02.
**Authorized by the user:** "download the 28 Stage A members of green_internal.zip (D1-D14
conn_labeled.csv and dhcp.log, 383,993,579 bytes) by byte range … and run the Stage A gate
N1-N6 (counts only, no scores) under run_capped. No Stage B, no model fitting."

**What was done:**
- **Download:** 28 members, fetched in 112.5 s. All 28 match the publisher's CRC32 and both
  sizes. SHA-256 of each deflate stream: `reports/phase8l/dedale_fetch_stageA.json`.
  - The files total 367 MB on disk, under the git-ignored `data/raw/dedale/green_internal/`.
- **Gate:** `scripts/phase8l/dedale_stage_a.py`, under `run_capped.py` (3.4 GiB). Peak 1,176 MiB;
  48 s of processing.
  - It produced counts and P1x calibration windows (features only).
  - **No source model was fitted or loaded, and no window was scored.**
  - No D15–D28 member was downloaded.
- **Pre-data amendment 2** (N6 count form, adapter details, client 3–4 name rule) was committed
  in `d1eabd5` before any row was parsed.
- **Process note.** The first run crashed after parsing, before any gate quantity was printed:
  importing `calibration_audit.py` binds `common` to the Phase 6 module, as in Phase 8k. The
  6-line `sessions()` helper was inlined, as in `probe_f0.py`, and the gate was rerun from the
  start.

## Gate N1–N6: **PASS**

| check | result | rule | |
|---|---|---|---|
| N1 integrity | 0 failures (28/28 CRC32 + sizes) | none | ✔ |
| N2 schema and time | all 22 conn fields and the label columns present; 0 unparseable rows of 8,043,889; 0 flows ending > 2 h outside their folder's UTC day; 0 calibration flows ending after the boundary | ≤ 1 % per day | ✔ |
| N3 calibration labels | label 0 on all 8,043,889 rows of D1–D14 | no label ≠ 0 | ✔ |
| N4 eligible primary hosts | **26** | ≥ 20 | ✔ |
| N5 Kish effective hosts / top host share (hold-out windows) | **26.0** / **4.0 %** | ≥ 10 / ≤ 25 % | ✔ |
| N6 eligible hold-out windows (count form) | **54,120** | ≥ 590 | ✔ |
| N6 descriptive: 30 min sessions in the hold-out; Kish effective sessions at ρ = 1 | 104; **52.1** | no criterion | – |

## What the calibration fortnight looks like

- **Day folders are UTC days.** Every folder's `ts` lies within its UTC date, and no
  calibration flow crosses the 2025-01-06 boundary.
- **Volume:** weekdays carry 763k–906k connections; weekends 16k–29k. Christmas and New Year
  have full weekday volume.
- **Windows:**
  - 316,903 P1x calibration windows from 87 sources;
  - the destination memory holds 16,588 destinations;
  - the hold-out starts 2025-01-01 19:07:30 UTC and holds 64,984 windows (all sources).
- **Identity:**
  - `dhcp.log` holds 6,248 leases for the 30 internal addresses;
  - each address has exactly one MAC (`00:50:56:00:00:0k`) and each MAC one address, so
    address and MAC identity coincide in D1–D14;
  - the host names `CLIENTk` confirm the inferred numbering **client k = `172.16.1.(k+1)`**,
    so clients 3–4 are `172.16.1.4` and `.5` by name.
- **Primary population:**
  - 30 internal addresses: 26 eligible, 2 excluded as compromised (`.2`, `.3`), 2 excluded as
    clients 3–4 (`.4`, `.5`);
  - every eligible host has 10,036–10,687 calibration windows and 2,018–2,160 hold-out windows;
  - the secondary population has 5 further eligible sources.

## What this does and does not establish

- **DEDALE now passes everything that can be checked without scores.** The feasibility verdict
  moves from "conditionally eligible, pending the Stage A gate" to **eligible for the
  single-network longitudinal test, pending N8**.
- **The balance is that of clones, not of diverse hosts.** The 26 hosts have near-identical
  window counts, so Kish = 26.0 and the top share is 4 %. That shows balanced volume, not
  behavioural diversity. They are 26 copies of one AURA profile family. External validity stays
  one generator.
- **The main remaining risk is N8.**
  - The hold-out covers 104 host sessions, about 4 per host: the working days of 2 and
    3 January, split by the nightly shutdowns.
  - If scores are strongly correlated within a session, the dependence-adjusted n can fall
    below 590. The ρ = 1 bound is 52.
  - N8 is computed on hold-out scores after the freeze, and **before** any evaluation data is
    downloaded. If it fails, the study ends NOT EVALUABLE at no cost to the evaluation data.
- **The Phase 8l network-level NO-GO is unchanged.**

## Next steps (each needs its own authorization where marked)

1. Write the DEDALE evaluation adapter (labels stored apart from features) and
   `dedale_analysis.py`, and unit-test them on synthetic data.
2. **Needs authorization:** fit the three registered source models (~5 min, B-raw LightGBM on
   the 4 NF-v3 development networks, seeds 0–2) and record their SHA-256.
3. An independent audit, then commit `DEDALE_FREEZE.md`.
4. Score the calibration windows and apply N8. No new data is needed.
5. **Needs authorization:** the Stage B download (396.3 MB) and the single run.
