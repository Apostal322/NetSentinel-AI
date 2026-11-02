# Phase 8j independent validation protocol and compute budget

**Status:** prepared, **not executed**. The development go/no-go rule gave no-go
(DEVELOPMENT_RESULTS.md), so steps 3–8 are not run. No fresh data has been downloaded or
opened. Every step below
that downloads, opens or evaluates fresh data needs the operator approvals listed in
[DATASET_ELIGIBILITY.md](DATASET_ELIGIBILITY.md) section 6. Every run longer than 2 minutes
needs separate approval (section 6 below).

## 1. Data roles

| data | role in Phase 8j | may be used for |
|---|---|---|
| NF-CIC-IDS2018-v3 (development part), NF-UNSW-NB15-v3 (development part), NF-ToN-IoT-v3 | development | everything: design, episodes, method and threshold selection |
| NF-BoT-IoT-v3 | **consumed** (Phase 8i confirmation) | development only; never confirmation |
| NF-CIC / NF-UNSW consumed test parts (last 20% of each day) | consumed | nothing (still never read) |
| F1 probe network `russellmitchell` (AIT) and the F2 probe week (UWF) | integrity probes | telemetry mapping and E3/E4/E6 checks only; **excluded from confirmation** |
| F1: the other 7 AIT networks; F2: the other UWF weeks | **protected confirmation** | the single frozen run only |

## 2. Order of work (each gate is a commit)

1. **Pre-registration commit** (this folder): hypotheses, methods, metrics, success criteria,
   development selection rules. Amendments are appended, never edited in place.
2. **Development runs** (`scripts/phase8j/`, approval for runs > 2 min). All results are
   labelled [E].
   - The P1x builder change: the window builder takes an excluded-host list before it builds
     the destination memory.
   - Rebuilds of the 4 development networks under P1x.
   - Seeds 1–2 of the leakage audit.
   - The episode set.
   - M1–M4 on development, leave-one-network-out, then the selection rule.
3. **Mapping code**: Tstat → canonical flows and Zeek conn (parquet) → canonical flows,
   unit-tested on synthetic records written from the published field definitions, before any
   fresh file exists locally.
4. **Integrity probes** (approvals A1, A2): open only the probe network/week; run the mapping
   and these checks only: record counts, timestamp continuity (largest gap), benign source
   hosts per hour, attack-log presence and format, the share of flows with every canonical
   field. **No source-model score, threshold or detection metric is computed on a probe.**
   Outcomes go in `reports/phase8j/probes.json`. A family that fails E3/E4/E6 on its probe is
   dropped before the freeze (backup: DARPA OpTC for F2, separate approval).
5. **Freeze**: `docs/phase8j/FREEZE.md` records the code commit, the selected method S and its
   abstention threshold τ, the M2 coefficients and feature scalers, the M3 parameters, the
   source models (seed, file hash), and the SHA-256 of every confirmation archive. Nothing in
   the freeze may be changed afterwards.
6. **Confirmation downloads** (approvals A3, A4): verify the hashes and sizes against the
   publisher record. Labels are split out at ingest (section 3).
7. **The single confirmatory run** (`--confirm`, refused unless FREEZE.md exists): builds
   windows, scores, applies every method, writes `reports/phase8j/confirm/`.
8. **Verdicts** against the registered criteria; the hypothesis ledger, RESULTS.md and a final
   report. Post-hoc analyses are labelled [R] and change no verdict. F1 and F2 are then
   **consumed**.

## 3. Label sealing on fresh data

- **Ingest writes two outputs:**
  - the canonical flows **without** any label column;
  - a sealed label file (labels plus attack-log rows) whose SHA-256 is recorded in FREEZE.md.
- **Only two functions may read the sealed file:**
  - `calibration_attackers(network, cal_end)` returns the hosts with an attack whose time is
    **before** `cal_end`. It raises if asked for anything later. It is unit-tested before the
    freeze.
  - `evaluation_truth(...)` is callable only under `--confirm` after the scoring outputs are
    written.
- **Protected guards:**
  - The window builder and every Phase 8j script refuse an F1/F2 confirmation network unless
    `docs/phase8j/FREEZE.md` exists and `--confirm` is passed (the Phase 8i guard pattern).
  - A `--stand-in` dry run on a development network exercises the confirm path before the
    freeze and writes only under `reports/phase8j/smoke/`.

## 4. Splits per fresh network

- **Unit:** an F1 network, or an F2 week. Each has its own calibration and evaluation
  period.
- **Calibration period:** the first half of the unit's time span (by flow end time). The
  evaluation period is the rest, cut into 1-hour blocks. If a published schedule shows the
  main attack chain starting before the midpoint, the calibration still ends at the midpoint
  (no peeking to move it). Calibration-period attackers are then removed by P1x.
- **Benign calibration:** P1x (DATA_INTEGRITY_AUDIT.md section 5). The excluded hosts are
  also kept out of the destination memory.
  - The first 70% of calibration slots is the train part (used by no Phase 8j method, since
    the source model is fixed).
  - The last 30% is the hold-out, as in Phase 8i, so M0 matches the Phase 8i comparator.
  - M0x uses all calibration windows.
- **Verified benign (metrics only):** windows of hosts with no attack label and no attack-log
  entry anywhere in the network's data.
- **Attack windows (metrics only):** windows holding a flow labelled malicious or matching an
  attack-log interval for that source host.

## 5. Failure and edge handling (registered)

- **Too few fresh networks pass the probes** (fewer than 4 networks across F1 + F2 meet E4 and
  E6 after the probes): J1 is **not evaluable**. The run is not done, and the shortfall is
  reported.
- **Blocks with fewer than 30 verified-benign windows:** they count for coverage and recall,
  not for FPR or overrun.
- **A network whose source-model ROC-AUC is below 0.6** (ranking failure from telemetry
  shift): it is still evaluated and reported; ranking failure is reported separately and does
  not excuse a J1 failure.
- **Every outcome**, failure included, goes to the hypothesis ledger. Preserved verdicts:
  Phase 8h (four negative results) and Phase 8i (I1 failure, I2 not evaluable, I3 failure)
  are not revisited.

## 6. Compute budget

| step | CPU time (estimate) | peak memory | GPU | basis |
|---|---|---|---|---|
| Leakage audit, seed 0 (done) | 262 s | 1,514 MiB (measured) | none | `reports/phase8j/logs/capped.jsonl` |
| Threshold statistics (done) | ~3 min | < 300 MiB | none | `reports/phase8j/threshold_stats.json` |
| Leakage audit, seeds 1 and 2 | 2 × ~4.5 min | ~1.5 GiB | none | as seed 0 |
| P1x rebuild of the 4 development networks | ~10 min | ≤ 1.3 GiB | none | Phase 8i audit build times and peaks (NF-CIC 187 s, NF-ToN-IoT 141 s) |
| Development episodes (9 domains × 90 calibration variants × blocks) and features | ~5–10 min | ≤ 1.5 GiB | none | grouped exceedance dominates; reads saved scores |
| M1–M4 on development, leave-one-network-out | < 2 min | < 1 GiB | none | logistic regression on < 10⁶ rows |
| Final source models (4 development networks, seeds 0–2) | ~5 min | ~1.5 GiB | none | Phase 8i `fit_source` |
| F1/F2 probes: download, map, check | < 5 min | < 1 GiB | none | 24.5 MB of files |
| F1/F2 confirmation: ingest and windows | ~10–20 min | ≤ 2 GiB target | none | streamed, row-group reads |
| Confirmatory scoring and evaluation | < 5 min | ≤ 1.5 GiB | none | |
| **Total** | **≈ 1 h CPU** | **hard cap 3.4 GiB** (`scripts/run_capped.py`) | none | |

- Every step runs under `scripts/run_capped.py --record reports/phase8j/logs/capped.jsonl`.
- Memory compliance is **measured per run, not assumed**. In particular, compliance on the
  fresh networks is shown by their own capped records.
- One Python ML process at a time. Free RAM is checked before each step: about 1.5 GB was free
  during this session, so heavy steps wait for headroom.
- No paid or remote compute is needed.
