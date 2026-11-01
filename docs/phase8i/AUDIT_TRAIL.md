# Phase 8i audit trail

A chronological record of what was done, in what order, and every deviation. Times are local
(UTC+3). Commits are local unless stated.

## 1. Chronology

| when (2026-11-02) | event |
|---|---|
| 01:0x | Repository verified: `main` = `origin/main` = `613848c`, clean tree, CI green on that commit (Phase 8h closure). |
| 01:1x | Candidate fresh networks surveyed from public metadata only. Archive sizes and ETags read with 1-byte range requests (no download). |
| 01:1x | Operator approved: (1) downloading NF-ToN-IoT-v3 (development) and NF-BoT-IoT-v3 (protected test); (2) a batch of development runs (about 20–40 min, < 2.5 GB, watchdog at 3.4 GB). |
| 01:18 | Both archives downloaded and verified (size + S3 ETag; SHA-256 in DATASET_AUDIT.md). NF-BoT-IoT-v3 not extracted. |
| 01:2x | Late-record telemetry-health fix and tests (commit `1acb709`). |
| 01:3x | Pre-registration, dataset audit, window builder and experiment code committed (`86b7daa`) **before any Phase 8i model was trained or scored**. |
| 01:31–01:44 | NF-ToN-IoT-v3 ingested: 27,520,260 flows, 7 days (2019-04-24..30), peak 2.67 GB. |
| 01:50 | NF-UNSW windows rebuilt: identical to Phase 8b (16,028 evaluation windows, 4,091 attack windows). |
| 01:51 | NF-CIC build stopped: wrong split point (amendment A2). Split fixed and committed before any model ran; NF-CIC rebuilt, now identical to Phase 8h. |

## 2. Deviations and incidents

1. **Watchdog path (incident, no data effect).** The Phase 8i watchdog was created from the
   Phase 8h script with a path substitution that did not apply. Its first two starts read
   `reports/phase8h/run.status` ("done") and exited at once, and one start overwrote the
   git-ignored `reports/phase8h/watchdog.log.peak` (a memory log, not a result). The path was
   corrected, and the watchdog restarted during the NF-ToN-IoT-v3 ingest. No frozen Phase 8h
   result file was touched (`git status reports/phase8h` is clean). The ingest ran briefly
   without a watchdog; its memory was checked manually (about 1 GB).
2. **Stale build process (incident, no data effect).** After the wrong-split NF-CIC build was
   stopped, the stopped shell loop started an `nfton` build at 01:51:33, possibly with the
   pre-fix code. It ran alongside the corrected NF-CIC build for about a minute, until it was
   killed. The builder writes outputs only when it finishes, so it left no files. The ToN
   windows come from the later corrected run.
