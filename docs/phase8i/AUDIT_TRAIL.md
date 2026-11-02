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
| 01:55 | NF-ToN-IoT-v3 windows built (57 s). Label audit: attack windows attributed mainly to the documented attacker range 192.168.1.30–38; no exclusions. |
| ~01:57 | Code smoke runs on development data (NF-UNSW: seed 0, 2 draws; NF-CIC 02-21: seed 0, 3 draws), written to `reports/phase8i/smoke/`, plus timing and profiling. They led to amendment A3 (compute) and an exact A4 speed-up. |
| 02:01–02:56 | Development batch at commit `0871e64`: Experiment A (31 min), B (4 min), C (20 min); peak 2.67 GB. |
| 02:5x | `analyze.py` applied the selection rules: A4, C1_k2, τ = 0.70095. |
| 03:0x | Confirmatory pipeline dry run with NF-UNSW standing in for N4 (smoke folder). It revealed the unanticipated no-overrun and ceiling cases: amendment A4, written before N4 was opened. |
| ~03:00 | Development results committed (`559b4e2`); FREEZE.md and freeze.json committed (`5db0c6f`). |
| 03:01–03:04 | **N4 opened for the first time:** NF-BoT-IoT-v3 ingested (16,933,808 rows, SHA-1 verified, all labels mapped by the pre-written map). |
| 03:04 | N4 windows built: 3,449 evaluation windows (1,579 attack, 8 attackers, 16 entities); 7,230 labelled calibration attack windows from 8 entities. |
| 03:04– | Confirmatory experiments A, C and B in the frozen order. |

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
3. **Development batch over the estimate.** The approved development envelope was "about
   20–40 min, < 2.5 GB". The batch took 55 min of wall time, with a peak of 2.67 GB (the
   NF-ToN-IoT-v3 ingest also peaked at 2.67 GB). Amendment A3 had already reduced the
   registered design to fit. The remaining overrun is recorded here, not hidden. No run came
   near the 3.4 GB watchdog limit.
4. **N4 ingest above the memory limit.** The NF-BoT-IoT-v3 ingest's own peak-RSS report is
   3.69 GB, above the 3.4 GB project limit. The watchdog, sampling every 5 s, saw at most
   3.28 GB and did not intervene. The run completed normally, with no effect on data or
   results. The ingest reads a 3.5 GB CSV in one pass. A chunked ingest is a follow-up for
   any larger archive.
5. **N4 window build above the memory limit.** `windows_nfbot.json` records a peak of
   4.10 GB for the NF-BoT-IoT-v3 window build, above the 3.4 GB limit. The 5 s watchdog
   sampling missed it, as with the ingest (item 4). The run completed and the results are
   unaffected. Both peaks were short; a finer sampling interval or an in-process RSS cap is
   the follow-up.
6. **Independent review (after the confirmatory run).** A review pass found no bug that changes
   a verdict, and upheld several report overstatements. Corrected in FINAL_REPORT.md
   section 9, which also lists these unregistered deviations:
   - the N4 bootstrap intervals for I2/I3 were not computed;
   - the NF-ToN-IoT label audit is a per-source attribution, not an initiator check
     (192.168.1.193 contributes 36% of attack windows, unexplained);
   - N4 got no label audit;
   - the draw-seed formula differs from "draw index";
   - `pool_short` is checked on draw 0 only;
   - the first evaluation hour is discarded, not used for the shift scores.
