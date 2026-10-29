# Real-data streaming audit (Phase 8g, post-hoc) [R]

**Label.** Retrospective engineering verification on CTU-13 scenarios 9 and 10. Both
scenarios were consumed by the frozen Phase 8g run. Nothing here changes the frozen results
([RESULTS.md](RESULTS.md), code 121acbf, `reports/phase8g/results.json`) or the frozen
window parts in `data/derived/phase8g`.

**Harness and outputs.**
- Harness: `scripts/phase8g_post/stream_audit.py`.
- Queue runner: `run.cmd`, with the 3.4 GB `watchdog.ps1`.
- Discrepancy tables: `reports/phase8g_post/<scenario>_<run>_compare.json`, plus Parquet
  lists of missing records and differing windows.

## 1. Method

| step | what it does |
|---|---|
| cache | Parses each conn.log once with the product parser, after checking its SHA-256 against the registry. Writes arrival-ordered Parquet: the record, its file position `seq`, and a 64-bit hash of the stream's `DEDUP_KEY`. No copy of the capture is made. |
| reference | Exact **non-streaming** reference. Every record goes to the window of its END. Duplicates (same `DEDUP_KEY`, same window) are removed, keeping the first arrival. Windows pass in order through the frozen `windows.Builder`, giving the same split and features as the frozen run. Unlimited lateness, no buffer. |
| stream | Replays the cache through a `WindowStream`. Code is either `current` or `frozen` (121acbf `live.py` loaded from git). Records each record's fate (emitted / duplicate / late / quarantined / invalid time), timing, peak RSS, and spill-disk bytes sampled every 2 s, and times each spill read-back. |
| compare | Matches records by identity (window, `DEDUP_KEY` hash). Reports missing, extra, moved and repeated records, with the fate of each missing one. Then windows (flow and packet sums, emitted twice, only in one side), every feature at every level and split, calibration destinations, then scores, thresholds and alert decisions. |
| equivalent | Every one of those counts is 0. Similar aggregates do not count. |

## 2. Equivalence results

### Scenario 9 (Neris; 2,625,792 records; reference 2,625,786 members, 6 duplicates)

| run | code | lateness / buffer / spill cap | missing (fate) | forced closes | windows differing | alert decisions differing | equivalent | health |
|---|---|---|---|---|---|---|---|---|
| frozen | 121acbf | 3,700 s / 1.5M / — | **1,039 (quarantined)** | 0 | 255 | not compared ¹ | no | `ok` (silent loss) |
| current | 9e526ca | 3,700 s / 1.5M / 6M | 0 | 0 | 0 | 0 of 8,041 | **yes** | `ok` |
| spill100k | 9e526ca | 3,700 s / 100k / 400k | 356 (late) | 311 | 85 | 11 (all gained) | no | `buffer_pressure` |
| spill100k_lazy | de8610c | 3,700 s / 100k / 400k | 356 (late) | 311 | 85 | 11 (all gained) | no | `buffer_pressure` |
| spill800k | de8610c | 3,700 s / 200k / 800k | 0 | 0 | 0 | 0 | **yes** | `ok` (`buffer_spill`) |

¹ Frozen replay vs the published frozen parts: see section 2.3.

- **The frozen replay reproduces the published run exactly.** 1,039 records were dropped as
  out of range, and 1,027 of them lasted longer than skew + lateness (the long-connection
  defect fixed in d67f061).
- **Current code at the registered parameters is exactly equivalent to the reference.** Every
  record, window, feature, score and alert decision matches.
- **With an under-sized buffer and spill budget (100k / 400k), degradation is explicit and
  conserved.** 356 records were late after 311 forced closes, and the flag is
  `buffer_pressure`. Records are conserved: emitted + duplicates + late = input. The
  resulting 11 alert flips are listed in the compare file.

### Scenario 10 (Rbot; 11,618,416 records; reference 11,618,409 members, 7 duplicates)

| run | code | lateness / buffer / spill cap | missing (fate) | forced closes | windows differing | alert decisions differing | equivalent | health |
|---|---|---|---|---|---|---|---|---|
| frozen | 121acbf | 600 s (A2) / 1.5M / — | **7,722** (6,030 late, 1,692 quarantined) | **57** | 353 of 572 | not compared | no | `buffer_pressure` |
| current | de8610c | 600 s (A2) / 1.5M / 6M | **90 (late)** | 0 | 67 | 10 of 3,608 (all lost) | no | `ok` (`buffer_spill`) |
| spill200k | de8610c | 600 s / 200k / 3M | 90 (late) | 24 | 67 | 10 (all lost) | no | `buffer_pressure` |
| lateness3700 | de8610c | 3,700 s (harness default) / 500k / 8M | 0 | 0 | 0 | 0 of 3,608 | **yes** | `ok` (`buffer_spill`) |

- **The frozen replay reproduces the published A2 failure exactly:** 6,030 late, 57 forced
  closes, 1,692 quarantine-rejected.
- **Pipeline failure.**
  - The 57 forced closes and the 6,030 late records came from buffer exhaustion. Spilling
    removes them: 0 forced closes, 0 quarantined.
  - The 1,692 quarantined records were long connections. The END rule removes them.
- **What remains at 600 s is a lateness-policy loss, not a pipeline failure.**
  - 90 records arrived after the watermark had passed their END window by more than 600 s.
  - Their durations are short (median 0.5 s). One lasted 1.6 h.
  - They are counted in `stats.late`, and records are conserved.
  - **A2 acceptance still fails on the current code** (`late 90`). Scenario 10 therefore
    stays **not evaluable under the registered protocol**, even after the fixes.
- **At the harness default lateness (3,700 s), current code is exactly equivalent to the
  reference.** The scenario is technically evaluable only retrospectively, at a lateness the
  registration did not specify for it ([FINAL_REPORT.md](FINAL_REPORT.md) section 4).
- **Gap: health stays `ok` when records are late.** The 90 late records are counted, but they
  do not change `health`, and the 10 alerts they cost are not flagged. A late record is, by
  the design of a bounded-lateness stream, dropped after its window was final. Recorded as a
  limitation and a Phase 8h item ([RELEASE_READINESS.md](RELEASE_READINESS.md)); not
  changed here.

**Engineering acceptance of the repaired stream on scenario 10** (registered parameters:
600 s, 1.5M buffer; default 6M spill cap). This is separate from the historical A2 verdict,
which stays **failed, not evaluated**.

| criterion | frozen 121acbf | repaired de8610c | met |
|---|---|---|---|
| A2 rule: late == 0 and forced_closes == 0 | 6,030 / 57 | **90 / 0** | **no** (late records remain) |
| no forced close at the registered buffer | 57 | 0 (57 windows spilled, 6.32M records written, peak 2.96M on disk) | yes |
| no silent loss: every missing record has a counted fate | 7,722 missing, all counted (6,030 late, 1,692 quarantined; 1,671 lasted longer than skew + lateness) | 90 missing, all `late` | yes |
| conservation (input = emitted + every loss counter) | — | 11,618,416 = 11,618,319 + 7 duplicates + 90 late | yes |
| no record emitted twice, moved or invented | 0 / 0 / 0 | 0 / 0 / 0 | yes |
| spill integrity | — | `spill_lost` 0, `spill_invalid` 0, no write error | yes |
| memory under the 3.4 GB watchdog | 1.66 GB | 2.81 GB | yes |
| spill directory removed after success | — | yes (peak 1.11 GB on disk) | yes |
| health reflects every loss | `buffer_pressure` | `ok` (`buffer_spill` only) despite 90 late records | **no** (open, medium) |
| exact equivalence with the reference | no | no at 600 s (67 windows, 10 alerts); **yes at 3,700 s** | at 3,700 s only |

### 2.3 Frozen parts vs reference

Output: `reports/phase8g_post/scenario_9_frozen_parts_compare.json`. It compares the
published frozen window parts with the exact reference, showing what the 1,039 lost records
changed in the frozen result:
- **Missing windows.** 591 test device windows (and 28 calibration device windows) are
  missing from the frozen parts. They contained only dropped records.
- **Different features.** 224 test device windows and 223 global windows have different
  features.
- **Thresholds.** Device threshold 28.018 frozen vs 28.040 reference.
- **Alerts.** 7,515 frozen vs 8,041 reference, over all scored windows and levels:
  - 547 alerts fall in the missing windows;
  - 43 alerts appear only in the frozen output and 22 only in the reference;
  - at least 4 initiators are among the alert flips (the listing is truncated).
- **Evaluation.** Re-run on the reference ([R]):
  - recall 0.209 → 0.211;
  - unverified 2,563 → 2,755/h;
  - initiators 10/10, 0 benign false alerts, median delay 47.5 s (all unchanged).
  - S5 still absorbs 1,932 windows (71.2%).

## 3. Records recovered and lost

| scenario | frozen lost | current lost (registered parameters) | recovered | remaining forced closes |
|---|---|---|---|---|
| 9 | 1,039 | 0 | 1,039 | 0 |
| 10 (600 s) | 7,722 | 90 (late, counted) | 7,632 | 0 |
| 10 (3,700 s, [R]) | — | 0 | — | 0 |

Every run conserves records: input = emitted + duplicates + late + quarantine_rejected +
quarantine_evicted + invalid_time + spill_lost. `spill_lost` and `spill_invalid` are 0 in
every run, and no spill write failed.

## 4. Resources (Windows 11, 4 cores, 8 GB RAM, local SSD)

| run | stream peak RSS | compare peak RSS | stream records/s | end-to-end records/s ² | peak spill disk | spill reads (s) | CPU, share of one core | spill dir removed |
|---|---|---|---|---|---|---|---|---|
| 9 frozen | 0.83 GB | 0.68 GB | 146.7k | 60.6k | 0 | — | 0.37 | yes |
| 9 current | 1.81 GB | 2.35 GB | 140.5k | 16.7k | 0 | — | 0.60 | yes |
| 9 spill100k (non-lazy) | **2.71 GB** | 2.37 GB | 25.0k | 10.5k | 154 MB | 599 (51 s) | 0.36 | yes |
| 9 spill100k_lazy | **0.99 GB** | 1.90 GB | 13.4k | 6.5k | 154 MB | 599 (80 s) | 0.25 | yes |
| 9 spill800k | 1.11 GB | 2.31 GB | 15.0k | 8.3k | 169 MB | 575 (82 s) | 0.27 | yes |
| 10 frozen | 1.66 GB | 1.93 GB | 178.5k | 103.3k | 0 | — | 0.42 | yes |
| 10 current | 2.81 GB | 2.60 GB | 24.0k | 10.5k | 1.11 GB | 57 (290 s) | 0.34 | yes |
| 10 spill200k | 2.05 GB | 2.68 GB | 17.7k | 8.6k | 1.13 GB | 112 (338 s) | 0.29 | yes |
| 10 lateness3700 | 1.96 GB | 2.67 GB | 16.5k | 8.9k | 2.51 GB | 319 (348 s) | 0.26 | yes |

² End-to-end includes the frozen feature build (about 2 min for scenario 9, 8–9 min for
scenario 10) and cache reading.

- **Memory.**
  - Every run stayed under the 3.4 GB watchdog; peak whole-queue working set 2.74 GB.
  - No budget was raised. The lateness3700 run used an 8M-record spill cap (2.5 GB on disk).
    That is the product's own default envelope (monitor default 2M buffer → 8M spill,
    roughly 2.8 GB).
- **The lazy flush (de8610c) cut the spill run's peak from 2.71 GB to 0.99 GB on real data.**
  Before it, every spilled window was read back at flush, and restored records did not share
  key strings.
- **Throughput.**
  - Without spilling, real data streams at 141–179k records/s, below the 234k records/s
    synthetic figure.
  - With spilling, it drops to 13–25k records/s. Reading spilled windows back is 30–60% of
    stream time.
  - Dense traffic therefore streams about 10× slower once it spills. At 13k records/s the
    stream still keeps up with scenario 10's mean arrival rate, about 1.4k records/s
    (11.6M records in 2.3 h of capture). Bursts are buffered on disk.
  - We do **not** claim parity with the synthetic benchmark.
- **The lazy run was slower than the non-lazy run** (13.4k vs 25.0k records/s; spill reads 80
  vs 51 s). This is **not** a code regression: it was machine load.
  - `scripts/phase8g_post/spill_bench.py` replays the same 500k real records through both
    codes, alternating, twice (20k buffer, 140 spilled windows).
  - 9e526ca: 33.5k and 39.7k records/s. Current: 38.1k and 37.2k records/s.
  - Spill reads: 5.7 s vs 6.4–6.7 s.
  - Output: `reports/phase8g_post/spill_bench.json`.
- **The feature build halves stream throughput** on this machine.
  - The same 100k / 400k scenario 9 replay without the build streams at 35.9k records/s;
    with it, 13.4–25.0k.
  - The build and the stream share one process and 8 GB of RAM.
- **Cleanup after success.** Every run's spill directory was removed (`spill_dirs_removed_after_flush`).
- **Cleanup after interruption: section 5.**

## 5. Edge cases (synthetic regression tests)

| case | test | result |
|---|---|---|
| connection spanning several windows | `test_spill_hardening::test_connection_spanning_several_windows_is_emitted_once_in_its_end_window` | emitted once, in its END window |
| very long connections (> skew + lateness) | `test_stream_robustness::test_long_lived_connections_are_not_dropped` | 0 lost (old rule: 143 lost, health `ok`) |
| timestamp before start / record ending before it starts | `test_spill_hardening::test_records_ending_before_they_start_are_rejected` | counted `invalid_time`, `integrity_degraded`; cannot vote on the clock |
| out-of-order and duplicates | `test_streaming::test_out_of_order_and_duplicates_within_lateness`, `test_stream_robustness::test_duplicates_are_counted_not_emitted` | exact |
| late records | `test_streaming::test_late_records_are_counted_not_merged` | counted, not merged |
| large gaps | `test_streaming::test_clock_resyncs_after_a_real_time_gap`, `test_genuine_gap_is_confirmed_not_reverted` | resynced, no loss |
| repeated forged future timestamps | `test_streaming::test_forged_future_timestamps_are_rejected_without_loss`, `test_stream_robustness::test_in_skew_forgery_…`, `test_quarantine_memory_stays_bounded_…` | rejected, `clock_anomaly`, bounded quarantine |
| buffer and spill saturation | `test_stream_robustness::test_exhausted_spill_budget_degrades_explicitly`, `test_spill_hardening::test_appends_to_spilled_windows_respect_the_disk_budget`, `test_spill_pending_memory_is_bounded_…` | `buffer_pressure`; disk and pending memory bounded |
| interruption during a spill write | `test_spill_hardening::test_interrupted_spill_write_loses_nothing` | partial line truncated; no record lost or doubled |
| disk full | `test_spill_hardening::test_disk_full_keeps_records_and_degrades_explicitly` | records kept in memory, `spill_failed` and then `buffer_pressure`; never silent |
| invalid or truncated spill JSONL | `test_spill_hardening::test_truncated_or_edited_spill_files_are_counted_not_fatal` | `spill_lost` / `spill_invalid`, `integrity_degraded` |
| stale spill directories | `test_spill_hardening::test_stale_spill_directories_of_dead_processes_are_removed`, `test_abandoned_stream_removes_its_spill_directory` | removed by the sweep of a later spill when the owner pid is dead, or when a directory without an owner file is more than 24 h old (no timer) |
| restart | `test_spill_hardening::test_restart_after_interruption_reproduces_the_reference` | the replay equals the reference |
| conservation | `test_spill_hardening::test_records_are_conserved_in_every_robustness_scenario` | identity holds in every scenario |
| bounded flush memory | `test_spill_hardening::test_flush_iter_does_not_materialise_every_spilled_window` | lazy peak < 1/5 of the list path |
| lazy flush interrupted by the consumer (Ctrl+C while writing a window), then closed again | `test_spill_hardening::test_flush_iter_interrupted_by_the_consumer_resumes_without_loss` | remaining windows stay on disk; the second close delivers each record exactly once; directory removed |
| stream abandoned during the lazy flush | `test_spill_hardening::test_stream_abandoned_during_flush_iter_removes_its_spill_directory` | directory removed when the stream is collected |
| spill file lost during the lazy flush | `test_spill_hardening::test_spill_file_lost_during_flush_iter_is_counted_and_flagged` | counted `spill_lost`, `integrity_degraded`, conserved; the flush continues |

- **Deserialization.** Spill files are JSON lines read with `json.loads`, so a planted file
  cannot execute code.
  - Lines are capped at 64 KiB.
  - At most the number of records written are read back.
  - Every restored record is validated: a dict with int START and END, END ≥ START, in its
    window.
- **Real-data interruption.** The queue process was killed once by the end of a session.
  Five orphaned directories, probably from d67f061 test runs (658,664 bytes, no owner file,
  10/28 07:17–07:26), are left in place. A sweep removes such a directory only when a later
  stream spills and the directory is then more than 24 h old; there is no timer. Section 5.1 adds a
  measured real-data kill.

### 5.1 Hard kill on real data (`scripts/phase8g_post/interrupt_check.py`)

| step | result |
|---|---|
| scenario 9 replay, 100k buffer, killed by `TerminateProcess` after 5.1 s (no finalizer, `finally` or `atexit` ran) | spill directory left behind: 55.2 MB, 45 window files, owner pid dead |
| `sweep_stale_spills()`, called here directly; in the product it runs only when a stream creates its spill directory | removed it (1 directory) |
| the five legacy test directories (no owner file, < 24 h old) | kept, as designed |
| partial run directory | removed by the check |

Output: `reports/phase8g_post/interrupt_check.json`.
- Disk after a crash is reclaimed only when a later stream spills and triggers the sweep.
  There is no background task or timer.
- If no stream spills again, the directory remains indefinitely.
- A directory without an owner file is removed by such a sweep only once it is more than
  24 h old. The current inventory of orphaned directories is in
  [FINAL_REPORT.md](FINAL_REPORT.md) §8a.

## 6. Verdicts

| claim | status |
|---|---|
| frozen replay reproduces the published scenario 9 and 10 stream statistics | **confirmed** [R] |
| current code is exactly equivalent to the non-streaming reference on scenario 9 at the registered parameters | **confirmed** [R] |
| current code is exactly equivalent on scenario 10 at the registered A2 lateness (600 s) | **refuted**: 90 late records, 10 alert decisions lost |
| current code is exactly equivalent on scenario 10 at 3,700 s | **confirmed** [R] (non-registered lateness) |
| buffer exhaustion no longer forces closes at the registered buffer | **confirmed** (scenario 10: 57 → 0) |
| every loss is counted and conserved | **confirmed** in all 9 runs |
| every loss is reflected in `health` | **refuted** for late records (section 2) |
| real-data throughput with spilling matches synthetic | **refuted** (10× slower; arrival rate still sustained) |
| a hard kill leaves no permanent spill directory once another stream spills | **confirmed** [R] |
