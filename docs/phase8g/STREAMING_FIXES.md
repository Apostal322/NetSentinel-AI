# Streaming fixes from the CTU-13 run (Phase 8g)

- The frozen CTU-13 evaluation (RESULTS.md, code 121acbf) exposed two gaps in `WindowStream`.
- Both are fixed in `src/netsentinel/streaming/live.py` and covered by synthetic regression
  tests in `tests/integration/test_stream_robustness.py` and `test_streaming.py`.
- The fixes change no Phase 8g result: they were made after the frozen run. They have **not**
  been re-run on CTU-13 data.

## 1. Long-lived connections were dropped silently

| | |
|---|---|
| finding | CTU-13 scenario 9: 1,039 records quarantined as "behind" and dropped at flush, with health `ok` |
| cause | out-of-range records were classified by flow START. Zeek writes a connection when it ENDS, so a connection that lasted longer than `max_skew_s + lateness_s` (about 1 h by default) had an old start but a current end. |
| fix | BEHIND is decided by the flow END; AHEAD is still decided by the start. A genuine backward clock reset moves both start and end, so it is still detected. |
| regression test | 3 h of traffic plus 143 connections lasting 2.5 h each, logged when they end. The pre-8g rule (re-applied in the test) loses all 143 with health `ok`; the fix loses 0 and quarantines none. |
| residual | a forged record with an old start and a current end is now accepted into the window of its END, exactly like any in-range record |

## 2. Dense traffic exhausted the buffer and lost records

| | |
|---|---|
| finding | CTU-13 scenario 10 (Rbot floods): the 1.5M-record buffer filled even at 600 s lateness. 57 windows were force-closed and 6,030 records were late. |
| fix | when more than `max_buffer` records are held, the oldest open windows are **spilled to disk** instead of being force-closed. Records arriving for a spilled window are appended, and duplicates are removed (and counted) when it closes. Forced closes (`buffer_pressure`) happen only once the spill budget (`max_spill`) is used up. |
| storage | JSON lines (never pickle, so a planted file cannot execute code) in a private `tempfile.mkdtemp` directory, removed on `flush`; flushed every 1,000 records per window |
| defaults | `max_spill` = 4 × `max_buffer` (`monitor --max-spill`; 0 restores the old behaviour). At the monitor default of 2M records: up to 8M records on disk, roughly 2.8 GB. |
| health | new informational flag `buffer_spill` (no loss, so not degrading); `buffer_pressure` as before when the budget is exhausted |
| regression tests | a dense out-of-order stream with a 100-record buffer: the old behaviour loses records (`buffer_pressure`); spilling loses none, with memory still ≤ buffer + quarantine. Also an exhausted budget degrades explicitly, and duplicates arriving while spilled are removed and the directory is cleaned. |

## Cost

| | before (8f) | after |
|---|---|---|
| throughput (synthetic, 210k records, no spill) | 244k records/s | 234k records/s (−4%) |
| memory | bounded by `max_buffer` | unchanged, plus disk up to `max_spill` |

## Not verified (at the time of these fixes)

- **Real data.** Neither fix had been re-run on CTU-13; that data is consumed. A post-hoc
  engineering check on it would be labelled [R].
- **Disk speed.** Spill throughput on slow disks has not been measured.

**Update (Phase 8g finalization, [R]).** The fixes were re-run on CTU-13 against an exact
non-streaming reference ([REAL_DATA_STREAMING_AUDIT.md](REAL_DATA_STREAMING_AUDIT.md)).
- **Scenario 9:** exact; 0 of the 1,039 records lost.
- **Scenario 10:**
  - 0 forced closes;
  - 90 records still late at A2's 600 s lateness;
  - exact at 3,700 s.
- **Hardening.** A review of these fixes found several gaps in the spill: the disk budget
  ignored appends, failed writes, unreadable files, stale directories and records ending
  before they start. All were fixed in 9e526ca and de8610c.
- **Throughput.** With spilling, real data streams at 13–40k records/s, not the synthetic
  234k.
