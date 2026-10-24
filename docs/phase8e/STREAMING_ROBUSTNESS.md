# Streaming robustness audit (Phase 8e, Mission 2)

- Code: `src/netsentinel/streaming/live.py` (`WindowStream` clock state machine,
  `advance()`, follow-mode idle ticks).
- Harness: `scripts/phase8e/stream_robustness.py`.
- Tests: `tests/integration/test_stream_robustness.py`, `tests/integration/test_streaming.py`.
- Results: `reports/phase8e/stream_robustness_{before,after}.json`,
  `reports/phase8e/ton_stream_regression.json`.

## Method

**Deterministic scenarios.** Genuine traffic: 3 hosts at 1 record/s for 1 h (10,800 records,
120 windows), with anomalies inserted. Every record is tagged genuine or anomalous (the stream
ignores the tag), so the emitted windows can be compared with a reference built from genuine
records alone.

**Metrics:**
- genuine records lost;
- reference windows whose emitted membership differs;
- anomalous records that reached an emitted window (integrity leak);
- peak records held (buffer + quarantine): the memory bound;
- recovery (genuine records lost after the last anomaly);
- reported health.

## Results: Phase 8d code (before) vs Phase 8e state machine (after)

| scenario | genuine lost (before -> after) | differing windows | forged emitted | peak held | health (after) |
|---|---|---|---|---|---|
| baseline | 0 -> 0 | 0 -> 0 | 0 -> 0 | 270 -> 270 | ok |
| single forged future burst (1,000 records, +30 d) | 1,068 -> **0** | 12 -> 0 | 1,000 -> **0** | 1,270 | clock_anomaly |
| 5 repeated forged bursts | **8,268 (77%)** -> **0** | 92 -> 0 | 5,000 -> 0 | 2,269 -> 1,270 | clock_anomaly |
| alternating valid / forged records | 0 -> 0 | 0 -> 0 | **10,800** -> **0** | 11,070 -> 4,270 (capped) | integrity_degraded |
| long idle gap (8 h), then traffic resumes | 0 -> 0 | 0 -> 0 | 0 -> 0 | 1,269 -> 2,169 | ok (resynced) |
| backward clock reset (-1 day) | **5,400 (all after the reset)**, health "ok" -> **0** | 60 -> 0 | 0 -> 0 | 270 -> 2,169 | clock_reset |
| out-of-order (+/-20 s) + 5% duplicates | 0 -> 0 | 0 -> 0 | 0 -> 0 | 270 | ok |
| 4 resync attempts to different future times | **8,990 (83%)** -> **0** | 100 -> 0 | 4,000 -> 0 | 1,999 -> 2,270 | clock_anomaly |
| forged flood dominating the stream (10 : 1 for 20 min) | after the first redesign: 1,300 lost, 36,000 emitted -> **0, 0** | 15 -> 0 | — | 40,000 -> 2,175 | clock_anomaly |
| buffer exhaustion (cap 100 records) | 0 | 0 | 0 | 100 | buffer_pressure |

**Real-data regression (post-hoc, consumed ToN_IoT input, 4M records with a genuine 460 h
gap):**
- record membership is identical to the non-streaming reference in all 5,820 windows;
- 2 jumps committed, 3,791 quarantined records replayed, 0 rejected or evicted;
- health `buffer_pressure` (the 1.5M cap was hit, still without loss).

## Design (what changed and why)

1. **Out-of-range records never move the committed clock or enter a window directly.**
   - A record more than `max_skew_s` ahead, or more than `max_skew_s + lateness_s` behind,
     goes into a bounded quarantine (default 4 x `resync_after`).
   - The oldest records are evicted and counted (`quarantine_evicted`, flag
     `integrity_degraded`).
   - In Phase 8d the jump moved the clock first and closed every genuine window; that was the
     cause of every loss in the "before" column.
2. **A pending jump opens only when >= 90% of the last `resync_after` records are out of
   range in the same direction.**
   - The committed timeline keeps running while the jump is pending.
   - In-range records vote against it, consistent out-of-range records vote for it.
3. **Commit** needs `resync_after` votes for it **and** at most 2% contradicting records.
   - A genuine gap or sensor reset silences the old timeline.
   - On commit, the open windows are emitted and the quarantined records are replayed, so
     nothing is lost.
   - A backward commit (`clock_reset`) can repeat window indices. Downstream stores are
     idempotent per window key, and the flag is degrading.
4. **Reject** when the jump is contradicted, or when two timelines interleave (more than 2%):
   - the quarantined records are dropped and counted (`quarantine_rejected`);
   - flag `clock_anomaly`.
5. **Explicit health.**
   - Flags: `resynced` (informational); `buffer_pressure`, `integrity_degraded`,
     `clock_anomaly`, `clock_reset` (degrading).
   - `health` = the most severe degrading flag.
   - Exposed in `monitor` output and used by the telemetry state (UNCERTAINTY_STATES.md).
6. **Idle periods.**
   - `WindowStream.advance(now_ms)` closes windows by wall-clock time.
   - Follow mode yields an `IDLE` marker on every idle poll, so a quiet network no longer
     holds its last windows open until traffic resumes.
   - A wall clock more than `max_skew_s` ahead is not trusted.

## Residual risks (measured or reasoned; not claims of security)

- **An attacker who controls the log can still cost detections.**
  - Forged records are quarantined, but a sustained flood keeps the stream in
    `clock_anomaly` / `integrity_degraded`.
  - Memory stays bounded (quarantine cap). Genuine traffic was not lost in any tested
    scenario.
- **A genuine gap that coincides with ongoing traffic from a second clock** (two sensors
  merged into one log with offset clocks) is indistinguishable from forgery by timestamps
  alone. It is rejected and visible as `clock_anomaly`.
- **Detection latency.** Commit needs 2 x `resync_after` out-of-range records, so windows after
  a genuine gap are emitted about 2,000 records later than before.
- **Buffer exhaustion** under very high rates still force-closes windows (`buffer_pressure`).
  Records arriving for a force-closed window are counted late.
- Not covered: adversarial manipulation of non-timestamp fields (bytes, ports), or an
  attacker who knows `resync_after` and keeps the forged share just below 90%. The latter
  degrades to quarantine evictions, which are bounded and visible.
