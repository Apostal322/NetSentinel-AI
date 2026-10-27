# Streaming robustness near the decision boundaries (Phase 8f, Mission 4)

- Scenarios: `scripts/phase8f/stream_near_trigger.py` → `reports/phase8f/stream_near_trigger.json`.
- Tests: `tests/integration/test_stream_robustness.py` (the Phase 8e scenarios plus 14 new
  Phase 8f tests).
- Inputs are synthetic and defensive: 3 genuine hosts at 1 record/s each; forged records come
  from one extra host.
- The Phase 8e scenarios and the frozen external results are unchanged.

## Results (after the fix below)

| scenario | genuine lost | forged emitted | peak held | health |
|---|---|---|---|---|
| future share 85% / 89% (just below the 90% trigger) | 0 | 0 | 4,320 (quarantine cap) | `integrity_degraded` (16k / 25k evicted) |
| future share 90% / 91% / 95% | 0 | 0 | ≤ 2,267 | `clock_anomaly` (17 / 19 / 35 rejected jumps) |
| share oscillating 88% ↔ 92% | 0 | 0 | 4,035 | `clock_anomaly` |
| 5 anomaly cycles, then clean traffic | 0 | 0 | 2,215 | `clock_anomaly` |
| 89% sustained for 3 h (43,200 genuine records) | 0 | 0 | 4,320 | `integrity_degraded` (258k evicted) |
| backward share 89% / 95% | 0 | 0 | 4,320 / 2,267 | `integrity_degraded` / `clock_anomaly` |
| **in-skew forgery, 2% of records +3,500 s** | **0** (before the fix: **8,997 = 83%**) | 72 | 392 | ok |
| **in-skew forgery, one record +3,500 s** | **0** (before the fix: **8,900 = 82%**) | 1 | 321 | ok |

**Bounded and explicit.**
- Memory stays within the window buffer plus the quarantine cap (4 × `resync_after`) in every
  scenario.
- Health turns degrading in every scenario that discards records.
- Health flags are sticky for the session: a monitor that saw an anomaly keeps reporting it
  after recovery. Recovery itself is complete, with 0 genuine records lost after the last
  anomaly.

## The vulnerability found

- **Before Phase 8f:** the committed clock was the **largest** accepted start. A record stamped
  just inside `max_skew_s` (3,600 s) is "in range", so a **single** such record moved the
  watermark almost an hour ahead. Every genuine record after it was late and dropped.
- **Impact:** 82% loss, health `ok`, no flag. The Phase 8e quarantine only covers records
  outside the skew range.
- **Fix (`WindowStream(clock_quorum=101)`):**
  - the clock advances to the **median** start of the last 101 accepted records;
  - moving it needs a majority of recent records;
  - the old timeline's quorum is cleared when a jump is committed;
  - replayed records are not counted;
  - a counter `uncorroborated_ahead` records accepted records more than `lateness_s` ahead of
    the clock.

## Costs and residual risk

| item | value |
|---|---|
| throughput (synthetic, 210k records) | 244k records/s (was 296k; −18%). P8-H7 required ≥ 20k/s. |
| latency | windows close about half the time span of the last 101 records later: about 17 s at 3 records/s. On slow streams (1 record / 10 s) about 8 min. In follow mode, idle ticks (`advance`, trusted wall clock) bound this. |
| in-skew forged records | still **emitted** into their own (future) windows. Timestamp checks cannot tell them from genuine records. They are counted, not flagged: on slow streams the median lags by design, and a flag would fire on benign traffic. |
| majority forgery inside the skew range | an attacker who controls most of the log can still move the clock. Out of scope for timestamp checks, and the source of the log must be trusted (threat model T15). |

**Real-data regression (post-hoc, consumed ToN_IoT input):** `reports/phase8f/ton_stream_regression.json`.
Identical record membership in all 5,820 windows (0 late, 0 `uncorroborated_ahead`; peak
1.36 GB), as before the fix.
