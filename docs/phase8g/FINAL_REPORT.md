# Phase 8g final report: CTU-13 independent validation, closure

**Date:** 2026-10-28. **Status: formally closed on 2026-10-29** (decision A, section 10).

**Frozen evaluation.**
- Code: 121acbf (registry `reports/phase8g/registry.json`).
- Published results: [RESULTS.md](RESULTS.md), `reports/phase8g/results.json`.

**Post-hoc work** (this report and its companions):
- [REAL_DATA_STREAMING_AUDIT.md](REAL_DATA_STREAMING_AUDIT.md);
- [V4_FAILURE_ANALYSIS.md](V4_FAILURE_ANALYSIS.md);
- [ALERT_BURDEN_ANALYSIS.md](ALERT_BURDEN_ANALYSIS.md);
- [RELEASE_READINESS.md](RELEASE_READINESS.md).

Scripts are in `scripts/phase8g_post/`; outputs in `reports/phase8g_post/`.

## 1. Evidence classes

| label | meaning | here |
|---|---|---|
| **[C] confirmatory** | pre-registered, frozen code, data unopened before the run | V1–V4 on scenario 9 (frozen run, attempt 2) |
| **[A] amended** | confirmatory under a pre-result amendment | A1 (scenarios 9/10, option a); A2 (per-scenario lateness; scenario 10 = 600 s with an exactness acceptance) |
| **[R] retrospective** | consumed CTU-13 data, after the result | the streaming audit; scenario 9 re-evaluated on the exact reference; scenario 10 at 3,700 s; V4 and burden diagnoses |
| **[E] exploratory** | synthetic or development data | V4 synthetic study; per-entity gate cost on CTU-Normal |
| **[Eng] engineering** | software checks | regression tests, benchmarks, kill test |
| **[H] hypothesis** | proposed, untested | burden reduction ideas; Phase 8h items |

**Frozen artifacts are unchanged.**
- The frozen results and window parts are untouched.
- CTU-13 file hashes were re-verified (SHA-256 equal to the registry for both conn.logs).
- `git diff 121acbf -- scripts/phase8g src/netsentinel/behavior` was empty until this phase's
  one product change (`registry.update_check`, section 7). The frozen evaluation does not
  call it.

## 2. Findings

| # | finding | class | status |
|---|---|---|---|
| 1 | V3: the deployed detector finds the documented initiators at its operating point (scenario 9): 10/10, Wilson [0.72, 1.00]; attack-window recall 0.209; median delay 47.5 s | C | **confirmed** (descriptive, as registered) |
| 2 | 0 false alerts in 803 verified-benign windows | C | **confirmed** |
| 3 | V1 `baseline_state` reliability | C | **not evaluated** (no monitoring segment) |
| 4 | V2 shift-test adoption | C | **not evaluated** (no benign-only segment) |
| 5 | V4 gated recalibration does not absorb attacks | C | **refuted** (S5 absorbed 1,932 windows, 71%) |
| 6 | scenario 10 | A | **not evaluated**: A2 acceptance failed (historical verdict, unchanged) |
| 7 | the frozen stream lost 1,039 scenario 9 records silently (long connections) | R | **confirmed**: exact replay; fixed (d67f061) |
| 8 | current code equals the non-streaming reference on scenario 9 | R | **confirmed**: every record, window, feature, score and alert |
| 9 | scenario 9 results on the exact reference: recall 0.211, unverified 2,755/h, V3 and V4 otherwise unchanged | R | **confirmed** (the published figures are 0.209 and 2,563/h) |
| 10 | scenario 10 under A2 with current code | R | **refuted**: still fails A2 (90 late records at 600 s; 0 forced closes, 0 quarantined) |
| 11 | scenario 10 at the harness default 3,700 s with current code equals the reference | R | **confirmed** |
| 12 | scenario 10 exploratory result (3,700 s): V3 10/10, recall 0.573, 4 benign false alerts in 606 windows (1.8/h), 1,475 unverified/h; V4 S5 absorbed 64% | R | **exploratory only** (non-registered lateness; consumed data; same hosts as scenario 9) |
| 13 | V4 root cause: population-level gate diluted (attack = 0.47% of windows), plus own profiles granted to new persistent sources | R | **confirmed** |
| 14 | the product update gate shares the weakness | R | **confirmed**; per-entity review trigger added (§7) |
| 15 | no data-driven refresh strategy is safe under gradual contamination | E | **confirmed** in the synthetic study |
| 16 | the alert burden (2,563/h) is mostly scale × 1% target | R | **confirmed** (1,975/h expected) |
| 17 | incident grouping makes the burden practical | R | **refuted** (−18%) |
| 18 | late records are reflected in `health` | Eng | **refuted**: they are counted, not flagged (open, §9) |

## 3. Pipeline failure vs model failure

| observation | pipeline or model |
|---|---|
| scenario 9: 1,039 records dropped, health `ok` | **pipeline** (START-based out-of-range rule). Effect on the result: +0.002 recall and +7.5% unverified burden. No verdict changes. |
| scenario 10: 6,030 late, 57 forced closes, 1,692 quarantined | **pipeline** (buffer exhaustion and long connections). Fixed: 57 → 0 forced closes, 7,722 → 90 lost. |
| scenario 10: 90 late at 600 s | **protocol / lateness policy**. A2 chose 600 s to fit the old buffer. At 3,700 s nothing is lost. |
| V4 absorption | **model-update design** (gate and refit). Not a software defect. |
| attack-window recall about 0.2 on scenario 9 | **model**: bots alert in 21% of their windows. The pooled-fallback threshold is set by transient sources (`tail_fallback_share` 0.97). |
| 2,563 unverified alerts/h | **model-at-scale**: 1% target × 197k device windows/h. Precision unknown (no labels). |

## 4. Scenario 10: three separate statements

1. **Historical frozen verdict [A]:** declared failed under A2 (6,030 late, 57 forced closes),
   not evaluated. **Unchanged.**
2. **Post-hoc engineering comparison [R]:**
   - The frozen replay reproduces the failure exactly.
   - Current code at the registered 600 s loses 90 records, with 0 forced closes, so it
     **still fails A2**.
   - At 3,700 s it is exactly equivalent to the reference.
3. **New exploratory result [R]:** the frozen evaluation on the exact reference (finding 12).
   - It is not a replication: the same 10 infected hosts, the same network, and a lateness
     the registration did not specify.

## 5. Label and timeline integrity

**How labels were established.**
- Attack windows: windows of the 10 documented initiators **after each documented infection
  time** (README, converted from CEST to UTC). The labels file is not used for this.
- Verified benign: the 6 documented normal hosts.
- Everything else is unverified.
- The label audit ([RESULTS.md](RESULTS.md)) showed:
  - From-Botnet labels start at VM start, about 2 h before infection;
  - 147.32.1.20 is labelled normal but is not in the design.
- A label-based evaluation would therefore have counted uninfected traffic as attack.

**Measures, kept separate (scenario 9, frozen):**

| measure | value |
|---|---|
| initiator coverage | 10/10 |
| attack-window recall | 0.209 (565 / 2,708) |
| incident-level detection | 55 attack incidents, 10/10 initiators; median 5 windows per incident |
| delay from documented infection | median 47.5 s (34–66 s; one initiator 442 s) |
| verified-benign false alerts | 0 / 803 windows |
| background burden | 2,563 alerts/h (unverified) |
| initiator traffic before infection (test period) | 15 windows, 0 alerts; not counted as attack |

This is not evidence of "perfect security". It covers one scenario of one network and one
botnet family. Recall per window is low.

## 6. Streaming and resources (summary of the audit)

- **Records recovered and lost.**
  - Scenario 9: 1,039 recovered, 0 lost.
  - Scenario 10: 7,632 recovered, 90 lost (late, counted). 0 forced closes at the registered
    buffer.
- **Conservation** holds in all 9 runs. `spill_lost` = `spill_invalid` = 0 everywhere.
- **Memory.**
  - Peak stream RSS 0.83–2.81 GB; whole queue 2.74 GB (watchdog 3.4 GB, never fired).
  - The lazy flush cut a spilling run from 2.71 GB to 0.99 GB.
- **Disk.** Peak spill 154–169 MB (scenario 9) and 1.1–2.5 GB (scenario 10). Every directory
  was removed after success. After a hard kill, the directory stays until a later stream
  spills and its sweep runs (§8a). Nothing removes it on a timer.
- **Throughput.**
  - 141–179k records/s without spilling; 13–40k records/s with spilling (234k synthetic).
  - Not at parity. It still exceeds scenario 10's mean arrival rate (about 1.4k records/s).

## 7. Changes made in finalization (each with a regression test that fails on the old code)

| commit | change | tests |
|---|---|---|
| 9e526ca | Spill bounded and hardened. Covers: disk budget for appends; pending memory; failed or interrupted writes (truncate, never half a record); validated, bounded read-back; stale-directory sweep (dead owner pid); `invalid_time` for records ending before they start; conservation counters. | `tests/integration/test_spill_hardening.py` (12) |
| de8610c | Lazy flush (`flush_iter`) and shared key strings for restored records; stream health stored per behaviour window (`telemetry_health`, with schema migration); dashboard warning | `test_spill_hardening.py` (+2), `test_telemetry_health_store.py` (3), `test_dashboard.py` |
| this phase | `update_check` per-entity review trigger (review only; adoption rule met on development data) | `test_calibration_reliability::test_update_gate_flags_a_persistently_anomalous_entity` |
| this phase | API test: `/behavior` returns each window's stored telemetry health | `test_telemetry_health_store::test_api_reports_the_stored_health_of_each_window` |
| this phase | verification tests of the lazy flush: interrupted by the consumer and resumed, abandoned mid-flush, spill file lost mid-flush (pass on de8610c; no code change needed) | `test_spill_hardening.py` (+3, 17 in total) |

No verdict was modified. The detection default (scoring, thresholds, target FPR) is
unchanged. The system remains detection-only.

## 8. Audit trail of corrections

1. **`registry.json` `contents_opened: false` is stale.** The files were opened by the frozen
   build. The field is left as recorded, and this note corrects it.
2. **The A2 acceptance rule checks losses only at a non-default lateness.**
   - At the default lateness the frozen pipeline did not check `late` or quarantine.
   - That is how scenario 9's 1,039 dropped records passed.
   - It is a methodology gap, disclosed here. The frozen code is unchanged.
3. **Stored health is the stream's health "so far"** at each window's write. A window written
   before a later degradation keeps `ok`.
4. **Post-hoc diagnosis bugs found and fixed before any figure was used:**
   - pooled scope compared to `"pooled"` instead of `"__pooled__"` (shares were 0);
   - the CTU-13 QKC variant excluded transient sources, unlike the synthetic definition;
   - an O(entities × windows) loop stalled the first diagnostics run.
5. **The 2× throughput gap between the lazy and non-lazy audit runs** was traced to machine
   load. A controlled benchmark showed no code difference.

## 8a. Temporary files and background jobs

| item | state |
|---|---|
| background jobs (queues, watchdogs, test runs) | none running; every queue ended with `done`, and the watchdog never killed a process (peak 2.74 GB) |
| spill directories of the audit runs | removed after every successful run; the hard-killed one was removed by the sweep |
| 5 orphaned spill directories `netsentinel-spill-{xgd0_eay, 1nn1urez, quhxhwt1, aa1ib4c1, g6vp4r9x}` in the user temp directory | **Data:** 658,664 bytes (804 KB on disk) of `<window>.jsonl` files; modified 10/28 07:17–07:26. **Source:** probably d67f061 test runs, inferred from their times; no `owner` file, so the creating process cannot be identified. **Action:** left in place, not deleted by hand. They are now over 24 h old, so the sweep **will** remove them the next time any stream spills; until then they stay. |
| `ns-8g-entity-*` temp directories (`entity_gate_dev.py` used `mkdtemp`, and one run was killed by a shell timeout) | removed; the script now uses `TemporaryDirectory` |
| 3 Phase 8f temp directories `ns-8f-{rhbjrufn, x1dao730, 6ussj19v}` in the user temp directory | **Contents:** saved calibration profiles (`calibration-<timestamp>` subdirectories); about 4 KB each as reported by `du`; created 10/20 23:59 – 10/21 00:03. **Source:** `scripts/phase8/robust_normality.py`, which creates them with `mkdtemp` and never removes them. **Action:** not swept (different prefix), not deleted; they remain until removed by hand. Fixing that older script is outside this documentation-only correction. |
| derived data | `data/derived/phase8g_post/` (cache, reference, runs; not in git). The frozen `data/derived/phase8g/` is untouched (157 parts, last written by the frozen run) |

**How orphaned spill directories are cleaned up** (`sweep_stale_spills`, `src/netsentinel/streaming/live.py`):
- There is **no background task and no timer**. The sweep runs only when a stream creates
  its spill directory, i.e. at the first spill of a later stream run. Nothing is removed
  while no stream spills.
- When it runs, it removes `netsentinel-spill-*` directories in the same temp root:
  - with an `owner` file whose process is no longer alive; or
  - without an `owner` file (written before 9e526ca) whose modification time is more than
    24 h old.
- It keeps directories of live processes, younger directories without an owner file, and
  anything not named `netsentinel-spill-*`.
- "Older than 24 h" is therefore a condition checked by that sweep, not a deletion time.

## 9. Risks and open issues

| risk | severity | handling |
|---|---|---|
| late records do not change `health` (scenario 10: 90 late records, 10 alerts lost, health `ok`) | medium | counted in `stats.late`; **open Phase 8h engineering task** (item 2): propagate late records into telemetry health |
| spilling is about 10× slower than in-memory streaming | medium | sustained the CTU-13 rates; Phase 8h item 4 |
| a crash leaves a spill directory until a later stream spills (no timer) | low | disk bounded by `max_spill`; removed by the next spill's sweep (§8a); Phase 8h item 4 adds a sweep at monitor start |
| the per-entity review trigger fires on background entities (scenario 9 without bots: 13) | medium (review burden) | review-only; listed entities give the reviewer evidence |
| any data-driven refresh learns a gradual attack | high (if refresh is automated) | refresh stays manual and review-gated; vetted-only recommended |
| alert burden 2,563/h is not triageable | high for deployment | documented; Phase 8h item 3 |
| generalisation | high | one scenario, one network; scenario 10 is not independent |

## 10. Closure decision

**A: Phase 8g is complete, with its limitations documented.** All three GitHub CI jobs
(test, docker, security) passed on bf47e28
([run 40817259525](https://github.com/Apostal322/NetSentinel-AI/actions/runs/40817259525));
details in [RELEASE_READINESS.md](RELEASE_READINESS.md).

- **Reliable software.**
  - The frozen run reproduces exactly.
  - The current stream equals the non-streaming reference wherever the lateness policy
    allows. Every loss is counted.
  - No critical defect is open. The late-record health gap is medium: counted, not silent.
- **Reproducible evidence.** Every published and post-hoc number is regenerated by a script
  from hash-verified inputs.
- **Defensible conclusions.**
  - V3 is descriptive and positive. V4 is refuted, with its root cause established.
  - V1 and V2 are not evaluable. Scenario 10 is not evaluated under the protocol.
- **Why not B, C or D.**
  - Not B: no critical defect remains.
  - Not C: the methodology gap (§8.2) is disclosed and changed no verdict. Re-evaluation on
    the exact reference moves recall by 0.002.
  - Not D: no further experiment on these consumed data could add confirmatory evidence; that
    requires new data, which is Phase 8h.

## 11. Phase 8h proposal (prioritised)

1. **A fresh, untouched evaluation capture with a pre-registration.** Include:
   - a gradual-onset attack;
   - the V4 entity-trigger and QKC hypotheses;
   - initiator coverage, window recall, incident detection, delay, verified-benign FPR and
     background burden as separate endpoints.
2. **Late-record integrity.**
   - A rate-based `late_records` health flag, with a pre-stated threshold and regression
     tests.
   - Future acceptance rules check losses at every lateness.
3. **Alert-burden reduction on development data, then pre-registered:**
   - aggregate pooled-fallback entities;
   - rank by persistence.
   - Store all evidence either way.
4. **Spill performance:** profile read-back and restore; a safe binary format (no pickle);
   a sweep at monitor start.
5. **Reviewer support:** show `excess_entities` and `strong_outliers` on the dashboard
   calibration page.
6. **Docker:** run the image with a mounted bundle and a spilling monitor.
