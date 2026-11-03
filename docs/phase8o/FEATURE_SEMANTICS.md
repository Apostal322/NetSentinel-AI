# Phase 8o: feature contract and `new_dst_frac` semantics

**Sources:**
- `src/netsentinel/behavior/windows.py` (`prepare_flows`, `aggregate`);
- the research builders: Phase 8b `WindowBuilder`, Phase 8i `build_windows`, Phase 8j
  `build_p1x`;
- the deployed path: `behavior/calibrate.py`, `behavior/monitor.py`, `streaming/live.py`.

Audit numbers come from `reports/phase8o/semantics_audit.json` (EXPLORATORY; saved artifacts only).

## 1. Shared construction

- **Entity window:** a device (`ipv4_src_addr`) in a 30 s tumbling window.
- **Flow assignment:** a flow belongs to the window that contains its **end** time.
- **Causality:** a window's features use only the flows that ended inside it, plus (for
  `new_dst_frac`) the destination memory built from earlier windows. No later record enters.
  - A long-lived connection counts once, in the window where it ends. Its whole byte volume
    and its duration are attributed there, so detection of a long session waits for its end.
- **Missing values:** `prepare_flows` replaces null bytes, packets and durations with 0 (G2.1).

## 2. Feature contract

| feature | formula per (device, window) | raw inputs | units | memory / state | missing-value behaviour |
|---|---|---|---|---|---|
| `log_flows` | ln(1 + flows) | flow count | log count | none | — |
| `log_up_bytes` | ln(1 + Σ `in_bytes`) | originator → responder bytes | log bytes | none | null → 0 |
| `log_down_bytes` | ln(1 + Σ `out_bytes`) | responder → originator bytes | log bytes | none | null → 0 (one-way telemetry gives 0) |
| `log_pkts` | ln(1 + Σ (`in_pkts` + `out_pkts`)) | packets | log count | none | null → 0 |
| `log_dst_hosts` | ln(1 + distinct `ipv4_dst_addr`) | destinations | log count | none | — |
| `log_dst_ports` | ln(1 + distinct `dst_port`) | ports | log count | none | — |
| `no_reply_frac` | mean[`out_pkts` = 0] | reply packets | share | none | **null `out_pkts` → counted as no reply** (G2.1) |
| `rst_frac` | mean[TCP ∧ (`cli_rst` ∨ `srv_rst`)] | Zeek-style reset flags | share | none | columns absent → 0 for every flow |
| `udp_share` | mean[`protocol` = 17] | protocol | share | none | — |
| `med_log_dur` | median ln(1 + duration ms) | duration | log ms | none | null → 0 |
| `upload_share` | Σ up / (Σ up + Σ down + 1) | bytes | share | none | null down → share ≈ 1 |
| `new_dst_frac` | distinct destinations not in the memory / distinct destinations | destinations | share | **destination memory (below)** | — |

- **Service context:** `service` is used only for the service level, which is not in the
  LightGBM models.
- **Order:** `WINDOW_FEATURES`, unchanged since Phase 8b. The deployed `load_profile` refuses a
  different feature list. The research LightGBM candidates (B0, M2) are not packaged artifacts.

## 3. `new_dst_frac` across the lifecycle

| where | builder | memory | what "new" means |
|---|---|---|---|
| source **calibration** rows (training; all benign) | `WindowBuilder` → `cal_clean` | **expanding** over calibration flows from the start of the capture (calibration attack *flows* removed) | first window in which any device contacts the destination |
| source **evaluation** rows (training; benign and every attack row) | → `eval_clean` | **frozen** at the time midpoint | not contacted during calibration, however often contacted since |
| target T0 **hold-out** (last 30 % of calibration slots) | `build_p1x` → `cal_p1x` | **expanding** (calibration-period attacker *hosts* removed) | as for source calibration |
| target **evaluation** | → `eval_p1x` | **frozen** at the midpoint | as for source evaluation |
| deployed monitor, calibration | `calibrate_flows` | expanding (`aggregate` without `known_dst`) | — |
| deployed monitor, scoring | `score_flows` | frozen `profile.known_dst`: every calibration destination (`crossfit`) or the fit part only (`split`) | — |

- **The two semantics are intended.** They were never stated as one contract, and they meet
  inside one training matrix.
- **The label is confounded with the semantics:**
  - every attack row has frozen semantics;
  - every expanding-memory row is benign.
- **Memory initialisation:** empty at the first flow of the capture; for NF-CIC, at the first
  flow of each day.
- **Restarts:** the research builders stream in time order and carry the memory forward
  (`prior_dst`). The deployed profile keeps a frozen set and never learns online.

## 4. Temporal causality checks

| case | behaviour | verified by |
|---|---|---|
| a window crossing the calibration boundary | its calibration flows form a calibration row, its evaluation flows an evaluation row; the memory takes the calibration part | Phase 8m build (`pre_freeze` tagging); Phase 8o F3 |
| a long connection | counted in its end window only | `prepare_flows` |
| out-of-order records within a call | sorted by end time, so the result does not depend on input order | test `test_aggregate_input_order_invariant` |
| out-of-order windows across calls | `NoveltyMemory.process` raises; `aggregate` with `prior_dst` assumes time order | Phase 8m tests; test `test_window_aligned_chunks_equal_batch` |
| a window split across two calls | two partial rows (G2.2); the live windower closes whole windows only, with 360 s lateness | test `test_split_window_gives_partial_rows` |
| a host or destination first seen after the freeze | always novel (frozen) | audit: NF-ToN hosts new after the freeze carry 57 % novel benign windows vs 15 % for known hosts |
| repeated destinations | new only in the first window (expanding); new for ever (frozen) | test `test_frozen_vs_expanding_repeated_destination` |
| duplicate flows | counted twice in counts, bytes and packets; destination shares are unchanged | test `test_duplicate_flow_counts` |
| missing flow direction | see G2.1 | test `test_missing_reply_counts_as_no_reply` |

## 5. Audit: the distributions behind the semantics

**Source training rows** (share of rows with `new_dst_frac` > 0):

| source | calibration (expanding, benign) | evaluation, benign (frozen) | evaluation, attack (frozen) |
|---|---|---|---|
| NF-CIC, 9 regular days | 2.8–3.7 % | 3.3–6.7 % | 02-14 100 %, 02-22 98.7 %, 03-02 100 %, 02-16/02-20/02-21 0 % |
| NF-CIC 02-27 (229 calibration windows) | 7.4 % | 10.5 % | — |
| **NF-CIC 02-28 (392 calibration windows)** | 3.1 % | **89.5 % (mean 0.85)** | — (infiltration is excluded as noisy) |
| NF-UNSW | 0.23 % | 0.03 % | 99.9 % |
| NF-ToN | 0.32 % | 9.0 % | 39 % |

**The F2 replay.** Replaying the evaluation rows with an expanding memory (Phase 8m
`nov_unconditional`, clean memory) changes 2.4–5.7 % of the regular NF-CIC evaluation rows,
25 % of NF-UNSW's and 14 % of NF-ToN's. It removes almost all attack novelty: NF-UNSW attack
mean 0.90 → 0.001; 02-14 1.0 → 0.005. So under an expanding memory the brute-force and scan
attacks are not novel; under a frozen one they are novel in every window.

**Targets** (benign windows with `new_dst_frac` > 0): see GAP_REGISTER G0.3.
- The NF-ToN evaluation novelty peaks in the second quarter (65 %), when hosts first seen after
  the freeze are active.
- On NF-UNSW the evaluation novelty is *lower* than the hold-out's.

## 6. What the audit establishes, and what it does not

- **Established:**
  - training-row semantics differ from evaluation semantics, and are confounded with the label;
  - one source day carries most of the "novel but benign" signal;
  - the T0 hold-out sees a much less novel benign population than evaluation does.
- **Not established:** whether any of these *causes* the detection or false-alert failures.
  That is H1 (training side), H1b (the cold-start source) and H4-C1 (calibration side), in
  PREREGISTRATION.md.
