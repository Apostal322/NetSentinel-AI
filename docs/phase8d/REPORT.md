# Phase 8d report: operating-point reliability and streaming validation

**Data roles.**
- The consumed data (ToN_IoT, the Phase 8b captures, 49-1) appear only in **post-hoc** or
  **retrospective** analyses, labelled in every table.
- All choices were made on development data: IoT-23 x9, NF-UNSW development part,
  CTU-Normal x12.
- The frozen verdicts (P8b B1-B6, P8c X1-X5) are **unchanged**.

**Evidence labels used below:**
- **[M]** measured, on the stated data;
- **[E]** exploratory observation;
- **[H]** hypothesis, not tested;
- **[A]** unverified assumption.

Scripts are in `scripts/phase8d/`; outputs in `reports/phase8d/`.

## 1. Streaming equivalence audit (post-hoc, ToN_IoT input)

### 1.1 Record-level audit (`stream_audit.py`)

Three ways of forming windows from the same 4,000,000 records:
1. a non-streaming reference: window = end // 30 s, with the same deduplication key;
2. the frozen stream: the clock froze after the 460 h gap;
3. the fixed stream: Phase 8c resync.

| | reference | frozen stream | fixed stream |
|---|---|---|---|
| windows | 5,820 | 5,820 | 5,820 |
| windows whose record membership differs from the reference | — | **0** | **0** |
| duplicates dropped | 18,606 | 18,606 | 18,606 |
| late records | — | 0 | 0 |
| closures: watermark / forced by buffer cap / final flush | — | 5,406 / **334** / 80 | 5,662 / 140 / 18 |
| clock_skew records / resyncs | — | 3,797,795 / 0 | 2,000 / 2 |

- **[M]** All 334 windows force-closed in the frozen run have exactly the reference
  membership. Membership was compared by an order-independent fingerprint: count, sum and
  XOR of record hashes.
- **[M]** The fixed stream still force-closes 140 windows. The evaluation period carries
  about 260 records/s, and a 3,700 s lateness allowance therefore needs about 1M buffered
  records. The buffer cap, not only the clock bug, caused forced closures.
- **[M]** Zero late records was *necessary* but not *sufficient* evidence. The record-level
  audit establishes membership equality directly.

### 1.2 Evaluation-table and prediction comparison (`posthoc_windows.py`)

- **[M]** The ToN_IoT evaluation windows were rebuilt with the **current** code (resync with
  probation) and a **smaller** buffer cap: 1.0M instead of 1.5M, giving 195 forced closures
  instead of 334.
  - The first attempt with the frozen cap was stopped by the memory watchdog at 3.43 GB.
  - The smaller cap makes the test stricter.
- **[M] Everything is identical to the frozen run:**
  - all five tables (calibration and evaluation windows, clean and unlabelled, truth), cell
    by cell;
  - flow counts, first-attack times, midpoint and evaluation span;
  - scores and alerts of A, C2 and LightGBM: max score difference 0.0, 0 alert
    disagreements.
- Current stream: 2 resyncs, 0 reverts, health ok, 0 late records. Peak 2.93 GB.
- **Conclusion [M]:** the clock-freeze bug did not influence the frozen Phase 8c evaluation.
  X1-X5 stand as reported.

### 1.3 Forged future timestamps

- **[M] Defect introduced by the Phase 8c fix.**
  - After 1,000 records with forged timestamps 30 days ahead, the clock resynchronised to
    the forged time.
  - **96.7% of the genuine records that followed (6,960 of 7,200) were then dropped as late**,
    and this would continue until real time caught up.
  - Malformed logs or a compromised sensor are realistic sources.
- **Fix (product).** A resync is now on probation:
  - later records far *behind* the new clock vote against the jump, records consistent with
    it vote for it;
  - 1,000 contradicting records revert the clock (`clock_reverts`, `health = clock_anomaly`).
- **[M]** With the fix, 986 genuine records are lost (about one probation period) instead of
  6,960 and counting. A genuine 20 h gap is still accepted, with no revert, no late records
  and no forced closes.
- Regression tests: `tests/integration/test_streaming.py::test_forged_future_timestamps_are_reverted_with_bounded_loss`,
  `::test_genuine_gap_is_confirmed_not_reverted`.
- **Residual risk [M]:** each forged burst still costs about `resync_after` genuine records
  plus the windows open at the jump. An attacker who can write the log can still blind the
  monitor briefly; the anomaly is now visible as `health`.

## 2. Why good ranking does not give attacker-level detection

`operating_points.py`; the rule and budget were fixed beforehand in DEVELOPMENT_LOG.md.

**Three mechanisms, measured:**

1. **Window metrics weight attackers by window count. [M]**
   - Development: most captures have one attacker with 943-2,168 attack windows; NF-UNSW has
     4 attackers of about 1,020 windows each.
   - ToN_IoT (retrospective): the top 3 of 40 attack-labelled sources hold 57% of the attack
     windows.
   - PR-AUC therefore mostly measures the heaviest attackers. Attacker recall counts every
     attacker once.
2. **Ranking-undetectable attackers. [M]**
   - At an *oracle* threshold of exactly 1% FPR on the capture's own benign windows (not
     achievable in practice), some attackers have no window above it.
   - NF-UNSW: robust-z 4 of 4 undetectable, LightGBM 0 of 4.
   - ToN_IoT (retrospective): robust-z 36 of 40, LightGBM 26 of 40.
   - No threshold choice can find these at that FPR.
3. **Threshold misplacement. [M]**
   - The realised operating point differs from the oracle one.
   - ToN_IoT robust-z: realised FPR 8.9% vs target 1%, while oracle window recall at 1% FPR is
     only 1.9%. Its PR-AUC of 0.695 comes from ranking outside the operating region.
   - Development NF-UNSW robust-z: FPR 3.4%, recall about 0.

**Label structure (ToN_IoT, retrospective) [M].**
- None of the 40 sources with attack-labelled flows lies in the documented attacker range
  192.168.159.30-39. 16 are 192.168.1.x, about 20 are link-local 169.254.x.x, and 1 is
  public.
- In these files the label does not follow the documented IP tagging, and many "attacking
  sources" are probably victims or incidental hosts **[H]**.
- Attacker-level recall on ToN_IoT (e.g. 9/40) is therefore **not** a meaningful count of
  attackers.

**Operating-point comparison (development; budget: max FPR <= 0.03 per covered capture with
>= 30 benign windows, median false alerts/h <= 1):**

| policy | attackers | captures covered | max FPR | median / max false alerts/h | within budget |
|---|---|---|---|---|---|
| A deployed | 9/10 | 22/22 | 0.111 | 0.0 / 50.9 | no |
| **A + abstention** | 4/10 | **11/22** | 0.010 | 0.0 / 1.1 | **yes (selected)** |
| B device / C Mondrian (+abst) | 5/10 (4/10) | 22 (11) | 0.111 (0.017) | — | no (yes) |
| C2 address class (+abst) | 9/10 (4/10) | 22 (11) | 0.111 (0.010) | — | no (yes) |
| E_local LightGBM | 10/10 | 22/22 | 0.286 | 1.9 / 36.9 | no |
| E_source | 10/10 | 22/22 | **0.946** | 0.6 / 87.4 | no |
| E_device / E_c2 | 10/10 | 22/22 | 0.286 | 1.9 / 37-39 | no |
| any E + abstention | 9/10 | 8/22 | 0.154 | 0.3 / 35 | no |

- **[M]** No policy is both within budget and sensitive.
- **[M]** The rule selects **A + selective abstention**: it is within budget *because it
  declines to decide on half of the captures* (unreliable threshold or tail warning).
- **[M]** Every LightGBM variant breaks the false-alert budget on benign development
  captures. Device-specific and hierarchical thresholds do not repair this.
- **[E]** Selective abstention is the only mechanism found that keeps the false-alert promise
  where calibration is weak. Its cost is explicit: coverage.

## 3. Calibration gaps and drift (`drift_gaps.py`, development unless stated)

| hours since calibration end | robust-z FPR | LightGBM (local) FPR | median KS (benign scores vs calibration) |
|---|---|---|---|
| 0-1 | 1.7% | 3.7% | 0.25 |
| 1-2 | 1.8% | 3.7% | 0.26 |
| 2-4 | 2.8% | 2.8% | 0.36 |
| 4-8 | 3.1% | 2.6% | 0.28 |
| 8-16 | 2.7% | 1.9% | 0.23 |

- **[M]** The deployed robust-z FPR roughly doubles within a few hours of calibration, and
  the score distributions shift (KS 0.25 -> 0.36).
- **[M]** With an older calibration (only its earliest half), robust-z FPR reaches 6-16% at
  2-8 h. This is not monotone, and some bins are small.
- **[M]** NF-UNSW: the evaluation half lies entirely on 18 Feb, 26 days after the calibration
  days. Robust-z FPR there is 3.4%.
- **ToN_IoT (retrospective) [M]:** KS distance between calibration held-out scores and benign
  evaluation scores is 0.62 (robust-z) and 0.72 (LightGBM), across a median gap of 462 h.
  - **[H]** Drift across the 460 h gap is a plausible cause of X1 (8.9% FPR).
  - It cannot be separated from model inadequacy with these data.

**Safety policies (pooled development captures):**

| policy | robust-z false alerts | robust-z attack windows alerted | robust-z attackers | LightGBM false alerts | LightGBM attackers |
|---|---|---|---|---|---|
| P0 reuse forever | 428 | 2,325 | 9/10 | 502 | 10/10 |
| P1 expire after 4 h | 193 | 654 | 6/10 | 310 | 8/10 |
| P1 expire after 8 h | 378 | 1,312 | 8/10 | 467 | 9/10 |
| P2 suspend on unlabelled drift alarm | **22** | **158** | 6/10 | 108 | 10/10 |

- **[M]** An unlabelled drift monitor (alert rate vs target) **cannot distinguish drift from
  an attack**: attacks raise the alert rate too. Suspending on such an alarm removes 95% of
  false alerts and 93% of alerted attack windows.
- **[E]** Expiry trades detections for false alerts roughly proportionally. No expiry horizon
  dominates.
- **Safer [E]:** never suspend silently. An expired or drift-suspected baseline should change
  the *state* (`unsupported` / `drift_suspected`, shown to the operator) while alerts continue
  to be shown with that state.
- The baseline must never be updated from suspicious periods. The existing update gate already
  requires review.
- Not implemented here; recommendation 3 in section 6.

## 4. Scientific validity of the Phase 8c results (post-hoc; frozen verdicts unchanged)

**Bootstrap blocks (`ci_reliability.py`).**
- 4 hourly blocks allow only **35 distinct resamples**, and the 4 hours differ: attack share
  41%, 51%, 60% and 78%.

| | 60 min (4 blocks, as frozen) | 15 min | 5 min | iid windows |
|---|---|---|---|---|
| X3 delta 0.278 | [0.136, 0.425] | [0.209, 0.372] | [0.209, 0.356] | [0.249, 0.305] |
| X4 delta 0.147 | [0.035, 0.262] | [0.090, 0.219] | [0.109, 0.194] | [0.122, 0.170] |

- **[M]** The direction of X3 and X4 is robust to the block choice.
- **[M]** The frozen intervals are the widest and coarsest, not anti-conservative relative to
  the alternatives.
- **[A]** All of them assume that windows within the 4-hour evaluation are representative of
  the dataset. No block size fixes "one dataset, one period".

**Other limitations:**
- **IP-based labels:** they do not match the documented attacker IPs in these files
  (section 2). Window-level metrics are the most defensible here, attacker-level ones the
  least.
- **Attack-heavy evaluation:** 99.4% of evaluation flows are labelled attack, and 1,352 of
  2,729 windows are attack windows. PR-AUC baselines are therefore high, and false-alert rates
  rest on 1,377 benign windows in 4 hours.
- **Metric levels kept separate:**
  - window level: PR-AUC, recall, FPR;
  - attacker level: attackers with at least one alerted attack window;
  - incident level: purity and reduction (X5).
  - They answer different questions and disagree here.
- **LightGBM** outranked robust-z on one external dataset (X3) and beyond the scan signature
  (X4). That is **n = 1**, and on development data the same models break the false-alert
  budget. It is not shown to be generally superior.

## 5. Product decision

**Evidence against shipping a supervised-window detector, even behind an opt-in flag:**
1. **[M]** On benign development captures, every LightGBM operating point breaks the
   false-alert budget: up to 29% FPR with a local threshold and 95% with the source threshold.
   Device-specific and hierarchical thresholds and abstention do not repair it.
2. **[M]** The transferred threshold is unpredictable across networks (B5 mixed: 0-5.5% on
   IoT-23, 2.7% on ToN_IoT, 95% on a benign development capture).
3. **[M]** The external success rests on one dataset, a 4-hour attack-heavy period and labels
   that do not match their documentation.
4. **[A]** An opt-in flag would be read as endorsement. The project's own budget says this
   operating behaviour is not acceptable.

**Decision:**
- LightGBM window scoring stays **research-only**: no product flag.
- The safe production default (local robust baseline, supervised threat policy `unverified`)
  is **unchanged**.
- A new pre-registered validation on a further independent network would be required, with an
  explicit false-alert budget as a primary criterion.

## 6. What changed in Phase 8d, and recommendations

**Changed (product).**
- Streaming clock-resync probation against forged or malformed future timestamps, with
  `clock_reverts` and `health`. Tests added.

**Recommendations (not implemented; each needs its own development study and test):**
1. Selective abstention as a **visible state**. When calibration is unreliable or the tail
   diagnostic warns, report "no supported decision" instead of a verdict. This was the only
   within-budget behaviour found.
2. Separate false-alert budgets per entity class (local devices vs transient external
   sources), shown to the operator.
3. Calibration age as a first-class signal (FPR roughly doubles within hours), and drift
   states that annotate instead of suppress (section 3).
4. Attacker-level and incident-level metrics as primary criteria in future pre-registrations,
   next to window-level ones.
