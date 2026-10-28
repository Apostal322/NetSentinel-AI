# Phase 8g results: CTU-13 scenarios 9 and 10 (independent validation, pre-registered)

**Registration and run:**
- Registration: [PREREG_CTU13.md](../phase8f/PREREG_CTU13.md) (A1 6f6e4f4, A2 121acbf).
- Frozen code: `121acbfe208e…` (registry `reports/phase8g/registry.json`).
- Results: `reports/phase8g/results.json`, `reports/phase8g/provenance.json`.
- Run attempts: `reports/phase8g/run_attempts.json`.

**Grade.** [M] under the Phase 8e evidence standard, for **one** scenario (9) of one network.
The two scenarios share the same 10 infected addresses. Only scenario 9 was evaluable (see
below), so there is no second environment.

## Data and run

| item | scenario 9 (Neris) | scenario 10 (Rbot) |
|---|---|---|
| conn.log records | 2,625,792 | about 10M (built, rejected) |
| calibration | 2.5 h; 1,094,811 flows kept; 530 flows to or from the initiators excluded | — |
| test | 2.69 h; 1,529,406 flows | — |
| time alignment (first record vs README capture start) | 0.8 s | — |
| stream | 0 late, 0 forced closes, health `ok`; 1,039 records dropped as out of range (disclosed A2 limitation) | **A2 acceptance failed:** 6,030 late, 57 forced closes, buffer at its 1.5M cap with 600 s lateness. **Declared failed, not evaluated.** |
| peak memory / time | 2.0 GB build; 2.6 GB evaluation; 20 min for the whole run | 2.7 GB build |

## Results (scenario 9, primary `vetted_benign`; sensitivity `unlabelled` in brackets)

| hypothesis | result | verdict |
|---|---|---|
| **V3** initiator detection at the operating point (descriptive) | **10 / 10** initiators detected (Wilson 95% [0.72, 1.00]) [10/10]. Attack-window recall **0.209** (block bootstrap 95% [0.147, 0.275], 11 blocks of 15 min) [0.328]. Median delay from documented infection **47.5 s** (34–66 s, one initiator 442 s). **0 false alerts in 803 verified-benign windows** (Wilson upper bound 0.48%) [0]. **2,563 alerts/h** on unverified background windows (530,694 windows); global 11.2/h, service 12.3/h. | descriptive (as registered) |
| **V1** reliability of `baseline_state` | every test segment is `drift_suspected` (bots are active throughout); 0 `monitoring` segments | **not evaluable** (as pre-declared) |
| **V2** shift-test adoption | C1 null not confirmed (0/1); 2 of 3 segments `confirmed_shift`, 1 untestable; no `valid` segment | **not evaluable for adoption** (as pre-declared) |
| **V4** gated recalibration (S5) vs fixed (S1) | S5 activated once (gate passed) and **absorbed 1,932 attack windows (71%)**. Recall 0.209 → 0.178; initiators 10/10 in both; benign FA/h 0 in both. | **failure** (absorbed > 1%) |

**Assessment states.**
- `normality_supported_share` = **0.0**: no test window was presented as normal. The device
  threshold was set by transient sources (`tail_fallback_share` 0.97, Phase 8c mechanism) and
  every segment was drift-suspected.
- Profile status `baseline_provisional`: the global threshold diagnostics are unreliable.

## Label provenance (after the run)

- **Labels confirm the documented initiators exactly.** From-Botnet sources are the 10
  documented VMs in both scenarios, with no undocumented botnet sources. To-Botnet
  destinations are documented initiators only.
- **Normal hosts.** The From-Normal sources are the 6 documented hosts **plus 147.32.1.20**. In
  this evaluation it counted as unverified.
- **Labels are IP-based, not bounded by the infection time.**
  - The file times are local (CEST): the last botnet flows (17:07–17:10) match "stopping
    every vm" at 17:06–17:10 CEST in the README.
  - In scenario 9 the first From-Botnet flows (12:28–12:42 CEST) start when each VM was
    started, about 2 h **before** its documented infection (14:24–15:05 CEST).
  - A label-based evaluation would count uninfected VM traffic as attack. The pre-registered
    design rule (windows after the documented infection) avoids that.
- **Label file.** Scenario 10's `.binetflow` carries the labels. The `.labeled` file uses an
  older column format (`Label(Normal:CC:Background)`).

## Interpretation

1. **[M] What the detector does on this network.**
   - At its deployed operating point it found **every** documented initiator within about a
     minute of infection, and raised **no** false alert on the verified-benign hosts.
   - It detected about one in five attack windows.
   - This is the first independent, pre-registered evidence of initiator detection in the
     project. It covers one scenario and one botnet family (Neris). The 10 initiators are VMs
     on the same network, so they are not 10 independent environments.
2. **The alert burden is not established.**
   - Background traffic is unlabelled (unknown, not benign). The 2,563 alerts/h there cannot
     be called false, but an operator would have to triage them.
   - That is about 1.3% of background windows, close to the 1% target on a population of
     530k windows.
3. **[M] Unvetted refresh absorbs attacks.** V4 replicates the Phase 8f development finding on
   independent data. The update gate passed a candidate built from attack-heavy traffic,
   because the current baseline scores most attack windows below threshold.
4. **[M] The uncertainty states did their job.** With drift suspected everywhere and a
   tail-dominated threshold, no quiet window was presented as normal.
5. **A streaming limit was found on real data.** Dense botnet traffic (scenario 10) overflowed
   the 1.5M-record buffer even at 600 s lateness, so windows were force-closed and 6,030
   records were late. The A2 rule correctly refused to evaluate it. **[H]** Rbot's floods
   produce record bursts that a fixed-size buffer cannot hold.

## Not established and next steps

- **Not established:**
  - generalisation beyond scenario 9;
  - the alert burden on unlabelled traffic;
  - any adoption decision for the shift test (V2 not evaluable on these data).
- **Consumed.** CTU-13 scenarios 9 and 10 are now consumed. Scenario 10 was opened by the
  frozen build, although it was not evaluated.
- **Product follow-ups found by this run:** both are now fixed after the run
  ([STREAMING_FIXES.md](STREAMING_FIXES.md)). The results above remain those of the frozen
  code 121acbf.
  1. long connections dropped by the START-based out-of-range rule (1,039 records, silent);
  2. buffer exhaustion under dense attack traffic (scenario 10).
