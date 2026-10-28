# Pre-registration: CTU-13 scenarios 9 and 10 (amendment A1 to INDEPENDENT_VALIDATION_PROTOCOL.md)

Built from [PREREGISTRATION_TEMPLATE.md](../phase8e/PREREGISTRATION_TEMPLATE.md).

**Status.** Registered before any CTU-13 data file is downloaded or opened. The only things
read so far are the scenario READMEs and the directory listings (CTU13_ELIGIBILITY.md).

**Operator decisions (2026-10-28):**
- attribution-only use is accepted;
- calibration option (a) is chosen.

## 0. Identity

- **Title:** NetSentinel behaviour detector and calibration-validity signals on CTU-13
  scenarios 9 and 10.
- **Hypotheses:** V1–V4 of INDEPENDENT_VALIDATION_PROTOCOL.md, as amended in section 4.
- **Commit of this registration:** the commit that adds this file.
- **Evaluation code:**
  - written as `scripts/phase8g/` and tested on synthetic Zeek fixtures only;
  - committed **before any CTU-13 file is opened**;
  - its SHA is recorded in `reports/phase8g/registry.json` at that point.
  The detector, assessment and recalibration code are the frozen Phase 8f components named in
  the protocol (section 2).

## 1. Data

| field | value |
|---|---|
| dataset | CTU-13, Stratosphere Lab / CVUT, Aug 2011, university department network 147.32.0.0/16 |
| licence | attribution only ("free to use these files as long as you reference this project"). Citation: Garcia et al., Computers & Security 45 (2014) 100–123, doi:10.1016/j.cose.2014.05.011, and the Malware Capture Facility Project. **Accepted by the operator.** |
| source | the official server mcfp.felk.cvut.cz/publicDatasets/ only; no mirrors |
| scenario 9 | CTU-Malware-Capture-Botnet-50, Neris: `bro/conn.log` (323 MB), `detailed-bidirectional-flow-labels/capture20110817.binetflow` (273 MB), `README.md` |
| scenario 10 | CTU-Malware-Capture-Botnet-51, Rbot: `bro/conn.log` (1.2 GB), `detailed-bidirectional-flow-labels/capture20110818.binetflow` (171 MB) and `.binetflow.labeled` (184 MB; which file carries the labels is not known before opening), `README.md` |
| integrity | size and SHA-256 of every file recorded on download in `reports/phase8g/registry.json` |
| location | `data/raw/ctu13/<scenario-id>/` (git-ignored); downloads go into their own empty directory |
| consumed | after the run, CTU-13 scenarios 9 and 10 are marked consumed in the hypothesis ledger |

## 2. Unit, level and populations

- **Windows:** 30 s, assigned by flow end, from Zeek `conn.log`. The Phase 8b harness protocol
  is used unchanged, except for the split rule in section 3.
- **Primary level:** device (source address). Global and service levels are reported
  descriptively: they include unknown background traffic.
- **Populations** (fixed by this registration, from the READMEs):
  - **initiators:** the 10 documented infected VMs, 147.32.84.165, .191, .192, .193, .204,
    .205, .206, .207, .208, .209, in both scenarios;
  - **verified benign:** the documented normal hosts of each scenario, as listed in its
    README (6 per scenario);
  - **unverified:** every other address. Background traffic is unknown, not benign.
- **Monitored network:** 147.32.0.0/16 is reported as "local" here. The product's private
  address rule is not changed.

## 3. Splits (option a)

- **Per scenario:** calibration = the first **2.5 h** after the first conn.log record (30
  blocks of 5 min); test = the rest. That is about 2 h 41 min (scenario 9) and about 2 h 38 min
  (scenario 10); both are ≥ 10 blocks of 15 min.
- **Calibration exclusion:** every flow with an initiator address as source **or**
  destination is removed from the calibration data. That covers the VMs before and after
  infection, and the flows sent to them.
  - Scenario 9: the VMs run uninfected from 12:27 and are infected from 14:24 CEST.
  - Scenario 10: infected from about 11:03 CEST.
  - The VMs therefore have no own profile and are scored by the pooled fallback.
- **Calibration modes:**
  - **primary:** `vetted_benign`. The vetting is the documented design: initiators excluded;
    the rest is asserted benign;
  - **sensitivity:** `unlabelled`, same data.
- **Disclosed deviation from protocol section 3 (blinding).**
  - The initiator and normal-host address lists come from the READMEs (the experiment
    design). They are used before the run, for the calibration exclusion and the population
    definitions.
  - Flow labels (`binetflow`) stay unopened until the frozen run has written its outputs.

## 4. Hypotheses and decision rules (amended for these data)

**Attack windows.** Test device windows of an initiator that start after its documented
infection time.
- The READMEs label as Botnet all flows to or from the infected addresses, so no flow-level
  join is needed.
- The binetflow labels are used afterwards, only for the provenance audit (LABEL_PROVENANCE
  method): roles, direction, and the From-Botnet share per address.

**Benign windows.** Test device windows of the verified-benign hosts.

| ID | metric | decision rule |
|---|---|---|
| V1 | pooled benign FPR (verified-benign hosts) over 1 h test segments with `baseline_state` = monitoring | **success:** ≤ 2% with Wilson 95% upper bound ≤ 3%. **Not evaluable** if fewer than 3 such segments across both scenarios: every test segment contains active bots, so a drift flag is expected. |
| V2 | C1–C4 of PLAN.md section 2 | **not evaluable for adoption:** there are no benign-only test segments, so C4 is undefined. C1–C3 are reported descriptively. The shift test cannot be adopted from these data. |
| V3 | per scenario: initiators detected / 10 (any alert in an attack window), attack-window recall, delay from documented infection to first alert, FA/h on verified-benign hosts, unverified alerts/h; compared with never-alert Z | **descriptive**, with Wilson intervals. Both scenarios share the same 10 addresses, so they are reported separately and never pooled as 20 independent initiators. |
| V4 | S5 vs S1 (2 h refit cadence, 1 h segments; at most one refit per test period) | **success:** S5 loses no initiator, absorbs ≤ 1% of attack windows, and its benign FA/h is not higher than S1's |

**Always reported:**
- assessment-state coverage (`normality_supported_share`);
- shadow validity per segment;
- false-negative cost for c ∈ {10, 100};
- CPU time and peak memory;
- the `unlabelled` sensitivity run.

## 5. Uncertainty

- Block bootstrap over 15 min test blocks: ≥ 10 blocks, 2,000 resamples, seed 0. This applies
  to the window recall and the FPR.
- Wilson intervals for initiator counts.

## 6. Compute and safety

| item | value |
|---|---|
| download | about **2.15 GB** from the official server (the files above, both scenario 10 label files included). Needs operator approval. |
| expected peak memory | < 3 GB: streaming windowing with the Phase 8b harness under the 3.4 GB watchdog. Scenario 10 (1.2 GB conn.log) is the largest file. |
| expected runtime | < 30 min, run detached with a status file |
| one heavy job at a time | yes |
| detection only | NetSentinel reads the files and never contacts any listed host |
| the botnet executables in the scenario folders | **not** downloaded |

## 7. After the run

- Results go to `reports/phase8g/`.
- Then: the provenance audit, the hypothesis-ledger entries, and marking CTU-13 scenarios 9
  and 10 as consumed.
- Anything else is post hoc **[R]**.

## Amendment A2 (2026-10-28, after aborted attempt 1; before any result)

**Attempt 1** (`reports/phase8g/run_attempts.json`):
- The frozen code (dfaf206) built scenario 9 (2.6M records, peak 2.18 GB).
- Its scenario 10 window build was killed by the 3.4 GB watchdog: the 3,700 s harness lateness
  buffers about an hour of records at about 550 records/s.
- `evaluate` stopped on the missing metadata. **No result was computed and no flow label was
  opened.**

**Operator decision.** Amendment A2, lateness only.
1. **Lateness becomes a per-scenario setting.** Scenario 9 keeps 3,700 s; scenario 10 uses
   **600 s**.
2. **Acceptance rule.** A non-default lateness is accepted only if the build reports
   `late == 0` and `forced_closes == 0`. Then every record lands in its END window, exactly as
   with unlimited lateness.
   - Otherwise the scenario is **declared failed** and not evaluated.
   - The failure is reported as such; it is not re-tuned.
3. **Stale parts.** The builder removes the parts of an aborted attempt before writing.
4. **Disclosed limitation, frozen behaviour unchanged.**
   - The stream clock classifies records by flow START. In scenario 9, 1,039 records (0.04%)
     were quarantined as out of range and dropped at flush with health `ok`.
   - Hypothesis (not verified): connections longer than about `max_skew_s` + lateness.
   - The drop applies equally to every population, and it is reported with the results.
   - A product fix is out of scope for this protocol.
5. **Rerun.** Both scenarios are rebuilt and evaluated with the re-frozen code. The new SHA is
   recorded in `reports/phase8g/registry.json` before the run.
