# Independent validation protocol (Phase 8f, Mission 6)

**Status: prepared, not run.**
- No data has been downloaded or opened.
- Running it needs explicit approval of a named dataset (download size, licence) under the
  project's approval gates.
- It instantiates [PREREGISTRATION_TEMPLATE.md](../phase8e/PREREGISTRATION_TEMPLATE.md) and the
  Phase 8e minimum evidence standard.
- Fields marked **[fill on approval]** are completed and committed **before** the data is
  opened.

## 1. Eligibility of a dataset

A candidate must satisfy every item. Each item is checked from the official source and
recorded with a link.

| requirement | check |
|---|---|
| a genuinely independent environment | a network, organisation and period never used by NetSentinel; not IoT-23, ToN_IoT, CIC-IDS2018 / CSE-CIC-IDS2018, UNSW-NB15 / NF-UNSW-NB15 or the CTU-Normal captures |
| provenance and licence | official publisher page, licence text permitting research use, citation; no mirrors (Phase 8c rule) |
| verified attack-initiator identities | a published list of attacking / infected host addresses with time intervals, produced by the experiment design and not inferred from flow labels. The M1 provenance audit (direction, roles, time bounds) runs after the frozen evaluation and must agree with the list. |
| compatible telemetry | Zeek conn.log, or flow records mappable to the canonical fields (timestamps, 5-tuple, per-direction bytes and packets, connection state). The mapping is written and tested on synthetic records before the data is opened. |
| enough time | at least 2.5 h of calibration and 2.5 h of test (≥ 10 blocks of 15 min each, evidence standard) per environment; ≥ 1 h of benign test time per population for FA/h |
| enough positives | ≥ 5 confirmed initiators in the test period for any rate claim (else counts only) |
| size within limits | download and peak memory within the machine limits (< 3.5 GB RAM; larger downloads need a separate approval) |

**Candidates.** Named from prior knowledge; every row must be verified before approval.

| candidate | why it might qualify | open questions |
|---|---|---|
| CTU-13 (Stratosphere Lab, CVUT) | 13 botnet scenarios on a university network; infected-host addresses documented per scenario; Zeek conn.log available | **checked 2026-10-28: [CTU13_ELIGIBILITY.md](CTU13_ELIGIBILITY.md).** Attribution-only use, no formal licence; only scenarios 9/10 have ≥ 5 initiators; the calibration rule needs an amendment |
| The operator's own network with a scheduled, authorised red-team exercise | initiators known by construction; the target environment itself | needs written authorisation, scope and an exercise plan; the strongest evidence for a deployment decision |
| CIC-IDS2017 | documented attacker addresses and schedule | the same lab and testbed design as CSE-CIC-IDS2018 (consumed): weak independence; known labelling errors |

## 2. Frozen components (recorded at registration)

- **Code:** git SHA **[fill on approval]**; scripts under `scripts/phase8g/` (to be written)
  calling only the components listed here.
- **Behaviour detector:** the deployed policy A. Robust median/MAD per key, top-2 |z|,
  cross-fit 1% threshold, clean (vetted) calibration on the calibration period only.
- **Uncertainty:** Phase 8e assessment states. Phase 8f: `baseline_state` (adopted) and the
  shift test in shadow mode.
- **Recalibration:** S1 (fixed) and S5 (candidate + gate) exactly as in
  `scripts/phase8f/recalibration_sim.py`. S4o is impossible without labels and is not
  evaluated.
- **Supervised models:** not part of the primary claims (out of domain; Phase 8b–8d).

## 3. Splits

- Per environment, time-ordered:
  - **calibration** (the first ≥ 2.5 h with no listed initiator active, verified from the
    published schedule only, not from flow labels);
  - **test** (the rest).
- No training period is needed for the behaviour detector.
- The initiator list and flow labels are opened only after the frozen run has written its
  outputs. Their hash is recorded at download; the content stays unread.

## 4. Hypotheses, metrics and decision rules

| ID | claim | primary metric | success |
|---|---|---|---|
| V1 | the adopted drift state is reliable: periods it does not flag keep the false-alarm promise | pooled benign device FPR over 1 h test segments with `baseline_state` = monitoring | ≤ 2% with the Wilson 95% upper bound ≤ 3% |
| V2 | the shift test earns adoption | C1–C4 of PLAN.md section 2 on the test segments | all four hold. Only then may a later phase adopt it for display. |
| V3 | the deployed detector finds confirmed initiators at its operating point | confirmed-initiator recall (any alert in the initiator's attack windows), FA/h per population | report with Wilson CI; no success threshold (descriptive), compared with the never-alert policy Z |
| V4 | gated recalibration is not worse than a fixed baseline | S5 vs S1: FA/h, initiators detected, absorbed attack windows | S5 loses no initiator, absorbs ≤ 1% of attack windows, and its FA/h is not higher |

**Always reported:**
- window-level recall;
- detection delay;
- assessment-state coverage (`normality_supported_share`);
- the validity status per segment;
- false-negative cost for c ∈ {10, 100};
- CPU and peak memory.

**Failure handling:**
- Every outcome is recorded in the hypothesis ledger, failures included.
- Post-hoc analyses are labelled **[R]** and never change a verdict.
- The dataset is marked consumed after the run.

## 5. Uncertainty

- Block bootstrap over 15 min blocks: ≥ 10 blocks, 2,000 resamples, seed 0.
- With fewer blocks, intervals are descriptive.
- Initiator-level proportions: Wilson intervals; counts only below 5.

## 6. Compute and safety

- **Estimated cost:** windowing and scoring stream in chunks (Phase 8b harness). Peak memory
  < 2 GB for ≤ 5M flows (Phase 8d: 1.36 GB for 4M records); runtime < 30 min.
- **Approvals:** the download (size and licence stated), and any run expected to exceed the
  limits.
- **Detection only:** NetSentinel reads the data; it never sends traffic to, or blocks, any
  host.
