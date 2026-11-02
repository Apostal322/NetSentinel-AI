# Phase 8l DEDALE single-network longitudinal test: pre-registration (draft)

**Status: DRAFT, not frozen.**
- It becomes binding only when `docs/phase8l/DEDALE_FREEZE.md` records its SHA-256 with the
  analysis code and the source-model hashes (section 9).
- Allowed changes before the freeze:
  - implementation detail;
  - corrections found by the independent audit;
  - quantities this text defines as functions of calibration data.
- Every change is listed in section 10.

**What was seen before writing it.**
- **No DEDALE flow record, label value or score.**
- **Archive metadata of all 28 days, evaluation days included:** member names, sizes and CRC32s
  from the zip central directories.
  - It shows, for example, per-day volumes and that `pe.log` exists only on D17
    (2025-01-08, the documented lateral-movement day).
  - It carries no score and no label, and it is disclosed here because it covers evaluation
    days.
- The public attack timeline and the labelling code.

**Question:** on one unseen emulated enterprise, does a threshold calibrated on two benign
weeks keep its verified-benign false-positive rate within budget over the next two weeks? And
what does it detect?

**This is N = 1. It does not test network-level accept/reject decisions, and it cannot revise
the Phase 8l NO-GO.**

## 1. Data, tap, temporal split and windows

- **Dataset and tap:** DEDALE V2 (DOI 10.57745/Y5JLDG), tap **green_internal** only. The members
  are listed in `DEDALE_MANIFEST.md`.
- **Split:** the official one, with its boundary placed at **2025-01-06 00:00 UTC**. The attack
  timeline and labels are in UTC, and the first attack event is 10:00:13 UTC that day.
- **Period by flow end time, not by folder**, as in the P1x builder:
  - **calibration** = flows from the D1–D14 members with `ts + duration` < the boundary;
  - **evaluation** = flows from the D15–D28 members with `ts + duration` ≥ the boundary and
    < 2025-01-20 00:00 UTC.
  - D1–D14 flows ending after the boundary, and D15–D28 flows ending before it, are dropped and
    counted. This covers long connections and day folders that may follow local time (CET).
  - The UTC span of each folder is recorded at Stage A.
- **Windows:** the Phase 8j P1x builder (`build_p1x.P1xBuilder`), unchanged:
  - 30 s windows, per source address (`ip_src`), the 12 window features, timed by window end;
  - the rows are streamed in time order through the same `build_windows.chunks` chunking as in
    Phase 8j;
  - the calibration period's attackers are excluded from the calibration windows and from the
    memory (there are none by construction; checked by N3).
- **Destination memory (stated because it is asymmetric by design):**
  - a calibration window's `new_dst_frac` is computed against the destinations of the
    *preceding* calibration chunks;
  - every evaluation window is computed against the *frozen* memory of all calibration
    destinations, which is never updated during evaluation.
  - Destinations first contacted in weeks 3–4 therefore stay "new". This is part of the
    deployed protocol being tested, not a defect to repair. Its share of false alerts is
    reported (section 6).
- **Hold-out:** `split_cut`, i.e. the last 30 % of the calibration window range. By the calendar
  that is about 2025-01-01 19:00 → 2025-01-06 00:00 UTC, which in practice is the working days
  2 and 3 January plus a near-silent weekend. The realised cut is recorded at Stage A.

## 2. Host eligibility (documentation and calibration data only)

- **Host identity:**
  - **If** the `dhcp.log` files show leases for the internal clients, a host is a **MAC
    address**. Flows are attributed to it through its leases: lease intervals from `dhcp.log`,
    with the address held until the next lease of that address.
  - **Otherwise** (static addresses), a host is a source address.
  - The `dhcp.log` files of D15–D28 are used for attribution only. They are not outcomes, and
    they arrive with Stage B.
- **Excluded for all 28 days, from every benign set:**
  - **Clients 1 and 2.** These are the hosts that hold `172.16.1.2` and `172.16.1.3` at the
    documented compromise times (2025-01-08 15:10 and 2025-01-06 10:00 UTC), and any host that
    held either address at any time.
  - **Clients 3 and 4.** They were not compromised according to the timeline, but the publisher
    collected forensic artefacts on clients 1–4 as "machines involved in the attack scenario".
    They are identified by DHCP host name; if names are missing, `172.16.1.4` and `.5` by the
    inferred numbering. Their inclusion is a sensitivity analysis.
  - The attacker and C2 addresses `172.19.0.2`, `172.19.1.1` and `172.19.2.1`.
  - The mail server `172.17.0.2`.
  - The DC `172.16.0.2`.
  - The router `172.16.1.1`.
- **Primary population:** the remaining internal-client hosts in `172.16.1.0/24`, at most 26.
  Each must have:
  - ≥ 100 calibration windows;
  - ≥ 20 hold-out windows;
  - under address identity, exactly one MAC per address in D1–D14 when `dhcp.log` shows MACs.
- **Secondary population** (reported, no criterion): all other source addresses seen at the
  tap, under the same exclusions and activity rules.
- **Label-file sanity check** (after unblinding):
  - label 1 or 2 flows on addresses outside the published script's address list would mean a
    different labelling version;
  - if found, they are reported, and those addresses are dropped in a sensitivity analysis.

## 3. Scores, thresholds and seeds

- **Score function:** the registered Phase 8i B-raw LightGBM, fitted once by the existing code
  (`fit_source`, Phase 8i settings) on all four NF-v3 development networks, seeds {0, 1, 2}.
  - It is fitted and hashed **before** the freeze, under its own authorization.
  - It is never fitted, tuned or selected on DEDALE.
  - The Zeek → canonical mapping is the Phase 8k rule set, with a DEDALE adapter for column
    names and the 0/1/2 label only.
- **Primary threshold T0:**
  - the plain conformal order statistic at rank k = ⌈(n + 1)(1 − α)⌉, α = 1 %;
  - n = hold-out windows of eligible primary hosts;
  - one per seed;
  - alert if a score is strictly above.
- **Secondary threshold:** M2, max(T0, PAC rank at `neff_m3`), reported with no criterion.
- **Seeds:**
  - every window gets the seed-mean of the three alert indicators;
  - all metrics are computed on that mean;
  - per-seed values are reported.

## 4. False-positive rate

- **Verified-benign evaluation window:** an evaluation window of a primary-population host with
  no label 1 or 2 flow. Windows with label 2 flows only are excluded from FPR and recall, and
  counted.
- **FPR** = Σ (seed-mean alert) ÷ verified-benign evaluation windows. It is pooled and
  window-weighted: the operational rate. The host-macro FPR is secondary.
- **Uncertainty:** two one-sided 95 % bounds.
  1. **Host-cluster bootstrap:** eligible hosts resampled with replacement, B = 10,000, RNG seed
     81202, percentile bounds, computed in chunks.
  2. **Clopper-Pearson at the effective n:** `neff_m3` of the evaluation alert indicators (AR(1)
     design effect within hosts, then the Kish host correction), with x = FPR × n_eff.
  - The criterion uses the **less favourable**: the larger upper bound and the smaller lower
    bound.
  - Clustered alerts widen these bounds, but they cannot make the analysis not evaluable (N9).

## 5. Hypotheses and outcomes

- **H1 (primary): the threshold's budget holds over the evaluation fortnight.**
  - **HOLDS:** point FPR ≤ 2 % (2α) **and** upper bound ≤ 3 %;
  - **FAILS:** lower bound > 2 %, which is valid at any n;
  - **INCONCLUSIVE:** otherwise.
  - The ledger and reports state HOLDS as "point ≤ 2 %, upper bound ≤ 3 %", never as
    "FPR ≤ 2 %".
- **H2 (secondary): each period separately, with the same three-state rule.** A period with
  fewer than 200 verified-benign windows is indeterminate.
  - **Attack period:** 2025-01-06 00:00 – 2025-01-13 23:59 UTC. This covers the infection
    through the last beacons, which the timeline places at 11:40 on 13 January.
  - **Post-attack period:** 2025-01-14 00:00 – 2025-01-19 23:59 UTC, with normal activity only.
- **H3 (descriptive): drift.**
  - Daily FPR for working days with ≥ 30 verified-benign windows.
  - A daily overrun test: an exact binomial test of FPR ≤ 2α at the day's windows, deflated by
    the hold-out design effect, with Holm correction across days.
  - The slope of a host-clustered logistic regression of the alert indicator on day index.
  - No criterion.
- **Registered sensitivity analyses:**
  - a hold-out made of the last 30 % of *active* calibration hours, i.e. weekday working hours;
  - clients 3 and 4 included;
  - the label-file sanity check's addresses dropped;
  - the secondary population.
- **Interpretation limits.** HOLDS supports temporal validity on one emulated enterprise from one
  generator, calibrated across a period without real holidays, for one fixed out-of-domain
  scorer. It is not evidence of cross-network reliability.

## 6. Detection metrics (descriptive; no success criterion)

All at T0, seed-mean.
- **Attack window:** a window of any source address holding ≥ 1 label 1 flow.
- **Window recall:** overall and per `attack_step`, with Wilson intervals. The intervals are
  marked as ignoring dependence.
- **Entity recall:**
  - the entities are clients 2 and 1;
  - an entity is detected if ≥ 1 of its label 1 windows alerts;
  - reported as k of 2.
- **Detection delay per entity:**
  1. from its first label 1 flow to its first alerted label 1 window;
  2. to its first alert on any window after compromise.
- **Alert burden:**
  - false alerts per verified-benign host-hour, and per day;
  - the share of false alerts on windows with `new_dst_frac` > 0 (destination-memory effect,
    section 1);
  - alerts on label-0 windows of excluded hosts, reported separately as unknown status.
- **Limit:** one campaign and two entities. No "useful detection" claim is made from these
  numbers.

## 7. Not-evaluable and stop conditions

**Stage A gate** (calibration files only, before the freeze; counts only, no scores):

| id | condition | consequence |
|---|---|---|
| N1 | a member fails CRC32, size or name check | stop; one re-download, then NOT EVALUABLE |
| N2 | required columns missing, or > 1 % of a folder's rows unparseable or ending > 2 h outside the folder's UTC day | NOT EVALUABLE (no repair beyond the labelling script's documented `-` → 0) |
| N3 | any calibration row with label ≠ 0 | NOT EVALUABLE (the documented benign period is not benign; no relabelling) |
| N4 | fewer than 20 eligible primary hosts | NOT EVALUABLE |
| N5 | Kish effective hosts over hold-out windows < 10, or top host share > 25 % | NOT EVALUABLE |
| N6 | eligible hold-out windows < 590 (count form; amendment 2). The Kish effective number of 30 min sessions (the ρ = 1 bound) is reported, with no criterion | NOT EVALUABLE |

**After the freeze, before Stage B is downloaded:**

| id | condition | consequence |
|---|---|---|
| N7 | a hash in DEDALE_FREEZE.md mismatches, or a seed file is missing | stop |
| N8 | `neff_m3` of the hold-out *scores* < 590 | NOT EVALUABLE; **Stage B is not downloaded** |

**Final run:**

| id | condition | consequence |
|---|---|---|
| N9 | fewer than 15 eligible hosts with ≥ 20 evaluation windows, or fewer than 2,000 verified-benign evaluation windows (counts only) | H1 can only be FAILS; otherwise NOT EVALUABLE |
| N10 | a Stage B member fails integrity | stop; one re-download, then NOT EVALUABLE |

**Why 590.** N6 and N8 gate the calibration side, not the evaluation bound.
- **The Phase 8j claim rule.** An observed 1 % over n independent windows has a one-sided 95 %
  Clopper-Pearson upper bound ≤ 2 % first at n = 590, and at every n ≥ 719
  (`threshold_stats.claim_table`). So with fewer than about 590 effective hold-out windows, the
  calibration itself cannot certify the 2α budget.
- **The plain conformal guarantee is weaker.** The 95th percentile of T0's conditional FPR is
  ≤ 2 % for n ≥ 313. The gate uses the stricter 590.
- **The evaluation criterion** (upper bound ≤ 3 %) is a separate, looser test of a separate
  sample.
- **The two checks.** N6 is a necessary-condition count screen: no dependence adjustment can lift a raw n below 590. N8 applies the score-based estimator, and
  runs before any evaluation data exists.

## 8. Leakage and independence controls

- **No evaluation day (D15–D28) member is downloaded before the freeze and N8.**
  `dedale_fetch.py` refuses Stage B unless `DEDALE_FREEZE.md` is tracked in git and holds this
  file's SHA-256.
- **Labels are public in principle** (feasibility section 5), so the controls protect our
  scores:
  - no DEDALE window is scored before the freeze;
  - Stage A yields counts only.
- **No parameter is chosen from DEDALE data except by a rule written here.**
- **One tap.** Other taps, weeks and days are never treated as independent units.
- **Label columns** are stored apart from features and read only by the final analysis.

## 9. Freeze steps

1. **Done:** feasibility, manifest and this draft. Tooling is tested on synthetic zips.
2. **Needs authorization:** the Stage A download (384.0 MB) and the Stage A gate N1–N6. The
   outcome is recorded in `DEDALE_STAGE_A.md`.
3. Write the DEDALE adapter and `dedale_analysis.py`. Unit-test them on synthetic data and the
   Stage A schema, with no scores.
4. **Done** (authorized 2026-11-02; script `b94495d`). The three registered source models were fitted:
   - 14 source domains of the four NF-v3 networks, 585,026 training rows each;
   - LightGBM 4.7.0;
   - 111 s, with a peak of 1,427 MiB under the cap;
   - each reloaded file reproduces `predict_proba` exactly.

   SHA-256:
   - seed 0: `770894fe2d13ef14c7ec4caf48d266e8f96c8473dba1e82816949ed08de25f39`;
   - seed 1: `fd30d57df14cd15a9cb583543d57fefff9126bcc923fe8ec422ade6cac058e0d`;
   - seed 2: `0812f9a44cec0804bcbebbc3f828bfe8d2a2cacf34e31e678c3afc5231760e3a`.

   The model files live under the git-ignored `data/derived/phase8l/dedale/models/`. The report
   is `reports/phase8l/dedale_source_models.json`. No DEDALE data was read.
5. An independent audit of the code and this document, with findings fixed.
6. Write and commit `DEDALE_FREEZE.md` holding:
   - the commit;
   - the SHA-256 of this file, the analysis code and the adapter;
   - the model hashes;
   - the manifest;
   - the Stage A SHA-256s;
   - the Stage A gate outcome.
7. Score the calibration windows and apply N8. **This needs no new data.**
8. **Needs authorization:** the Stage B download (396.3 MB) and **one** run of
   `dedale_analysis.py`. Results are reported whatever they are.

## 10. Changes before freeze

1. **Independent review of the first draft (same day, before any data).**
   - **Dependence-based evaluability removed (old N9).** Evaluability now rests on counts. A
     FAILS stays possible at any n. Before, clustered alerts, the signature of a real failure,
     could turn a failure into NOT EVALUABLE.
   - **Periods.** "Week 4 after the attack" was wrong: beacons continue to 13 January 11:40.
     The periods now follow the timeline.
   - **Period assignment** by flow end time, with a tolerance, not by folder.
   - **Hosts keyed by MAC** through DHCP leases when they exist. This covers the case where an
     excluded machine changes address.
   - **Clients 3–4 excluded** in the primary analysis (forensic artefacts).
   - **The 590 gate explained,** and the score-based check (N8) moved before Stage B.
   - **The destination-memory asymmetry stated,** and its share of false alerts reported.
   - The disclosure of the evaluation-day metadata seen.
   - The HOLDS wording.
2. **Before the Stage A gate was run** (2026-11-02). At this point the 28 Stage A members had been
   downloaded and verified by CRC32, and no row had been parsed.
   - **N6 takes its count form.** The session-adjusted effective n of Phase 8i weighs sessions
     by the intraclass correlation of *scores*, and Stage A computes no scores.
     - N6 therefore requires ≥ 590 eligible hold-out windows, a necessary condition.
     - The dependence-adjusted check is N8, on hold-out scores, after the freeze and before
       Stage B.
     - The Kish effective number of sessions (ρ = 1, the most conservative bound) is reported,
       with no criterion.
   - **Adapter detail.** Flows are written in the Phase 6/8i NetFlow column set, so that
     `build_windows.chunks` and `P1xBuilder` run unchanged:
     - Zeek `history` 'R' / 'r' become bit 4 (RST) of the client / server TCP flags;
     - label 0 / 1 / 2 become "benign" / "attack" / "attack_related";
     - labels 1 and 2 both count as attack in the builder's calibration exclusion.
   - **Clients 3–4 identification rule:** a DHCP host name ending in "client" plus its number.
     It was written before the names were read.
