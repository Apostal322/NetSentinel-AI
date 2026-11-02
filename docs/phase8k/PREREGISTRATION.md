# Phase 8k pre-registration: independent validation of calibration-reliability decisions

**Written:** 2026-11-02.
- **After** the development experiments ([DEVELOPMENT_EXPERIMENTS.md](DEVELOPMENT_EXPERIMENTS.md))
  and the independent audit ([AUDIT.md](AUDIT.md)), whose findings are folded in here.
- **Before** any fresh file was downloaded.

**Analysis code:** `scripts/phase8k/confirm_analysis.py`. Its development dry run is in
`reports/phase8k/smoke/verdicts.json`: a stand-in, not a result.

**Frozen hashes:** [FREEZE_CANDIDATE.md](FREEZE_CANDIDATE.md). The script runs `--confirm` only
when `docs/phase8k/FREEZE.md` exists **and** contains the script's SHA-256. That file is written
after the probes, the source models and the confirmation downloads (section 8).

Amendments are appended (section 10), never edited in place. Phase 8j's registered NO-GO is
unaffected.

## 1. Hypotheses

| id | claim | type |
|---|---|---|
| **K1** | M1 (fixed checks 1–3) accepts adequate units and rejects unsafe ones better than chance, keeps the budget on what it accepts, keeps useful detection there, and does so in each family. | **primary** |
| K2 | On M1-accepted units, detection stays useful: recall, entity recall, delay, alert burden. | descriptive |
| K3 | K1 for M2 (PAC at the dependence-adjusted effective n). | secondary; read only if K1 succeeds |
| K4 | Calibration recency: on M1-accepted units, FPR in the first 24 h after the hold-out vs later. | descriptive |

**Why M1 is primary, and how it differs from earlier phases:**
- M1 is checks 1–3 of the Phase 8i final audit (section 10.4), the only rule proposed before
  any Phase 8j or 8k comparison. It separated all 4 development networks, but that is circular,
  which is exactly why it needs fresh data.
- **M1 is not identical to Phase 8j M1.** Phase 8j M1 also applied check 4, abstaining on
  blocks that start more than 24 h after the hold-out. Check 4 is a time-coverage policy (how
  long a calibration is trusted), not a calibration-adequacy decision. Phase 8k keeps the two
  questions apart:
  - the network decision is checks 1–3;
  - recency is measured descriptively as K4.

  The Phase 8i/8j N4 failure was a 309 h staleness problem, so K4 is reported however K1
  turns out.
- M2 has simulation support, but falsely accepted NF-ToN-IoT on development data. M3, M4 and
  learned classifiers are not carried forward.

## 2. Units and data

- **Unit:** an F1 network (7, excluding the probe `russellmitchell`), or an F2 week (6,
  excluding the probe week 2024-03-03 – 03-10).
- **Family:** F1 or F2. F1's networks share a generator, and F2's weeks share hosts and a
  range, so **the families are the independent environments**.
- **If the F2 probe fails,** F2 is dropped. OpTC would need a registered amendment before any of
  it is opened.
- **Per unit:**
  - calibration = flows ending before the unit's time midpoint; evaluation = the rest;
  - P1x windows (Phase 8j): 30 s, per source address, the 12 window features;
  - calibration-period attackers are removed from the calibration windows and from the
    destination memory. They come only from label rows or attack-log entries timed before the
    midpoint (vetted calibration; cost in section 7).
- **Scores:** B-raw LightGBM (Phase 8i settings), trained on all 4 NF-v3 development networks,
  seeds {0, 1, 2}, before the freeze.
  - **Exactly three files per unit**, `<unit>__seed<k>.npz`, in the Phase 8j `dev_scores.py`
    schema. A missing file stops the analysis before any evaluation field is read.

## 3. Decisions (decision-time information only)

Each decision uses the unit's full P1x hold-out: the last 30% of calibration slots. It is
computed from calibration fields before the unit's evaluation fields are read.

| rule | accept when | threshold |
|---|---|---|
| M0 (control: always accept) | always | T0 = order statistic k = ⌈(n + 1)(1 − α)⌉, α = 1%; alert if strictly above |
| **M1** | session-adjusted effective n ≥ 199, **and** effective hosts ≥ 10 with top host ≤ 25%, **and** host-grouped exceedance ≤ 2α (`dev_compare.m1_network_pass`) | T0 |
| M2 | ≥ 10 hosts **and** a PAC exceedance count l ≥ 1 at the dependence-adjusted n_eff (`threshold_stats.neff_m3`, `pac_threshold`) | max(T0, PAC). A seed with no PAC rank uses the hold-out maximum, i.e. PAC count 0 |
| always abstain (control) | never | – |
| random selection (control) | exact hypergeometric at the rule's number of accepted determinable units | – |

A unit is accepted by a rule when **at least 2 of its 3 seeds** accept.

## 4. Outcomes (evaluation only, computed after every decision)

- **Verified benign:** windows of hosts with no attack label and no attack-log entry anywhere in
  the unit.
- **Attack window:** a window holding a malicious flow.
- **Attack entity:** a source with ≥ 5 attack windows, taken from the labels.
- **Adequacy of a unit for a rule:** the seed-mean realised verified-benign FPR at the
  **rule's own threshold** is ≤ 2α. For M0 and M1 that is T0; for M2 it is M2's threshold.
  - A unit with fewer than 200 verified-benign evaluation windows is **indeterminate**: excluded
    from decision counts, included in coverage and recall.
- **Uncertainty of adequacy:** a 95% host-bootstrap interval for each unit's FPR. A unit whose
  interval contains 2% is **borderline**; see the sensitivity analyses in section 6.

## 5. Metrics (all reported, every rule, every unit)

All of the following are produced by `rule_report`:
- **Decision counts:** true and false acceptances and rejections; false-acceptance rate (FAR)
  and false-rejection rate (FRR), each with Clopper-Pearson 95% intervals; and the same counts
  per family.
- **Coverage:**
  - units accepted;
  - acceptance among adequate units and among unsafe units;
  - accepted share of evaluation windows, attack windows and attack entities;
  - share of the attack entities on adequate units that are covered.
- **Accepted units:**
  - pooled verified-benign FPR (mean over units within a family, then over families; units
    without verified-benign windows are left out);
  - its two-level bootstrap 95% upper bound. Units are resampled within a family, with a fresh
    host resample per drawn slot, 2,000 draws. Families are **not** resampled, and a family with
    a single accepted unit contributes host variance only;
  - window recall (window-weighted), entity recall, median detection delay, false alerts per
    hour (plain mean over accepted units);
  - K4: pooled FPR in the first 24 h after the hold-out and afterwards.
- **All units:**
  - window and entity recall with abstained units counted as missed;
  - alerts per hour.
- **Random selection:**
  - the exact hypergeometric probability that a random set of the same number of determinable
    units holds no more unsafe units;
  - the best p-value any rule could reach, 1/C(N, K).

## 6. Criteria (the code's `gates` and `verdict`)

**Evaluability, per rule:**
- **E1:** ≥ 4 determinable units. Otherwise **NOT EVALUABLE**.
- **E2:** ≥ 2 adequate **and** ≥ 2 unsafe determinable units. Otherwise discrimination is
  **NOT EVALUABLE**, and conditional detection is reported descriptively.
- **E3:** even a perfect rule could reach (d), i.e. 1/C(N, K) ≤ 0.05 (N determinable units,
  K unsafe). Otherwise discrimination is **NOT EVALUABLE**: the test would have no power.
- **If only one family has determinable units,** the verdict carries the label "single
  environment family". It can then make no claim beyond that family.

**K1 succeeds only if all six hold** (the same six define K3 for M2):
- **(a) False acceptance:** FAR ≤ 0.25. With 2–3 unsafe units, none may be accepted.
- **(b) False rejection:** FRR ≤ 0.5, **and** at least 2 *determinable* units accepted.
- **(c) Budget on accepted units:** pooled FPR ≤ 2%, **and** its 95% upper bound ≤ 3%.
- **(d) Better than chance:** random-selection p ≤ 0.05.
  - This is usually stricter than (b). With no false acceptance, p = C(N − K, a) / C(N, a) for
    a accepted adequate units. For example:
    - N = 13, K = 2 needs a ≥ 10 of 11 (FRR ≤ 0.09);
    - N = 13, K = 4 needs a ≥ 6 of 9;
    - N = 9, K = 2 needs all 7.
- **(e) Useful detection:** entity recall on accepted units ≥ 0.5, **and** ≥ 50% of the attack
  entities on adequate units covered.
- **(f) Each family:** within every family, FAR ≤ 0.25 (if it has unsafe units), **and** the
  family's pooled FPR on accepted units ≤ 2%.

**Failure:** any criterion fails, given E1–E3. K3 is labelled "not read" unless K1 succeeds; its
numbers are still reported.

**Registered sensitivity analyses** (they change no verdict, and are reported next to it):
1. The verdict without borderline units.
2. The verdict with each multi-unit family collapsed to one unit, adequate or accepted by
   majority. This does not assume that a family's units are exchangeable.
   - If K1 succeeds only when weeks or networks are counted as separate units, the success is
     reported as **"dependent on unit exchangeability"**.

**Claim limits:**
- About 13 units in 2 emulated families. A success shows the rule worked on these networks, not
  a population rate.
- "1% FPR" is never claimed. Only realised rates with bounds are reported.

## 7. Known costs and limitations

- **P1x needs the calibration-period attacker list.** In deployment that is a vetted quiet
  period: an analyst reviews alerts and incidents of the calibration days. Here it comes from
  the datasets' own labels before the midpoint, which is an idealised, error-free vetting.
  Label errors there pass into calibration.
- **Telemetry shift:** nProbe in development; Tstat (F1) and Zeek (F2) in confirmation. Ranking
  (ROC-AUC) is reported separately.
- **Prior expectation** (stated so it cannot be rationalised afterwards):
  - F1 networks have 10–24 simulated users (paper; unverified) and a server-side vantage point;
    F2 host counts are unknown.
  - M1 and M2 need ≥ 10 effective hosts, so they may reject most or all units.
  - **The most likely registered outcomes are "discrimination NOT EVALUABLE" (E2/E3) or a K1
    failure on (b)/(d).** Both are informative negatives, not reasons to change the protocol.

## 8. Order of work before the protected run

1. **Done:** hypotheses, methods, parameters, units, criteria, analysis script (this document;
   `confirm_analysis.py`).
2. **Done:** a development dry run (`--stand-in`; `reports/phase8k/smoke/`). 142 s, 861 MiB
   under the cap.
3. **Done:** an independent audit, with its findings fixed before the freeze (AUDIT.md).
4. **Done:** the SHA-256 of the frozen files recorded (FREEZE_CANDIDATE.md).
5. **Needs authorization:** download the probes (A1 20.8 MB, A2 3.7 MB).
   - Write the Tstat and Zeek → canonical mappings and unit-test them on the probe units only.
   - **Feasibility gate F0**, on each probe's calibration side only: benign source hosts,
     effective hosts, field completeness.
   - If a probe has < 10 calibration hosts, its family cannot test acceptance. That is recorded,
     and the family is not downloaded.
   - No score, threshold or detection metric is computed on a probe.
6. **Needs authorization:** train the 3 confirmation source models (~5 min) and record their
   SHA-256.
7. **Needs authorization:** download the confirmation files (A3 252.9 MB, A4 136.5 MB). Verify
   them against the publisher sizes and record their SHA-256.
8. Write `docs/phase8k/FREEZE.md` with:
   - the commit;
   - every hash, including `confirm_analysis.py`'s;
   - the mapping code;
   - the F0 outcomes;
   - the unit → family file.

   Then run once:
   `confirm_analysis.py --confirm --scores ... --families ...`.
9. Record the verdicts, consume F1/F2, and update the hypothesis ledger.

## 9. Multiple comparisons and chronology

- **One primary test (K1).** K3 is read only if K1 succeeds. K2 and K4 are descriptive.
- **What was seen before the rules were fixed:** M0–M4 and the construction ablations on
  development data, and the development dry run.
  - The dry run shows K1 "success" for M1. That is circular, and its own sensitivity analysis
    shows it depends on counting NF-CIC's 6 days as separate units: collapsed, discrimination is
    NOT EVALUABLE (E2).
- **What changed after the audit:** E3, (f), the K3 adequacy definition, the seed and
  missing-file rules, the borderline and family sensitivity analyses, and K4. All of these
  followed from the protocol's own logic, and none from a result.
- **Nothing in sections 3–6 was or will be tuned on F1/F2.**

## 10. Amendments

(none)
