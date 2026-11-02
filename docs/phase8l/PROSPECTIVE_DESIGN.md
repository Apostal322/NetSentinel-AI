# Phase 8l revised prospective evaluation design and model comparison plan

**Status:** a design for a future study. **Nothing here is registered or frozen, and no data is
collected under it.** It repairs the problems Phases 8j and 8k exposed, and states the sample
it needs *before* any data is collected.

## 1. Units and minimum sample (checked before collection)

- **Unit:** an independent network, meaning a distinct capture environment. Networks from one
  generator, institution or range form a **family**; families are the resampling unit.
- **Minimum sample** (POWER_ANALYSIS.md), all to be met before the study is registered:
  - ≥ **20 independent networks** from ≥ 10 families (≥ 30 if fewer families);
  - each with ≥ **1,000 effective independent verified-benign evaluation windows**. That is
    estimated beforehand from the calibration side (hosts × days × session dependence), so no
    evaluation data is touched;
  - expected ≥ 2 adequate and ≥ 2 unsafe networks: the prevalence assumption must be stated,
    with the power simulation rerun at it.
- **Attainability check:** before registration, the power simulation is extended to every
  registered criterion and rerun with the actual N, families and n_eff estimates. Power ≥ 0.8
  for a "good" rule is required, otherwise the study is not run.
  - Today `power_analysis.py` models only the discrimination criteria (1), (2) and (4). Its
    minimum N (20–30) is therefore a **lower bound**.
  - Every criterion must be attainable at the realised determinable N; the gate G3 stays.

## 2. Labels (evaluation only, after decisions are frozen)

- **Three-state adequacy** per network and method:
  - adequate if the exact 95% upper bound of verified-benign FPR (at the effective n) is ≤ 2%;
  - unsafe if the lower bound is > 2%;
  - otherwise indeterminate. Indeterminate networks are excluded from decision counts,
    included in coverage and recall, and their number is reported.
- **Verified benign:** hosts with no attack role, attack label or attack-log entry, *from the
  dataset's documented host roles and attack logs*, registered before data access. Per-flow
  time-window labels (AIT) are not host ground truth.
- **Vetted calibration:** calibration-period attackers come from the documented attack schedule
  or roles, timed before the calibration end. In deployment this is an analyst-vetted quiet
  period; that cost is stated, not assumed away.

## 3. Measurements (all reported; no binary statistic without them)

| measurement | definition |
|---|---|
| correct acceptance / correct rejection | accepted adequate networks / adequate; rejected unsafe / unsafe |
| false acceptance (FAR) / false rejection (FRR) | with exact intervals, overall and per family |
| coverage | accepted networks; accepted share of evaluation windows, attack windows and attack entities; coverage among adequate networks |
| verified-benign FPR on accepted networks | pooled (family, then network) with a two-level bootstrap upper bound |
| false alerts per hour | on accepted networks; and over all networks (abstained = 0) |
| attack recall | window and entity recall on accepted networks, and over all networks (abstained attacks = missed) |
| detection delay | median, from an attacker's first attack window; abstained time counts |
| **operational utility U(c)** | U(c) = entity recall over all networks − c × (false alerts per hour over all networks ÷ always-accept's false alerts per hour), for c ∈ {0.25, 0.5, 1} |

**U(c) is macro-averaged:** each network's entity recall and normalised false-alert rate are
averaged with equal network weight, so high-traffic networks do not dominate.

**Controls:**
- always accept: U = recall₀ − c;
- always abstain: U = 0;
- random selection at the method's acceptance count: exact.

**A method may not be called successful by abstaining.** It must:
- beat **both** always-accept and always-abstain on U(c) for every pre-specified c;
- keep FRR ≤ 0.5;
- beat random selection (exact one-sided p ≤ 0.05).

## 4. Success criteria for the primary method

**Gates** (named G here, to avoid a clash with the dataset criteria E1–E7):
- **G1:** ≥ 4 determinable networks.
- **G2:** ≥ 2 adequate and ≥ 2 unsafe networks, judged at a **common reference threshold (T0)**.
  This stops a method that raises its own threshold from making every network "adequate" and
  turning a failure into "not evaluable". If the method's own labels then empty a class, that
  counts as a failure.
- **G3:** the random-selection test is attainable.

**All six criteria must hold:**
1. Pooled FAR ≤ 0.25. A per-family FAR criterion was dropped: in families of 2–3 networks a
   single false acceptance breaks it at any N, which the review showed by simulation. Family
   dependence is instead handled in (4) and in the sensitivity analysis.
2. FRR ≤ 0.5, with ≥ 2 determinable networks accepted.
3. Pooled accepted FPR ≤ 2%, and its upper bound ≤ 3%.
4. Random-selection p ≤ 0.05, from a **family-level permutation test** (accept decisions permuted
   within the family structure). The exchangeable hypergeometric test is anti-conservative when
   networks are clustered.
5. U(c) above both controls for c ∈ {0.25, 0.5, 1}.
6. Entity recall on accepted networks ≥ 0.5.

**Registered sensitivity analyses:**
- each family collapsed to one unit;
- indeterminate networks treated as unsafe, then as adequate.

## 5. Exact model comparison plan

| id | method | decision-time information | role |
|---|---|---|---|
| C0 | always accept, T0 | – | control |
| CA | always abstain | – | control |
| CR | random selection at the method's acceptance count | – | control |
| M1 | fixed checks 1–3 (Phase 8i), T0 | effective n, effective hosts, top share, grouped exceedance | secondary, tested last (circular on development) |
| **M2** | PAC rank at the dependence-adjusted n_eff, threshold max(T0, PAC) | effective n with AR(1) deflation | **primary, tested first**: the one method not shaped by development outcomes (it came from the Phase 8j simulation) |
| M5 | M2 **and** within-calibration turnover ≤ 0.5 | M2 + share of the late calibration from hosts new in it | secondary, tested second: adds the turnover mechanism (task B) |
| M6 | M5 plus a 24 h expiry (blocks later than 24 h after calibration abstain) | as M5 | secondary, tested third (ageing) |

**The same circularity standard applies to all of them:**
- M1's checks and M5's 0.5 cut-off were both chosen *after* seeing the 4 development networks.
  The cut-off sits between NF-CIC (0.15–0.19) and NF-ToN-IoT (0.79), and rests on that one
  network.
- Neither may be primary. Sensitivity at 0.3 and 0.7 is registered for M5.
- M5 addresses turnover, not dominance. Dominance is left to M2's effective-n and to M1's host
  checks.

**Not carried:**
- host-balanced calibration (negative on development);
- the temporal self-consistency check (did not see turnover);
- learned reliability classifiers (fewer than about 20 independent development networks).

**Multiplicity:** a fixed sequence (M2 → M5 → M6 → M1), each tested at α = 0.05 only if the
previous one succeeded. A failure of the turnover add-on cannot hide M2, which comes first.

## 6. Leakage controls

- Calibration hosts are selected only by calibration-period, documented roles or attack logs.
  Evaluation-period labels never enter features, calibration, thresholds or method choice.
- The analysis script, hashes and parameters are frozen before data access. The Phase 8k runner
  is the template: it refuses to run without a freeze file holding its hash, requires every seed
  file, and handles empty classes.
- Protected data is downloaded only after the freeze and with authorization. Probes are used for
  schema and feasibility only, and are then excluded.

## 7. Data and compute requirements

| need | estimate |
|---|---|
| independent networks | ≥ 20 (≥ 30 if few families), each with days of traffic from many benign hosts, documented attacks and an early benign period |
| available publicly today | **about 1 confirmation-grade network** (DEDALE), possibly 2 (OpTC at ~940 GB) |
| per-network processing | streamed Zeek/flow → windows → scores under the 3.4 GiB cap; ~5–20 min each on this machine |
| total for 20–30 networks | ~10 h CPU; downloads depend on the source (DEDALE's Zeek logs alone are ~11 GB) |
| realistic source of the sample | a consortium of operators, each contributing a monitored period with an authorised red-team exercise, or a future public multi-institution corpus |
