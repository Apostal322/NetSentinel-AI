# Phase 8r pre-registration: trusted calibration, contamination and memory

**Registered:** 2026-11-08, committed before any Experiment A, B or C outcome was computed.

**What had been run before this commit:**
- the Stage 1 identifiability analysis (CALIBRATION_IDENTIFIABILITY.md);
- synthetic unit tests (`tests/unit/test_phase8r.py`);
- two pipeline dry runs. Their outcomes were not inspected: only timing lines were printed, and
  the output files were deleted.
  - Experiment A/B on NF-UNSW and NF-CIC 02-22, with 2 draws;
  - Experiment C feature level on NF-UNSW.

**Code:**
- `scripts/phase8r/trusted_methods.py` (policies, vetting, estimators, contamination);
- `scripts/phase8r/experiment_ab.py`;
- `scripts/phase8r/experiment_c_features.py`.

**Scores:** the frozen M2 construction, scored as Phase 8o F0: 6 fits (base and stress × r6–8),
the mean of K = 5 members. α = 1 %.

**Metrics:**
- recall on V2 documented attackers;
- FPR on the historical benign set;
- false alerts per hour;
- entity R₂₀ (expected count per fit and draw);
- recall per Phase 8q audit category (operational evaluation).

**Aggregation (as in Phase 8q):** draws, then fits, then domains within a network, then a macro
over networks. Draw percentiles (p10/p90) are reported for every network metric.

## 1. Amendment rule

Any change after this commit is recorded as an amendment with:
- its timestamp;
- the original rule and the new rule;
- the reason;
- whether outcomes had been inspected;
- its effect on confirmatory status. An amendment made after outcomes were inspected makes the
  affected result exploratory.

## 2. Evidence sources and budgets (Stage 2)

**Vetting unit:** a host's whole hold-out activity, or, for the interval budget, a host within
one hour. Every vetting outcome is **ORACLE-SIMULATED** from `cal_truth`: a T1 proxy for T3/T4.

**Budgets:**

| budget | hosts vetted | effort recorded |
|---|---|---|
| none | 0 | — (A0) |
| small | 3 | hosts, host-hours reviewed, trusted windows, trusted host-hour blocks, malicious found |
| modest | 10 | same |
| limited verified interval | every host active in one random 1-h block of the hold-out; trust limited to that hour | same (reviewed = hosts in the block) |
| larger bounded | 30 | same |

"Sessions" are not defined in these window data. Host-hour blocks stand in for them.

**Selection policies:** applied at matched budgets, before any label is seen, and using only
label-free host metadata.

| policy | rule |
|---|---|
| `random` | uniform over hold-out hosts |
| `diversity` | hosts sorted by window count and split into k strata; one random host per stratum |
| `temporal_block` | k random hosts among those active in one random 1-h block (their whole hold-out is vetted) |
| `service_diverse` | round robin over six service profiles: (median UDP share > 0.5) × median destination ports in {1}, {2–5}, {> 5} |
| `admin_persistent` | the k hosts active in the most 1-h blocks (an administrator's "known" hosts; deterministic) |

- `naive_T2`: the `admin_persistent` hosts trusted **without** vetting.

**Annotation errors** (modest budget; `random` and `admin_persistent`), as (e_fb, e_fm):
(0.10, 0), (0.25, 0), (0.25, 0.05).
- e_fb is the probability that a malicious host is accepted as benign.
- e_fm is the probability that a benign host is rejected.

**Draws:** 20 per stochastic cell, with seeds from CRC32 of (domain, fit, budget, policy, error,
draw).

## 3. References

| reference | threshold | evaluation memory | role |
|---|---|---|---|
| A0 | conformal T0 on the unlabelled hold-out | unlabelled | no trusted data |
| A1 | P1x T0 (oracle) | P1x (oracle) | full oracle |
| A1T | T0 on the benign hold-out windows (oracle) | unlabelled | ceiling of any threshold-only method |

## 4. Experiment A: trusted-negative calibration (threshold only)

**Methods** (`trusted_methods.py`), all on unlabelled-memory hold-out scores, applied to
unlabelled-memory evaluation scores:
- **A2:** conformal T0 over the trusted windows.
- **A3:** trusted-anchored screening of the unlabelled hold-out.
  - q_ref = A2.
  - An unvetted host is removed when more than 10 α of its windows exceed q_ref.
  - Vetted-malicious hosts (T4) are always removed.
  - T0 is then taken over the trusted windows plus the retained windows.
- **A4:** dependence-aware: the 90th percentile of A2 over 100 host-cluster bootstrap
  resamples.
- **A5:** A3, abstaining (no alerts) when there are fewer than 5 trusted hosts or fewer than
  20 trusted host-hour blocks.
- **Empty trusted set:** A2–A4 fall back to A0, and the fallback is counted. A5 abstains.

**Primary hypothesis H-A1:** A3, modest budget (10 hosts), `random` policy, no annotation error.
"Trusted calibration" is **SUPPORTED** if all four criteria hold:
1. macro recall − A0 macro recall ≥ 0.10;
2. on every network, mean FPR ≤ A1T FPR + 0.02;
3. macro recall − A0 ≥ 0.5 × (A1T − A0), i.e. at least half of the threshold gap is recovered;
4. on every network, the p90-over-draws FPR ≤ A1T FPR + 0.05.

Otherwise it is **NOT SUPPORTED**.

**Secondary (descriptive, no verdict):**
- A2, A4 and A5 at every budget and policy;
- the budget curve;
- the policy comparison at matched budgets;
- annotation errors;
- `naive_T2`;
- effort;
- recall per audit category.

## 5. Experiment B: bounded contamination of the trusted set

**Base cell:** the modest / `random` trusted set of Experiment A (same seeds).

**Contamination:** real calibration-attacker hold-out windows of the same domain are marked
trusted until they form a share c ∈ {1, 2, 5, 10} % of the trusted windows.

**Mechanisms** (`contaminate`):
- **random:** uniform over attacker windows;
- **persistent:** from the attacker host with the most windows;
- **coordinated:** equal shares from the top 3 attacker hosts;
- **burst:** a contiguous time run;
- **gradual:** sampling probability rising linearly with time;
- **service_matched:** only attacker windows whose UDP share and destination-port count lie
  inside the trusted windows' 10–90 % ranges.

Hosts with injected windows count as vetted, and only their injected windows are used. The
estimators are time-agnostic, so burst and gradual differ from random only through which windows
they select. This is stated, not hidden.

**Estimand:** for A2, A3 and A4, the paired difference (contaminated − clean, on the same domain,
fit and draw) in:
- macro and per-network recall;
- per-network FPR;
- the breakdown fraction: the smallest c with a macro recall loss ≥ 0.10.

**Evaluable domains:** those with calibration-attacker hold-out windows. 02-16 and 02-21 are NOT
EVALUABLE.

**H-B1:** contamination robustness is **SUPPORTED** if A3's macro recall loss is ≤ 0.10 at
c = 5 % under every evaluable mechanism. Otherwise it is **NOT SUPPORTED**.

## 6. Experiment C: memory contamination

**Memories:**
- M0 P1x;
- M1 unlabelled forward-only;
- M2a purge of the destinations contacted only by vetted-malicious hosts;
- M2b trusted-only allowlist;
- M3 quarantine: promotion after ≥ 2 distinct sources in ≥ 2 distinct 1-h blocks;
- M4 no novelty.

Full definitions are in `experiment_c_features.py`. M2 uses the Experiment A selections of fit
`base_r6`: modest budget, `random` draws 0–4 and `admin_persistent`.

**Feature level** (run now; no model):
- memory size and growth;
- attack-only destinations accepted;
- legitimate destinations rejected;
- M3 promotion delays;
- evaluation novelty shares;
- build runtime.

**Gate for the scored part:**
- A variant (memory × vetting policy, with draws pooled by their median) is scored only if, on
  02-22 or 03-02, it restores ≥ 50 % of the documented-attack novelty-share gap between U and
  P1x, while raising the benign novelty share by ≤ 5 percentage points over U.
- M4 is scored only if at least one other variant passes. Without that, removing the feature
  only tests the Phase 8n/8o feature ablations again.

**Scored part** (only for variants that pass the gate, and **only after explicit
authorization**, since refits exceed 2 min):
- refit the frozen M2 construction with the same seeds, saving the boosters;
- reproduce the saved F0 scores exactly before any scoring;
- rescore the target hold-out and evaluation windows under each memory;
- **separate feature from threshold effects** by evaluating every memory with:
  - (a) the A1T-style oracle threshold on that memory's benign hold-out;
  - (b) the A3 modest/`random` trusted threshold.
- Registered criterion H-C1: a variant is a **DEVELOPMENT GO** candidate if, under (b), it raises
  mean NF-CIC 02-22/03-02 recall by ≥ 0.25 over M1 without raising FPR by more than 0.01 on any
  network.

If no variant passes the gate:
- memory robustness is reported as NOT SUPPORTED at the feature level;
- the scored part is NOT RUN.

## 7. Experiment D: weakly supervised training

**Run only if** H-A1 is SUPPORTED **and** a memory variant passes H-C1. Weak supervision would then
have trusted inputs to build on.

**Otherwise it is NOT RUN, because:**
- the dependence lies in the calibration inputs (Phase 8q decomposition; Stage 1 § 3);
- realistic budgets yield only a handful of T4 hosts per domain, too few for supervised training.

## 8. Decision gates

| gate | scale | rule |
|---|---|---|
| scientific identifiability | IDENTIFIABLE / CONDITIONALLY / NOT IDENTIFIABLE / NOT EVALUABLE | from Stage 1 (already observed, descriptive) |
| trusted calibration | SUPPORTED / NOT SUPPORTED / NOT EVALUABLE | H-A1 |
| contamination robustness | SUPPORTED / NOT SUPPORTED / NOT EVALUABLE | H-B1 |
| model improvement | DEVELOPMENT GO / NO-GO / NOT EVALUABLE | GO only via H-C1 (or D, if run); NOT EVALUABLE if the scored part is gated off or not authorized |
| independent confirmation | READY / NOT READY | READY only with an eligible unconsumed network (none known) |
| deployment | GO / NO-GO | NO-GO unless every gate above is positive *and* independent confirmation has been done |

## 9. Statistics

- **Decision unit:** the registered means. No p-values enter any rule.
- **Uncertainty:** the p10/p90 across draws, and the spread across the 6 correlated fits (not
  independent replications).
- **Correlation:**
  - entities and domains are clustered;
  - NF-CIC averages 6 days, and its draws are matched by index only.
- **Multiplicity:** one primary cell per hypothesis. Everything else is descriptive.

## 10. Amendments

| id | timestamp | original rule | new rule | reason | outcomes inspected? | effect on confirmatory status |
|---|---|---|---|---|---|---|
| R-1 | 2026-11-08, after the results commit `a8a6980` | M3 promotion "≥ 2 sources in ≥ 2 distinct 1-h blocks" (text) | unchanged; the **code** is corrected to match it. `max_horizontal` ignored nulls and implemented OR | implementation bug found by the independent review | yes | the corrected M3 rerun implements the registered rule; the gate verdict is unchanged (M3 fails under both); M3 numbers replace the first run's |
| R-2 | same | A2/A3 "conformal T0 over the trusted windows" | unchanged; **disclosed**: below 99 windows the capped rank is the sample maximum (the Phase 8j/8q `t0` convention) | review finding | yes | none; reported as a limitation (TRUSTED_CALIBRATION) |
| R-3 | same | B fractions c of the trusted windows | unchanged; **disclosed**: rounding makes NF-ToN's "5 %" about 9 %, and NF-ToN drops out at 1 %; a sensitivity without NF-ToN is reported, but it does not replace the verdict | review finding | yes | H-B1 stays NOT SUPPORTED as registered; the sensitivity is exploratory |
