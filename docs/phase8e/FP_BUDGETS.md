# False-positive budgets per population (Phase 8e, Mission 4)

> **Status: rule declared before any budget result was computed** (this section was
> committed first; results are appended below it in a later commit).
> Development data only. No consumed capture (IoT-23 1-1, 9-1, 49-1, 60-1; ToN_IoT) is used
> for any choice or reported here.

## Question

Phases 8c and 8d found that one shared device threshold spends the false-alarm budget on
transient external sources, which leaves local devices nearly undetectable. Can explicit
per-population budgets keep the alert burden bounded **without** buying it by suppressing
almost every detection?

## Data

- Development captures from `scripts/phase8b/dev_compare.dev_captures()`:
  - 9 IoT-23 / honeypot captures;
  - 13 CTU-Normal captures;
  - the NF-UNSW-NB15-v3 development part.
- Splits as in Phase 8b: calibration = flows ending before the time midpoint; evaluation = the
  rest.
- Calibration variant `clean` (benign-labelled flows only), as in Phases 8c and 8d.
- Device windows: the cached Phase 8b windows.
- Global and service windows: rebuilt with the same harness and protocol
  (`scripts/phase8e/population_windows.py`, cached in `data/derived/phase8e/<level>/`).

## Populations

| population | definition |
|---|---|
| local | device windows whose source is private or link-local |
| external_transient | device windows of an external source **without** an own profile (fewer than 30 calibration windows: scored with the pooled fallback) |
| external_profiled | device windows of an external source with an own profile |
| global | the global window (one per 30 s) |
| service | service-category windows |

## Policies

All policies use the deployed scoring:
- robust median/MAD profiles, top-2 |z|;
- cross-fit held-out calibration scores for thresholds;
- no LightGBM and no training.

| policy | thresholds |
|---|---|
| Z | never alert (trivial reference: meets every budget, detects nothing) |
| A | deployed: one 1% conformal threshold per level (all device windows share one) |
| P | one 1% conformal threshold per population (Mondrian over the three device populations) |
| H | FA/h budget per population: `t = max(thr(1%), thr(alpha))`, with `alpha = B / (calibration windows per hour of that population)` |
| HX | H, but external_transient windows abstain (no decision; counted in coverage) |

**Budgets B (false alerts per hour of evaluation time):**
- local 1.0;
- external_transient 0.5;
- external_profiled 0.5;
- global 0.5;
- service 1.0.

## Metrics (per capture, population and policy)

- benign and attack windows;
- FPR and false alerts per hour (FA/h);
- attack-window recall;
- attackers detected, for the device populations. An attacker is a source with attack-labelled
  evaluation flows. Phase 8e M1 caveat: on IoT-23, labels are flow-level, so this means "a
  source with attack-labelled flows", not a confirmed initiator;
- detection delay: first alerted attack window end − first attack window end, per attacker or
  per level;
- coverage: share of evaluation windows that receive a decision.

## Acceptance and selection rule

1. **Budget.** For every population, over captures with at least 1 h of evaluation time and at
   least 30 benign windows in that population:
   - the median FA/h is ≤ B;
   - the maximum FA/h is ≤ 3 × B.
2. **Non-degeneracy.** This guards against meeting the target by suppressing detections.
   - The median device-level coverage across captures is ≥ 0.8.
   - Pooled attacker recall over the device populations is ≥ 0.5 × that of A.
   - Pooled device attack-window recall is ≥ 0.5 × that of A.
   - Z must fail this rule; it is the check that the rule works.
3. **Selection.** Among the policies that pass rules 1 and 2, pick the highest pooled attacker
   recall; break ties by the lower sum of median FA/h.
4. **Outcome.**
   - The selected policy is at most a *development candidate*.
   - No default changes in Phase 8e, whatever the outcome.
   - A confirmatory claim needs fresh, unconsumed data under the pre-registration template
     (EVALUATION_METHODOLOGY.md).
   - If no policy passes, that is the result.

Thresholds with too few held-out windows for the target (`conformal_threshold` reliable =
False) are kept, flagged and counted. They are not dropped.

---

## Results (appended after the rule commit 8b70c94)

- Scripts: `scripts/phase8e/population_windows.py` (84 s, peak 1.1 GB) and
  `scripts/phase8e/fp_budgets.py` (8 s).
- Result: `reports/phase8e/fp_budgets.json`. All numbers are **[D]** development data.
- 22 of 23 development captures were analysed. CTU-Normal-28 was skipped: fewer than 60
  calibration windows.

### Rule outcome: **no policy passes. Nothing is selected; defaults are unchanged.**

| policy | budget met (rule 1) | non-degenerate (rule 2) | attackers detected (device) | pooled device window recall |
|---|---|---|---|---|
| Z never alert | yes | **no** (the guard works) | 0/10 | 0.00 |
| A deployed | no | yes | 9/10 (Wilson 95% [0.60, 0.98]) | 0.269 |
| P per-population 1% | no | yes | 5/10 ([0.24, 0.76]) | 0.266 |
| H FA/h budgets | no | yes | 5/10 | 0.266 |
| HX H + abstain on external_transient | no | yes (median coverage 1.0) | 5/10 | 0.266 |

**False alerts per hour.** Median / max over budget-eligible captures (≥ 1 h of evaluation
and ≥ 30 benign windows):

| population (budget) | eligible captures | A | P | H | HX |
|---|---|---|---|---|---|
| local (1.0) | 15 | 0.00 / **33.2** | 0.00 / **19.0** | 0.00 / **19.0** | 0.00 / **19.0** |
| external_transient (0.5) | 2 | **5.63** / **11.3** | 0.06 / 0.11 | 0.06 / 0.11 | 0 / 0 (abstained) |
| external_profiled (0.5) | 1 | **1.69** | **6.53** | **6.53** | **6.53** |
| global (0.5) | 14 | 0.00 / **4.55** | 0.00 / **4.55** | 0.00 / **4.55** | 0.00 / **4.55** |
| service (1.0) | 17 | 0.09 / **13.3** | 0.09 / **13.3** | 0.09 / **13.3** | 0.09 / **13.3** |

### What the numbers show

1. **The overruns come from calibration → evaluation shift, not from the threshold
   allocation.**
   - On NF-UNSW-NB15 (development part), the realised local FPR at a 1% target was **39%**
     under A and 22% under H.
   - The global and service maxima come from single captures: 42-1 (global 4.55/h, service
     12.0/h under A, 1.44/h under H) and the NF-UNSW services (13.3/h).
   - No threshold rule set on calibration scores can hold a budget when the evaluation
     distribution moves this far. This matches Phase 8d (FPR doubles within hours) and is
     what `drift_detected` / `calibration_expired` are for (UNCERTAINTY_STATES.md).
2. **The declared FA/h budgets were rarely stricter than the 1% FPR target**, so H ≈ P.
   - A population with about 85–120 windows per hour gives alpha = B / (windows per hour)
     ≈ 0.8–1.2%, and H takes min(1%, alpha).
   - The stricter H thresholds that did apply were mostly unreliable: too few held-out
     windows for the quantile (7 local, 8 global, 5 service thresholds flagged).
3. **Population thresholds remove transient-external false alarms, but at a cost in
   attackers.**
   - P/H cut external_transient false alerts from a median of 5.6/h to 0.06/h.
   - They lose the 4 NF-UNSW external attackers that A "detects".
   - Those 4 detections came at a **25% FPR** in that population under A. A's 9/10 is
     therefore partly bought with false alarms, and is not evidence that A is the better
     policy.
   - Excluding them, A and P/H both detect 5/6 attackers.
4. **Abstention (HX) did not buy the budget by suppression.**
   - Median coverage stayed 1.0.
   - Coverage fell only where external transient sources exist (NF-UNSW 0.72, 3-1 0.79).
   - HX still failed the budget on the other populations.
5. **Detection delay** (median, first alerted attack window vs first attack window):
   - local 0 s under every policy (the attackers are already anomalous in their first
     window);
   - global 0 s (A) vs 420 s (H);
   - service 15 s.
6. **Sample size.** 10 attackers over 7 captures; 4 of them come from NF-UNSW. Every
   attacker-level difference above is within the Wilson intervals.

### Interpretation (what is and is not claimed)

- **[D]** On development data, per-population thresholds control the external-transient
  burden that dominated the deployed policy (Phase 8c finding). They do not control
  shift-driven overruns.
- **[D]** No policy kept every population within budget. The negative result is the result.
- **[H]** A shift-aware policy might meet the budgets: one that suppresses *normality claims*
  (not alerts) when `drift_detected`. This was not tested, and per the rule it would need
  fresh data.
- **No default changed.** The deployed policy A stays the default. The new uncertainty states
  make its weaknesses visible instead of silent.
