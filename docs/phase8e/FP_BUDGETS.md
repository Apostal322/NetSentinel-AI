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
