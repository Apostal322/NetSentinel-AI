# Phase 8r Stage 1: calibration identifiability

**Status:** analysis on saved scores. No model was fitted, and no Experiment A/B/C outcome had
been computed when this was written.

**Sources:**
- `scripts/phase8r/identifiability.py`;
- `reports/phase8r/identifiability.json`.

## 1. Trust categories

These categories describe where a piece of evidence came from. **They carry no confidence
values.**

| category | meaning | in these data | available at deployment? |
|---|---|---|---|
| **T0 unknown** | no evidence about the window or host | every unlabelled calibration window | yes |
| **T1 dataset-labelled benign** | benign according to the dataset's flow labels | the non-attacker hold-out hosts (`cal_truth`) | **no** (a testbed artefact) |
| **T2 weakly trusted benign** | believed benign without review (for example an administrator's "known" persistent hosts) | simulated: the most persistent hold-out hosts, *not* vetted (`naive_T2`) | yes |
| **T3 vetted benign** | reviewed by an analyst and found benign, within a review budget | **simulated** by T1 labels of the selected hosts (ORACLE-SIMULATED vetting) | yes, at a cost |
| **T4 confirmed malicious** | reviewed and found malicious | simulated: selected hosts that are calibration attackers in `cal_truth` | yes, at a cost (only for the hosts reviewed) |

**Rules:**
- Dataset-labelled benign (T1) is never presented as verified benign. Phase 8q found no verified
  benign population (gap Q0.4).
- Simulated vetting is labelled **ORACLE-SIMULATED** wherever it is used.
- Ambiguous traffic keeps its Phase 8q audit category. Nothing is relabelled.

## 2. Deployment information boundary

```
time ─────────────────────────────────────────────────────────────────────────────────►
      calibration period (before mid)                        │ evaluation (deployment)
 ├──────────── first 70 % ─────────────┼──── hold-out 30 % ──┤├──────────────────────────
 │ flows → destination memory (T0)     │ windows scored (T0) ││ windows scored, alerts
 │                                     │ ↑ vetting of a few  ││ memory FROZEN at mid
 │                                     │   hosts: T3 / T4    ││
 │                                     │   (budgeted, before ││
 │                                     │   the freeze)       ││
 └─────────────────────────────────────┴─────────────────────┘│
   available to a deployment: T0 everywhere; T2 (administrator belief); T3/T4 for the
   vetted hosts only, at a review cost; never future labels or evaluation labels.
   NOT available: T1 (dataset labels), the P1x purge (needs every calibration attacker),
   evaluation labels (used for metrics only).
```

| input | category | used by |
|---|---|---|
| unlabelled hold-out scores, hosts, times | T0 | A0, A3, Phase 8q L1–L5 |
| host metadata (windows, active hours, UDP share, destination ports) | T0 | selection policies |
| vetting outcome of the selected hosts | T3/T4 (ORACLE-SIMULATED) | A2–A5, M2 |
| administrator trust without review | T2 | `naive_T2` |
| all calibration-attacker identities | T1 / oracle | A1, A1T, M0 (references only) |
| evaluation labels and audit categories | oracle | metrics only |

## 3. Is the benign threshold identifiable?

**Target:** the benign (1 − α) hold-out quantile q_b, at α = 1 %.

**Observation without labels:** the mixture F = (1 − ε) F_b + ε G, where G (the attacker windows)
is arbitrary and ε is unknown.

**Result (Horowitz–Manski):** if ε ≤ ε̄, then
q_b ∈ [Q_F((1 − α)(1 − ε̄)), Q_F(1 − α(1 − ε̄))].
- The interval is exact for empirical distributions at ε̄ = ε. A unit test checks containment
  on synthetic mixtures.
- **Without a bound on ε, the identified set is the whole score range.**

**Identified sets on the real hold-outs** (mean over 6 fits):
- The FPR and documented-attacker recall ranges come from applying the interval's end points to
  the unlabelled-memory evaluation scores.
- ε is the oracle attacker share of the hold-out windows.

| domain | ε | benign hosts (effective) | FPR range at ε̄ = ε | recall range at ε̄ = ε | FPR range at ε̄ = 5 % | contains q_b at 5 %? |
|---|---|---|---|---|---|---|
| NF-CIC 02-14 | 0.15 % | 6,557 (555) | 1.0–1.1 % | 0.99 | 1.0–6.3 % | yes |
| NF-CIC 02-16 | 0 | 5,053 (477) | 1.2 % | 0.96 | 1.2–5.8 % | yes |
| NF-CIC 02-20 | < 0.01 % | 6,534 (651) | 1.2 % | 0.06 | 1.2–6.1 % | yes |
| NF-CIC 02-21 | 0 | 6,505 (598) | 1.4 % | 0.99 | 1.3–6.9 % | yes |
| NF-CIC 02-22 | 9.8 % | 6,002 (506) | 1.1–11.9 % | 0.003–0.016 | 1.1–6.5 % | **no** |
| NF-CIC 03-02 | 2.7 % | 4,736 (609) | 1.1–3.9 % | 0.0004 | 1.1–6.3 % | yes |
| NF-UNSW | 28.9 % | 17 (12.3) | 1.7–19.0 % | 0.05–0.80 | 1.8–3.3 % | **no** |
| NF-ToN | 76.3 % | 3,635 (92.8) | 0.1–64.2 % | 0.0001–0.96 | 0.4–2.3 % | **no** |
| NF-BoT | 91.9 % | 7 (2.2) | 1.5–96.9 % | 0.62–0.99 | 9.6–14.4 % | **no** |

**Conclusions:**
1. **Without trusted evidence and without a contamination bound: NOT IDENTIFIABLE, on every
   network.** This is a property of the problem, not of the Phase 8q estimators.
2. **With a known bound, the threshold is only partially identified.**
   - Only NF-CIC has contamination small enough for a useful bound: at ε̄ ≤ 5 % its FPR range
     is about 1–7 %.
   - On NF-UNSW, NF-ToN and NF-BoT, any bound narrow enough to be useful is false. At
     ε̄ ≤ 10 % the interval excludes q_b.
   - On NF-ToN and NF-BoT the honest bound (the true ε) spans almost the whole FPR range.
3. **A representative trusted-benign sample makes q_b identifiable, up to sampling error,
   under one assumption:** the vetted hosts are exchangeable with the deployment's benign hosts.
   So the threshold is **CONDITIONALLY IDENTIFIABLE**, and Experiment A measures what realistic
   budgets and selection policies achieve.
4. **Distribution-free FPR control at the host level needs ≥ 99 exchangeable benign hosts**
   (⌈1/α⌉ − 1).
   - Feasible on NF-CIC (≥ 4,700) and NF-ToN (3,635).
   - Infeasible on NF-UNSW (17) and NF-BoT (7, of which 2.2 are effective).
   - On those two networks, an FPR guarantee is **NOT IDENTIFIABLE** whatever the trusted
     budget. A window-level conformal guarantee would ignore within-host dependence.
5. **Recall is not identifiable without positive evidence (T4).** It is evaluated here with
   dataset labels, never estimated by a deployment method.
6. **The memory is a separate problem.**
   - With the unlabelled memory, even the oracle threshold gives 02-22 recall 0.003–0.016 and
     03-02 recall 0.0004.
   - So no threshold, trusted or not, can recover those days. Only the feature state can
     (Experiment C).
   - The threshold problem is confined to NF-UNSW, NF-ToN and NF-BoT. On NF-CIC, U ≈ q_b
     (within 0.005).
