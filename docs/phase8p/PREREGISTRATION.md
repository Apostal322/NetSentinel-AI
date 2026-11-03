# Phase 8p pre-registration: Experiment E (victim-side, service-aware, bidirectional, calibration)

**Chronology.**
- Written 2026-11-03 after Stage 1 (ATTACK_OBSERVABILITY.md: label audit and in-domain
  diagnostics) and before any Experiment E model was fitted.
- No score of any Experiment E arm exists when this file is committed.

**What was seen before registration:**
- the Phase 8o F0 scores and entity outcomes;
- the per-group, in-domain, label-using diagnostics of the new victim-side features (every group
  separable in-domain; ATTACK_OBSERVABILITY § 3).

No cross-network result of any new feature or model had been seen.

**Data:** the four consumed development networks, leave-one-network-out (Phase 8j targets). All
results are REGISTERED DEVELOPMENT; none is an independent confirmation. Frozen M2, DEDALE and
every earlier artifact are untouched; new outputs go to `data/derived/phase8p/`.

## 1. Fits (Experiment E)

| item | value |
|---|---|
| construction | Phase 8n M2: 5 members, member m of replicate r with LightGBM and subsample seed 1000 + 10r + m; Phase 8i B-raw parameters; network- and class-balanced weights; 50,000-row cap per domain; `candidates.source_data` / `fit_one` |
| replicates | r = 6, 7, 8: the same seeds as Phase 8o F0, so every arm is **paired** with S0 fit by fit |
| regimes | base; stress (each member's source hosts resampled, `rng([8, r, j])`); the controls are base only |
| calibration | P1x hold-out (last 30 % of calibration slots); T0 = conformal rank ⌈(n + 1)(1 − α)⌉, α = 1 % |
| ensemble | mean of the 5 members |

## 2. Arms

| arm | features | units | regimes |
|---|---|---|---|
| **S0** source-only baseline | the 12 `WINDOW_FEATURES` | source windows | **reused:** Phase 8o F0 per-member scores (6 fits). The base fits are refitted once to save models for C2, and must reproduce the Phase 8o scores exactly (R1) |
| **D2** source + victim context | 12 + `CONTEXT_FEATURES` (5) | source windows | base, stress |
| **S1** source + service | 12 + `SERVICE_FEATURES` (4) | source windows | base, stress |
| **D2S** source + context + service | 12 + 5 + 4 | source windows | base, stress |
| **D1** victim-only | `VICTIM_FEATURES` (16) | victim windows | base, stress |
| D1h control: victim-only without history | VW minus `v_hist_dev`, `v_hist_n` | victim windows | base |
| Sonly control: service-only (port-label shortcut probe) | `SERVICE_FEATURES` (4) | source windows | base |
| **D3** late fusion (no new fit) | S0 and D1 scores | source windows | paired S0 / D1 fits |

**Feature joins.**
- **Source windows:** the SX rows of `build_victim.py`, joined on (key, win) to the Phase 8h
  training rows and to the P1x target windows (`replace`-style left join, order checked).
- **Context features** come from all-flow victim windows. In calibration they include the traffic
  of calibration-period attackers (P1x purges attacker *windows* and *memory*, not other hosts'
  context). This is registered, not corrected after the fact.

**D1.**
- **Training rows:** source domains' victim windows, calibration and evaluation periods, without
  noisy windows. Label `y` = the window holds ≥ 1 attack flow. Host bootstrap is over responders.
- **Target hold-out:** calibration victim windows in the last 30 % of calibration slots, with no
  attack flow (the flow-level analogue of P1x's oracle purge).
- **Target evaluation:** evaluation victim windows that are not noisy.

**D3.**
- For each target source window, `v` = the maximum D1 score over the responders the source
  contacted in that window (Phase 8m `contacts_p1x`).
- `fused = max(F_s(s), F_v(v))`, where `F_s` and `F_v` are the empirical CDFs of `s` (S0) and
  `v` over that fit's source hold-out windows.
- T0 is computed on the fused hold-out score at the same α. So D3 operates **under the same
  shared alert budget** as S0.

## 3. Metrics (per fit, target domain; at T0 unless stated)

- **Source-window units:**
  - window recall over all attack windows (historical comparability) and over
    **documented-attacker windows** (primary, ATTACK_OBSERVABILITY § 2);
  - false alerts, verified-benign FPR (benign = label benign and not noisy), false alerts per
    hour;
  - AUC, ranking recall at the benign 99th percentile (diagnostic only), median detection delay.
- **Entities:**
  - E_doc = the 48 documented attackers (primary);
  - all 75 (secondary);
  - detected at ≥ 1 window / ≥ 20 % / ≥ 50 % of its windows;
  - R/U/N over an arm's fits;
  - attacked-host traffic (5) and undocumented sources (22) reported separately.
- **Network value** = mean over the network's domains and fits; macro = mean of the 4.
- **Collapse** = recall < 0.2 on a strong domain (Phase 8n RP4) in one fit.
- **D1 (victim units):**
  - victim-window recall (≥ 1 attack flow; sensitivity: ≥ 50 % of flows attack), FPR over
    attack-free victim windows;
  - victim-host detection (a host with attack windows, alerted at ≥ 1 / ≥ 20 % of them);
  - **attributed attacker coverage:** a documented attacker is covered if one of its attack
    contacts falls in an alerted victim window. Attribution uses labels only after the fact; it
    is reported beside source-attacker recall, never in place of it.
- **Complementarity (descriptive):**
  - entities detected by S0 / D1 coverage / D3;
  - the Spearman correlation of `s` and `v` on attack windows;
  - the overlap of false-alert windows.

## 4. Decision rules (candidate X ∈ {D2, S1, D2S, D3} vs S0, paired fits; K = 5)

**Guardrails (all):**
- on every network, FA(X) ≤ 1.10 × FA(S0) and recall_doc(X) ≥ recall_doc(S0) − 0.05;
- collapses(X) ≤ collapses(S0);
- U₂₀,doc(X) ≤ U₂₀,doc(S0) + 2.

**Improvement (either):**
- **(a)** R₂₀,doc(X) − R₂₀,doc(S0) ≥ 3, i.e. three more documented attackers detected at
  ≥ 20 % of their windows in every fit. S0 leaves 11 documented attackers never at 20 %.
- **(b)** macro recall_doc(X) − macro recall_doc(S0) ≥ 0.03.
  - About 3 SD of the Phase 8o paired per-fit differences (SD 0.011).

**X passes** if every guardrail holds and either improvement holds.

**Verdicts:**
- **H1, victim-side features add attack-relevant signal:** SUPPORTED if D2 passes. D1's
  standalone victim-unit results are reported as supporting evidence, not decisive.
- **H2, service context helps without a shortcut:** SUPPORTED if S1 passes **and** the Sonly
  control's macro recall_doc is below 0.5 × S1's. If service mix alone carries half of S1's
  detection, any gain is not attributed to service *conditioning*.
- **H3, a bidirectional detector improves operational detection at the shared budget:**
  SUPPORTED if D3 passes. D2S is reported as the joint feature model.
- **Selection:** among passing candidates, the largest R₂₀,doc; ties go to the simpler, in the
  order D2, S1, D2S, D3.
- **Model candidate:** DEVELOPMENT GO if any candidate passes (H2 additionally needs its
  control); otherwise DEVELOPMENT NO-GO.
- **NOT EVALUABLE:** if R1 fails, or any registered fit is missing.

**Uncertainty:**
- paired per-fit differences (6 correlated fits, reported, not tested);
- an entity bootstrap of the R₂₀,doc difference: resampling the 48 documented attackers,
  B = 2,000, seed 8. This is approximate, because entities cluster by network-day.

## 5. H4: deployment-realistic calibration (S0)

| scenario | information assumed | hold-out | fits |
|---|---|---|---|
| **C0** P1x (oracle-assisted reference) | every calibration-period attacker host is known | P1x | 6 (Phase 8o F0) |
| **C1** unlabelled | none | all calibration windows, memory from all calibration flows (Phase 8i unlabelled) | 6 (Phase 8o `s_hold_u`, `s_ev_u`) |
| **C2** delayed labels | an attacker is known only if its last calibration-period attack flow ended ≥ 60 min before the calibration end (time for review) | P1x builder with that partial exclusion list (hold-out and memory) | 3 (S0 base refits) |
| **C3** host-balanced, unlabelled | none | C1's hold-out; T0 = the weighted (1 − α) quantile with weight 1 / (the host's hold-out windows), so a persistent host cannot dominate the tail | 6 |

**Reported per scenario and network:**
- information used; hold-out windows; independent host-hour blocks; hosts; top-host share;
- calibration age at the evaluation midpoint;
- nominal α; observed FPR;
- recall_doc and recall over all attack windows; entities R₂₀,doc;
- coverage. Every scenario assesses all windows; there is no abstention.

**H4 rule:** C3 preserves useful detection if:
- macro recall_doc(C3) ≥ 0.75 × macro recall_doc(C0);
- on every network, FPR(C3) ≤ FPR(C0) + 0.01.

C1 and C2 are descriptive. No scenario claims distribution-free FPR control.

## 6. Deployment

NO-GO. No independent data is eligible (Phase 8o INDEPENDENT_DATA).

## 7. Budget (authorization requested)

| run | fits | estimate |
|---|---|---|
| C2 window build (P1x builder, partial exclusions, 9 targets) | none | ≈ 5 min, ≤ 2 GiB |
| `experiment_e.py` | 33 arm × regime × replicate configurations × 4 source sets × 5 members ≈ 660 LightGBM fits | ≈ 100–120 min, ≈ 2.3 GiB peak, ≈ 2 GB of scores |

Everything runs sequentially under `run_capped` (3.4 GiB), on CPU.
