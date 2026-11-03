# Phase 8o pre-registration: Experiment D

**Chronology:**
- Written 2026-11-03 after the Stage A audit (GAP_REGISTER.md, FEATURE_SEMANTICS.md). That audit
  read saved windows, saved features and saved Phase 8n *ensemble means* only.
- Before any Phase 8o model was fitted.
- No score of any arm below exists when this file is committed.

**Data:** the four consumed development networks; all results are REGISTERED DEVELOPMENT. The
frozen M2 candidate (Phase 8n FREEZE_CANDIDATE.md) is not changed; new members are stored under
`data/derived/phase8o/`.

**What was seen before registration:**
- the novelty rates of training, hold-out and evaluation windows;
- the false-alert decomposition of the Phase 8n M0/M2 fits;
- the hold-out block counts.

**Margins.** The margins below come from Phase 8n:
- the G1–G3 and RP margins;
- the size of a no-op refit (+0.09 NF-CIC recall);
- the M2 fresh-replication changes (unstable entities 11 → 1 at ≥ 1 window, 14 → 10 at ≥ 20 %).

C4's threshold was chosen with the audit's novelty rates in view, so C4 is EXPLORATORY.

## 1. Fits

| item | value |
|---|---|
| model | M2 construction (Phase 8n): member m of replicate r has LightGBM seed and subsample seed 1000 + 10r + m; Phase 8i B-raw parameters; network- and class-balanced weights; 50,000-window cap |
| members | m = 0–4, **scores stored per member** |
| replicates | **r = 6, 7, 8** (fresh randomness; never fitted before) |
| regimes | base; stress (each member's source hosts resampled with replacement, `rng([8, r, j])`, as Phase 8n) |
| sources / targets | leave-one-network-out (Phase 8j `leakage_audit.targets`): 9 target domains, 4 source sets |
| calibration | P1x hold-out (last 30 % of calibration slots); T0 = conformal rank ⌈(n + 1)(1 − α)⌉, α = 1 % |
| K-member ensemble | mean probability of members 0 … K − 1 (**nested prefix**, fixed before results; no seed is chosen by its outcome) |

## 2. Arms

Only the source training rows change, except in F4. Rows, labels, weights, seeds, subsamples and
target windows are identical to F0.

| arm | source training rows | target windows | regimes |
|---|---|---|---|
| **F0** historical | Phase 8h `train_matrix` (calibration: expanding memory; evaluation: frozen at the midpoint) | P1x, historical | base, stress |
| **F1** deployment-aligned | calibration rows in the source's last 30 % of calibration slots get `new_dst_frac` from a memory **frozen at that slot boundary q** (calibration flows before q; calibration attack flows removed, as the clean memory). Rows before q are calibration rows under that scenario and keep their expanding value; evaluation rows keep the midpoint-frozen value | historical | base, stress |
| **F2** forward-only replay | evaluation rows get the Phase 8m causal expanding value (`nov_unconditional`, clean memory); calibration rows unchanged | historical | base |
| **F3** no-op rebuild | the F1 builder run with the freeze at the midpoint reproduces every calibration row's `new_dst_frac`. **Checked on features, not trained:** identical inputs give identical fits (Phase 8n, 81/81) | — | — |
| **F4** matched-information control | `new_dst_frac` → `new_dst_frac²` in training **and** target matrices (monotone: same information, different histogram bins) | transformed | base, stress |
| **F5** cold-start exclusion (H1b) | source domains whose calibration part has fewer than 1,000 windows are dropped (NF-CIC 2018-02-27: 229; 2018-02-28: 392; every other source has ≥ 14,000) | historical | base |

**The deployment scenario behind F1, stated causally:**
- the memory starts empty at the first flow of the source capture or day;
- it grows on calibration flows until q, then freezes;
- windows in [q, midpoint) are scored against it.

No row uses a flow that ended at or after its own window's end. The memory never sees a
destination first contacted after q.

**The dose, measured on features before any fit** (build_aligned.py; R3 passed on all 14
domains):
- **F1 is a small manipulation.** It changes 1.9–2.7 % of the late calibration rows, under 1 %
  of all training rows of a source set; the novel share of those rows doubles (e.g. NF-CIC 02-14
  1.5 % → 3.0 %, NF-ToN 1.2 % → 2.9 %).
- **C1 raises the hold-out novel share:**

  | network | before → after |
  |---|---|
  | NF-CIC | 1.5 % → 3.0–3.3 % |
  | NF-UNSW | 0.45 % → 2.9 % |
  | NF-ToN | 0.9 % → 2.4 % (its evaluation: 14–65 %) |
  | NF-BoT | 0.13 % → 3.5 % |

- **Expected outcomes, stated before results:**
  - F1 is unlikely to move detection beyond the F4 noise floor;
  - C1 cannot by itself close NF-ToN's gap, whose staleness accumulates over 72 h of
    evaluation.

  The registered rules stand regardless.

**Reproduction checks (stop and diagnose if any fails):**
- **R1:** F0, base, r = 0, the K = 5 mean equals the saved Phase 8n M2 base r0 `s_hold` and
  `s_ev` (max |Δ| = 0).
- **R2:** a single M0 fit (seeds 0, 0) equals the Phase 8n P_ref r0 scores.
- **R3:** F3 is bit-exact on every calibration row.

## 3. Metrics (per fit and target domain, at T0 unless stated)

- **Window measures:** window recall, false alerts, FPR, AUC, ranking recall at the benign
  99th percentile (oracle; a ranking diagnostic only, never reported as deployable performance),
  false alerts per hour and per active host-hour, median detection delay.
- **Entities:** sources with ≥ 5 attack windows in a domain (75). An entity is detected in a fit
  at level q ∈ {≥ 1 window, ≥ 20 %, ≥ 50 % of its attack windows}. Over the fits of an arm,
  R_q / U_q / N_q = detected in all / some / none.
- **Network value:** the mean over the network's domains and fits; macro = the mean of the 4
  networks.
- **Collapse:** window recall < 0.2 on a strong domain in one fit. Strong domains are those with
  Phase 8j B0 mean recall ≥ 0.5 (Phase 8n RP4): NF-BoT, NF-CIC 02-14/02-16/02-21, NF-ToN,
  NF-UNSW.

## 4. H1: training-inference alignment (F1 vs F0; K = 5; 6 fits each)

**Noise floor from the F4 control:**
- δ = macro mean of |recall(F4) − recall(F0)| per network;
- ε = max over networks of |FA(F4) / FA(F0) − 1|.

**NOT EVALUABLE** if R3 fails or δ ≥ 0.05.

**SUPPORTED** if every guardrail holds and either path holds:
- **Guardrails:**
  - on every network, recall(F1) ≥ recall(F0) − 0.05 and FA(F1) ≤ 1.10 × FA(F0);
  - R₂₀(F1) ≥ R₂₀(F0) − 2 and U₂₀(F1) ≤ U₂₀(F0) + 2;
  - collapses(F1) ≤ collapses(F0).
- **Path R (detection):** macro recall(F1) − macro recall(F0) ≥ max(0.02, 2δ).
- **Path F (workload):** on ≥ 2 networks FA(F1) ≤ (1 − max(0.20, 2ε)) × FA(F0), and macro
  recall(F1) ≥ macro recall(F0) − 0.01.

**NOT SUPPORTED** otherwise.

**F2 (dose contrast, descriptive):** if aligned semantics matter, F2, which is more misaligned,
should not beat F0 on macro recall. F2 is reported, not decided.

**H1b (F5 vs F0, base fits only, 3 each):** the same rule, with δ and ε from the base fits of
F4. It is a registered secondary hypothesis with half the fits.

## 5. H2: ensemble size (F0 fits; K ∈ {1, 2, 3, 5})

- Δ₁ = U₁(K=1) − U₁(K=5) and Δ₂₀ = U₂₀(K=1) − U₂₀(K=5).
- A definition is *informative* if its Δ ≥ 3.
- **If neither definition is informative,** H2 is NOT EVALUABLE (the stability gain of M2 over
  one member is not reproduced on these fits), and K = 5 stays.

**K ∈ {2, 3} preserves M2's benefit** if:
- for every informative definition d, U_d(K=1) − U_d(K) ≥ 0.75 Δ_d;
- R₂₀(K) ≥ R₂₀(5) − 1;
- collapses(K) ≤ collapses(5);
- on every network, recall(K) ≥ recall(5) − 0.02 and FA(K) ≤ 1.10 × FA(5).

**Selected:** the smallest preserving K, otherwise K = 5.

**Uncertainty (exploratory):** U, R and recall over all C(5, K) member subsets.

**Cost:** measured directly by `scripts/phase8o/profile_inference.py`, not inferred from training
time. It records:
- artifact size, load time and peak RSS;
- windows per second, batch and single-window latency;
- feature-building throughput.

K = 10 is not run.

## 6. H4: calibration and false-alert control (F0 fits, K = 5; K = 1 reported too)

| method | definition | role |
|---|---|---|
| T0 | registered Phase 8j threshold | reference |
| **C1** aligned hold-out | T0 computed on the same hold-out windows with `new_dst_frac` from the P1x memory **frozen at the hold-out start** (calibration flows before it, calibration-period attacker hosts removed) | **registered** |
| C2 minimum evidence | T0 is valid only if the hold-out holds ≥ 1/α = 100 distinct (host, hour) blocks; otherwise the domain is "calibration invalid: insufficient evidence" and all its windows are unassessed | registered, descriptive |
| C3 no calibration labels | T0 from the *unlabelled* hold-out (calibration-period attackers kept; memory from all calibration flows), applied to the unlabelled evaluation windows | registered, descriptive (deployment-realistic labels) |
| C4 shift abstention | an evaluation window is unassessed ("calibration stale") when the share of novel evaluation windows that ended in the previous hour exceeds the hold-out share + 0.10; label-free and causal | **EXPLORATORY** |

**C1 is SUPPORTED** if:
- |FPR − α| falls on ≥ 3 of 4 networks;
- on every network with T0 FPR ≤ 2α, recall(C1) ≥ recall(T0) − 0.05;
- R₂₀(C1) ≥ R₂₀(T0) − 2.

**Guardrails for C2 and C4 (Phase 8o Part 7.4), always reported:**
- the share of domains and windows assessed;
- FPR and recall conditional on assessment;
- workload over the whole population (unassessed windows counted, never dropped);
- how many attack windows fall in unassessed time.

## 7. H3 entity robustness and H5 domain robustness (descriptive, registered metrics)

**H3** is described over the 30 single-member F0 fits and the 6 K = 5 fits:
- for every entity: detection frequency at the three levels, worst-fit window recall, and
  margin (median attack score − T0);
- delay range;
- ranking vs threshold failure per fit: a failure is *threshold* if the ranking recall at the
  benign 99th percentile is ≥ 0.5 while recall at T0 is < 0.2, and *ranking* if both are < 0.2;
- for the never-detected entities, whether any source network contains the attack family.

**H5,** per arm:
- macro recall and worst-network recall;
- per-network recall, FPR, false alerts per hour, by attack family;
- min and max over fits.

NF-CIC days are not independent institutions.

## 8. Decisions

| decision | rule |
|---|---|
| research completion | GO if R1–R3 pass and every registered fit is complete; NOT EVALUABLE if a reproduction fails and cannot be explained |
| feature-semantics improvement | the H1 verdict (H1b reported beside it, separately) |
| ML model improvement | DEVELOPMENT GO if H1 or H1b is SUPPORTED; otherwise DEVELOPMENT NO-GO. H2 is an efficiency result, not a detection improvement |
| calibration | the C1 verdict; C2–C4 descriptive |
| deployment | NO-GO unless independent evidence exists (it does not: Phase 8n FREEZE_CANDIDATE) |

## 9. Budget

| run | fits | cost | status |
|---|---|---|---|
| feature build `build_aligned.py` (calibration flows only; 11 NF-CIC days + 3 networks; no model) | none | measured: 2 min, peak 1.4 GiB | done before registration; R3 passed |
| inference profile `profile_inference.py` | 5 M2 r0 members on the NF-CIC target's sources (cost measurement only; no detection metric) | measured: 106 s, peak 1.5 GiB | done |
| training `experiment_d.py` | 24 arm × regime × replicate configurations × 4 source sets × 5 members (480 LightGBM fits), plus R1/R2 (24 fits) | ≈ 70 min, ≈ 2.0 GiB peak, ≈ 1.5 GB of float64 scores | **authorization requested** |

Everything runs sequentially under `run_capped` (3.4 GiB), on CPU.
