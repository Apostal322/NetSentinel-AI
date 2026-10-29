# V4 failure analysis: why the gated refresh absorbed 71% of the attack (Phase 8g, post-hoc)

**Labels.**
- [R]: diagnosis on consumed CTU-13 scenario 9.
- [E]: synthetic or development data.

**Verdict and artifacts.**
- The pre-registered V4 verdict (**refuted**: S5 absorbed 1,932 attack windows, 71%) is
  unchanged.
- Nothing here was tuned on CTU-13 and then claimed as a result.
- Scripts: `scripts/phase8g_post/sc9_diagnostics.py`, `sc9_product_gate.py`,
  `v4_synthetic.py`, `entity_gate_dev.py`.
- Outputs: `reports/phase8g_post/sc9_diagnostics.json`, `sc9_product_gate*.json`,
  `v4_synthetic*.json`, `entity_gate_dev.json`.

## 1. Reproduction

The diagnosis rebuilds the frozen scenario 9 profile from the frozen window parts. The
profile code has not changed since 121acbf. It recomputes the published numbers **exactly**:
- V3: 10/10 initiators, 565 attack windows detected, 0 benign false alerts, 2,563.4
  unverified alerts/h, median delay 47.5 s;
- V4: gate passed, 1,932 attack windows absorbed.

## 2. Mechanism [R]

| step | evidence (scenario 9, refresh after test segment 1) |
|---|---|
| **The candidate period is mostly background.** | 414,484 device windows: 387,876 external background, 23,252 internal background, 1,932 attack (**0.47%**), 573 verified benign, 836 unclassifiable |
| **The gate scores the candidate with the model it is about to replace.** | Under the current baseline only 482 of the 1,932 attack windows (25%) alert. The rest are below the threshold and invisible to the gate. |
| **Rate rule: significant but too small an effect.** | 5,130 / 414,484 = 1.24% alert rate, binomial p = 5e-50. The rule needs rate > 2 × 1% **and** p < 0.01, so it passed. |
| **Dilution is structural.** | Even if all 1,932 attack windows had alerted, the rate would be about 1.59% < 2%. A 10-host attack in a population of about 400k device windows cannot trip a population-rate rule. |
| **Strong-outlier rule.** | Max candidate score 60.9 < 2 × held-out max (124.1). Bots are persistent, not bursty. |
| **The candidate gives the bots their own profiles.** | The initiators were excluded from calibration (pre-registered), so they were scored by the pooled fallback (0 of 10 with an own profile). Each has ≥ 30 windows in the candidate period, so the refit gives **all 10** an own profile fitted on their attack behaviour. |
| **Effect after activation** | Last segment (0.68 h, 776 attack windows): S1 detects 10/10 initiators, recall 0.107. S5 detects **0/10**, recall **0.000** (per initiator: S1 recall 0.01–0.31, S5 recall 0 for every one). |
| **Evidence before activation** | Unchanged. S5 scores segments 0–1 with the old baseline, so no stored alert disappears. Only future detection is lost. |
| **The per-entity signal was there.** | Under the current baseline the initiators alert in 24.8% of their candidate windows (about 25× target). A one-sided binomial test per entity (Holm, α = 0.01) flags **all 10 initiators** and 12 others (10 external, 2 internal background). |

**Root cause.** The refresh gate tests the period, not the entities. A small number of
persistently anomalous entities is diluted below any population-level rule. The refit then
learns them, as their own profiles. "Absorbed" counts every attack window in the refit data
(1,932). In effect, the bots stopped being anomalous to themselves.

### Mechanisms the mission asked about

| mechanism | finding |
|---|---|
| observations passing the gate; dependence on the same model | yes: 75% of attack windows were below the current threshold, so invisible |
| mislabelled eligibility | no: eligibility was "all device windows of the period", as registered (an unvetted refresh) |
| dilution by aggregation | yes: the main cause (0.47% of windows) |
| cadence | one refresh in 2.69 h (every 2 segments) |
| source identity and ordering | identity: yes (own profiles granted to new persistent sources); ordering: not involved |
| gradual contamination | not on CTU-13 (bots were active from infection). Synthetic: section 4 |
| evidence disappearing after a refresh | no for stored alerts; yes for detection after activation |
| rollback | available but never triggered: S5 keeps the previous version, and nothing detects that the activation lost the bots. The product has explicit `calibration rollback` (tested), but it is an operator action. |

## 3. The product gate has the same weakness [R]

- **`registry.update_check` at 121acbf…de8610c:**
  - a rate test at the **global** level (one window per 30 s);
  - plus strong outliers at every level.
- **Run on the raw flows of the same candidate period** (1,176,615 flows), with the frozen
  profile saved as the previous calibration:
  - 4 alerts in 241 global windows (1.66%, p = 0.22);
  - no strong outlier;
  - **`review_required: false`**: activation would have proceeded without review
    (`sc9_product_gate_before_entity_rule.json`).
- The global level has even less power than the device level: 241 windows.

## 4. Synthetic contamination study [E]

**World.**
- 150 known devices, 300 transient sources per hour on the pooled fallback, 5 attackers.
- Drift of +0.75 on 2 features from evaluation segment 2 (a legitimate change).
- Calibration 2 h, evaluation 6 h, refresh due every 2 h.
- 5 seeds; means shown.
- Attacker types:
  - "new": absent from calibration;
  - "known": benign in calibration, then shifted;
  - "known_ramp": shift grows linearly from δ/6 to δ.

| cell | strategy | activations | absorbed | recall after first refresh | attackers detected in last segment (of 5) | known-device FPR after drift |
|---|---|---|---|---|---|---|
| new δ=3 | S1 fixed | 0 | 0.00 | 0.12 | 2.8 | 0.0022 |
| | S5 (V4) | 3 | **1.00** | 0.00 | **0.0** | 0.0015 |
| | QC per-entity quarantine + carry-over | 3 | 0.72 | 0.11 | 1.2 | 0.0014 |
| | QKC QC + no new own profile from unvetted data | 3 | 0.00 | 0.13 | 3.0 | 0.0012 |
| | QKCD QKC + shadow, delayed activation | 1.8 | 0.00 | 0.13 | 3.0 | 0.0018 |
| | V vetted-only | 3 | 0.00 | 0.12 | 2.8 | 0.0021 |
| known δ=1.5 | S1 | 0 | 0.00 | 0.36 | 5.0 | 0.0026 |
| | S5 | 0.6 | 0.20 | 0.30 | 4.0 | 0.0023 |
| | Q (quarantine, no carry-over) | 3 | 0.67 | 0.00 | 0.0 | 0.0012 |
| | QC / QKC | 3 | 0.00 | 0.34 | 5.0 | 0.0012 |
| | V | 3 | 0.00 | 0.36 | 5.0 | 0.0024 |
| known_ramp δ=1.5 | S1 | 0 | 0.00 | 0.13 | 5.0 | 0.0026 |
| | S5 / QC / QKC | 3 | **1.00** | 0.00 | 1.0 | 0.0012 |
| | QKCD | 2 | 0.67 | 0.00 | 1.0 | 0.0019 |
| | V | 3 | 0.00 | 0.13 | 5.0 | 0.0024 |
| known_ramp δ=3 | S1 | 0 | 0.00 | 0.81 | 5.0 | 0.0026 |
| | S5 / QC / QKC | 3 | 0.89–1.00 | 0.02–0.08 | 4.4–4.6 | 0.0013 |
| | QKCD | 1 | 0.00 | 1.00 | 5.0 | 0.0020 |
| | V | 3 | 0.00 | 0.81 | 5.0 | 0.0024 |

All cells and strategies are in `v4_synthetic.json` and `v4_synthetic_known_ramp.json`.

**What the study shows.**
1. **S5 reproduces the CTU-13 failure.** "New" attackers obtain own profiles and are absorbed
   completely.
2. **Removing an entity without carrying its statistics over is worse than not removing it
   (Q).**
   - The entity falls back to the pooled profile, becomes invisible, and is admitted at the
     next refresh (a cascade).
   - Carry-over (QC) fixes this for "known" attackers.
3. **Entity-level checks fail under gradual contamination.**
   - A slow ramp stays below the per-entity test at the early refreshes, so QC and QKC absorb
     89–100%.
   - Delayed activation (QKCD) helps only when the attack is strong (δ = 3).
4. **Only vetted-only refresh (V) and refusal (S1) absorbed nothing in every cell.**
5. **The benefit of refreshing is small in this world.**
   - Known-device FPR after the drift: 0.0021–0.0026 for S1 and V, versus 0.0012–0.0019 for
     the data-driven strategies.
   - Those strategies buy their lower FPR partly by learning attacks.

**On CTU-13 [R; not validation].**
- On the last segment, QC and QKC kept 10/10 initiators: recall 0.104 / 0.115 versus 0.107
  for S1, with 19% fewer unverified alerts.
- That is one 0.68 h segment of consumed data. The synthetic ramp shows the same strategies
  failing, so this is not evidence of safety.

## 5. Product change: per-entity review trigger (adopted; detection unchanged)

**What changed.** `update_check` now also requires review when a device or service entity
with ≥ `min_windows` windows alerts persistently under the current baseline:
- one-sided binomial, Holm over every tested entity, α = 0.01;
- alert rate > 2 × target.

The rule **only adds reviews**:
- it never activates, excludes or refits anything;
- activation of a review-required calibration still needs `--reviewed` (operator), and
  rollback is unchanged.

**Adoption rule** (fixed before the development run): at most 1 of the 12 clean development
periods newly requires review, and no scan caught by the Phase 8F gate is lost.

| evidence | result |
|---|---|
| regression test `test_update_gate_flags_a_persistently_anomalous_entity` | old gate: no review for a host alerting in about 10% of its windows; new gate: review, entity listed |
| development data (12 benign CTU-Normal periods, Phase 8F protocol) [E] | clean periods newly requiring review: **0 / 12**; injected 60 s scans requiring review: **8 / 12** (Phase 8F gate: 7 / 12), none lost → **rule met** |
| CTU-13 scenario 9 candidate period [R] | review required: 23 entities, **all 10 initiators listed**. Without the initiators' flows: still required (13 background entities, e.g. 186.198.158.69 alerting in 78 of 87 windows) |

**Limits.**
- On scenario 9 the trigger would have fired from the background alone. Its specificity for
  attacks on that network is therefore not shown. It puts the bots in front of the reviewer;
  it does not identify them.
- It does not protect against gradual contamination (section 4). An entity not yet
  significant when a refresh is reviewed is still learned.
- It is not a confirmatory result. α and the 2 × target factor are the existing gate
  constants, not tuned.

## 6. Recommendations

1. **Keep refresh manual and review-gated, and prefer vetted-only refresh.** No automatic
   data-driven refresh: none of the alternatives is safe in every synthetic cell.
2. **Never grant an own profile from unvetted data** to an entity that had none (the QKC
   rule) when a refresh is vetted only partially. Recorded as a recommendation; not
   implemented.
3. **Phase 8h:** test the entity trigger and QKC on a fresh capture with a pre-registered
   criterion, including a gradual-onset attack.

| finding | status |
|---|---|
| V4 (pre-registered): gated recalibration does not absorb attacks | **refuted** (unchanged) |
| root cause = population-level gate diluted, plus own profiles granted to new persistent sources | **confirmed** [R] (exact reproduction, step-by-step) |
| the product gate shares the weakness | **confirmed** [R] |
| per-entity trigger: no new false reviews on development data | **confirmed** [E] |
| per-entity trigger: specific to attacks on CTU-13 | **not evaluated** (fires on background too) |
| any data-driven refresh is safe under gradual contamination | **refuted** [E] |
| QC / QKC safe on CTU-13 | **inconclusive** [R] (one segment, consumed data) |
