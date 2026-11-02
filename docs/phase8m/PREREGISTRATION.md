# Phase 8m pre-registration: adaptive destination novelty (development)

**Written:** 2026-11-02, before any Phase 8m comparison was run.
**Seen when writing:**
- the Phase 8l DEDALE confirmatory result, which motivates the phase;
- the code trace.

The Stage 1 novelty audit (NOVELTY_FAILURE_ANALYSIS.md) was still running when sections 1–8 were
drafted. Its results arrived afterwards and are handled by amendment 1 (section 9), which was
written before any comparison.

No model with an adaptive feature had been trained or scored.

**Status of everything here: REGISTERED DEVELOPMENT.**
- The four development networks were explored in Phases 8b–8k.
- No result of this phase is independent confirmation.
- DEDALE is consumed: it is used only for POST-HOC diagnostics *after* the candidate is fixed
  (section 8).

## 1. Units, data and protocol

- **Domains:** the 9 Phase 8j development domains.
  - NF-CIC-IDS2018-v3: 6 days, which form one network.
  - NF-UNSW-NB15-v3, NF-ToN-IoT-v3 and NF-BoT-IoT-v3: one each.
- **Independent units: 4 networks.** Domains of one network are not independent. Windows and hosts
  are nested inside domains.
- **Protocol:** Phase 8j P1x leave-one-network-out, unchanged.
  - The source models are trained on the other networks' domains: B-raw LightGBM, Phase 8i
    settings, seeds {0, 1, 2}.
  - Calibration is P1x: calibration-period attackers are removed from the calibration windows and
    from every memory before the freeze.
  - T0 is the conformal rank at α = 1 % on the last 30 % of calibration slots, per seed and per
    model. Alerts are scores strictly above T0.
  - Evaluation = everything after the domain's time midpoint.
- **Same information budget for every model:**
  - the same windows, labels, calibration, hold-out and seeds;
  - only the novelty columns differ.

## 2. Features and memory policies (`src/netsentinel/behavior/novelty.py`)

**All features are causal.** A window's values come from the memory before that window. The class
reproduces the deployed `new_dst_frac` exactly under the frozen policy (unit test).

| policy / feature | definition | role |
|---|---|---|
| A0 `nov_frozen` | = `new_dst_frac`: calibration memory, frozen at the midpoint | control (the deployed behaviour) |
| A1 `nov_unconditional` | every destination is known after its first window | necessary, unsafe comparison; never promoted |
| A3 `nov_guarded`, `log_new_guarded` | known only after ≥ 2 distinct sources, with contacts spanning ≥ 1 h | candidate |
| A2 `familiarity_decay` | mean exp(−time since last contact / τ), τ = 1 day | candidate (recency) |
| A4 `nov_host` | share of the source's first contacts | context |
| A4 `log_prevalence` | mean log(1 + earlier distinct sources), cap 8 | context (network-wide familiarity) |

**Parameters are fixed from first principles, not tuned:**
- **≥ 2 sources:** shared infrastructure is contacted by several hosts, while a single
  compromised host's C2 is not.
- **≥ 1 h span:** persistence beyond a single burst.
- **τ = 1 day:** the diurnal cycle.

A sensitivity grid is reported as EXPLORATORY: sources {2, 3} × span {10 min, 1 h, 6 h} ×
τ {1 h, 1 day, 7 days}. It never selects the candidate.

**Models:**

| model | features |
|---|---|
| **B0** | the 12 registered window features, with `new_dst_frac` (Phase 8j scores reused; they were produced by exactly this protocol) |
| B1 | the 11 non-novelty features + `nov_guarded`, `log_new_guarded`, `familiarity_decay` |
| **B2** (primary candidate) | B1 + `nov_host`, `log_prevalence` |
| B3 | a single-feature, label-free rule: score = `log_new_guarded`, calibrated in the same way |
| B1u (unsafe comparison) | the 11 + `nov_unconditional`, `familiarity_decay` |
| ablations (exploratory) | the 11 only (no novelty); B2 without the volume features (`log_flows`, `log_up_bytes`, `log_down_bytes`, `log_pkts`) |

## 3. Hypotheses and decision rules

**Per domain and seed:**
- verified-benign FPR at T0;
- false alerts;
- attack-window recall;
- entity recall (an entity is a source with ≥ 5 attack windows);
- detection delay;
- precision.

**Aggregation:**
- **per network:** the mean over its domains and seeds;
- **"on k of 4 networks"** always refers to these network means.

**H3 (primary): detection utility of B2 against B0, at each model's own T0 (Q2).** SUPPORTED
(development) if all three hold:
1. attack-window recall rises by ≥ 0.05 (absolute) on ≥ 3 of 4 networks;
2. recall falls by more than 0.05 on no network;
3. verified-benign false alerts are ≤ 1.25 × B0's on every network.

Otherwise NOT SUPPORTED.
- **The 0.05 is operational.** Below it, the improvement is within the seed spread seen in
  Phase 8j.
- **The 1.25 bound** keeps workload from rising more than a quarter.

**H1: adaptive novelty reduces false alerts from benign destination churn.** SUPPORTED if:
- on the networks where B0's evaluation FPR exceeds 2α (on Phase 8j: NF-UNSW and NF-ToN-IoT),
  B2's FPR is lower on both and at least 20 % lower on one;
- **and** B2 does not exceed 2α where B0 did not.

**Secondary measure of H1:** the share of false alerts in windows that are novel under A0 but not
under A3.

**H2: guarded memory resists contamination (development, mechanism).**
- **Synthetic injection (stated as synthetic).** One benign host per domain beacons to a fresh
  destination every 1 min, 10 min or 1 h from the start of evaluation. Two variants: a single
  host, and two hosts beaconing to the same destination.
- **Measured:** the share of beacon windows that stay novel; the time to acceptance; the score
  change at the frozen T0 of B2.
- **Real:** the share of the evaluation attackers' destinations promoted under A1 vs A3, and
  recall in their windows.
- **SUPPORTED if all hold:**
  - under A3, ≥ 95 % of single-host beacon windows stay novel through the evaluation;
  - under A1, ≤ 5 % stay novel;
  - A3 promotes ≥ 50 % of the benign post-freeze destinations that A1 learns, by the end of
    evaluation. That is the adaptation benefit; refusing all adaptation fails this.
- **Two-host beaconing is reported as the known limit** of the rule.
- **Negative controls:** fully frozen memory (A0) and always-quarantine (nothing promoted after
  the freeze).

**H4 (generalisation).** It is covered by the "≥ 3 of 4 networks" clauses. A gain driven by one
network is reported as such.

**Q1 (representation effect without recalibration), descriptive.** B0's models keep their B0 T0.
The `new_dst_frac` column of the evaluation windows is replaced by the A3 value (`nov_guarded`).
This measures what the representation alone changes.

**Multiplicity:**
- one primary comparison (B2 vs B0);
- B1 vs B0 is secondary;
- everything else is exploratory and marked as such.

**Selection rule:**
- if B2 meets H3, B2 is the candidate, unless B1 also meets H3 and B2 does not beat B1 by ≥ 0.05
  recall on ≥ 3 networks; then the simpler B1 is the candidate;
- if neither meets H3, there is no candidate (NO-GO). B0 stays.

## 4. Uncertainty

- **Per domain:**
  - a paired host-cluster bootstrap of the FPR and recall differences: hosts resampled, the same
    resample for both models, B = 2,000, seed 8;
  - one-sided 95 % bounds.
- **Across networks:** only sign counts (4 units). No p-value is claimed. With 4 networks the
  smallest exact one-sided sign-test p is 1/16.
- **Attack entities and episodes per domain are few.** Entity-level results are counts with no
  interval.

## 5. Temporal generalisation (descriptive)

- **Calibration age:** FPR and recall by calibration-age bin (0–1, 1–6, 6–24, 24–72, > 72 h).
- **Hosts:** hosts seen in calibration vs hosts first seen after it, for B0, B2 and B1u.

## 6. Data roles and leakage controls

- **No future information.**
  - Every novelty value comes from strictly earlier windows.
  - Calibration exclusions use calibration-period labels only (P1x), and apply only before the
    freeze.
  - No feature or rule uses scores or labels.
- **No threshold uses evaluation data.**
- **The Phase 8j artifacts are reused read-only.** New outputs go to
  `data/derived/phase8m/` and `reports/phase8m/`, and existing reports are never overwritten.

## 7. Resources

- **Novelty build:** one streaming pass over the four networks' flows (about 70 M flows), under
  `run_capped` (3.4 GiB).
- **Training:**
  - 4 source sets × 3 seeds × 4 trained variants (B1, B2, B1u, and the 2 ablations sharing runs
    where possible);
  - B0 is reused.
- **The estimates are stated before launch, and the runs need the user's authorization**
  (each is above 2 minutes).

## 8. After the candidate is fixed: DEDALE (POST-HOC only)

The fixed candidate, with no retuning, is applied to the consumed DEDALE data:
- false alerts from stale memory;
- whether A1 absorbs attack destinations;
- recall and delay.

These results are labelled POST-HOC retrospective diagnostics. The Phase 8l result stays
unchanged, and no claim of external improvement is made from them.

## 9. Amendments

**Amendment 1** (2026-11-02). Written after the Stage 1 audit and before any Phase 8m comparison.

The audit shows that NF-UNSW-NB15's evaluation false alerts are not novel:
- P(novel | false alert) is 0.7 %;
- benign novelty is 0.0 %.

So the adaptive memory has no mechanism to lower its FPR. NF-BoT-IoT's false alerts are not
novelty-driven either.

**No hypothesis, threshold, feature or parameter is changed.** H1 and H3 stand as written. The
following prediction is recorded so that the outcome is not read as a surprise afterwards:
- H1's clause requiring a lower B2 FPR on NF-UNSW-NB15 is expected to fail, and H1 with it;
- any H3 gain is expected to come mainly from NF-ToN-IoT, where 99 % of false alerts are novel;
- that makes the "≥ 3 of 4 networks" clause unlikely to be met.

**Clarification of H1.** This resolves an ambiguity in the wording; it is not a new rule.
- The H1 set is defined by its rule: every network where B0's evaluation FPR exceeds 2α.
- The parenthetical example named two networks. On the audit's B0 values the set has three:
  NF-ToN-IoT 14.8 %, NF-UNSW-NB15 3.7 % and NF-BoT-IoT 11.9 %. NF-CIC is at 1.29 %.
- "Lower on both" therefore reads "lower on every network in the set".
- NF-BoT-IoT has only 620 benign evaluation windows, so its FPR is reported with that caveat.
