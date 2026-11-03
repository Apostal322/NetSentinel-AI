# Phase 8n final report: training stability, robustness and detection

**Question.** Can the LightGBM detector be made less fragile to reasonable training perturbations,
while keeping its attack sensitivity and false-alert control across networks?

**Answer on development data: partly.**
- **The fragility is explained:**
  - dependence on the *information* in `new_dst_frac`;
  - whole-entity flips on single-attacker days when the training data change.
- **A 5-member seed ensemble (M2)** removes those flips, and that result replicated with fresh
  randomness.
- **M2 does not raise detection everywhere,** and it cannot be confirmed independently: no eligible
  fresh network exists.

## 1. Repository state

- **Start:** `80c0b5c` (= `origin/main`), with a clean tree.
- **Phase 8n local commits:**

  | commit | contents |
  |---|---|
  | `99db028` | gap register, Experiment A registered |
  | `6365116` | Experiment A results, amendment 1 |
  | `5fd46ab` | Experiment C, review, amendment 2 |
  | following commit | replication, final docs |

- **Nothing pushed; no release.** CI could not be checked (`gh` not installed).
- **Runs,** all authorized by the user, sequential, under `run_capped` (3.4 GiB), CPU only:

  | run | time | peak | outcome |
  |---|---|---|---|
  | Experiment A | 35 min | 1.75 GiB | 597 model × domain runs |
  | Experiment C | 40 min | 1.81 GiB | 216 runs |
  | replication | 31 min | 1.76 GiB | 162 runs |

- **Earlier work is preserved:** no Phase 8j–8m file or frozen result was changed. The one
  exception is an editorial addendum to the Phase 8m report about its publication status. No new
  data was downloaded.

## 2. Gap closure (GAP_REGISTER.md)

| gap | root cause / finding | evidence | status |
|---|---|---|---|
| G0.1 NF-CIC collapse in retrained variants | learned dependence on the information in `new_dst_frac`, plus all-or-nothing behaviour of single-attacker days | Experiment A: drop/shuffle 9/9 catastrophic focus cases; no-op arms 0/9 | closed |
| G0.2 baseline reproducibility | — | 27/27 P_ref and 54/54 M0 fits identical (same machine) | closed |
| G0.3 ranking vs threshold | the failures are ranking failures. On NF-CIC (FPR ≈ α) this is nearly true by construction | AUC, ranking recall at the benign 99th percentile, T0 per case | closed with a limit |
| G0.4 correlated units | 1 attacker on 02-14 and on 02-16 | entity-level reporting; degenerate intervals marked | documented limit |
| G0.5 P1x needs confirmed calibration labels | protocol assumption (Phase 8j) | — | documented limit |
| G1.1 B0 seed-unstable on 03-02 | the attack cluster sits at the threshold | 03-02 recall 0.06–1.00 for M0 | improved by M2 on fits 0–2 (0.86–1.00); fresh fits 0.14–1.00 |
| G1.2 interaction dependence | the feature's information, not the column layout (the shuffle control is as damaging as the drop) | Experiment A | closed; the source-side reason is open |
| G1.4 no worst-case criterion | entity rule plus RP3/RP4 (window collapses) | amendments 1–2 | closed |
| G1.5 no independent confirmation | DEDALE and NF-BoT consumed; AIT/UWF ineligible | FREEZE_CANDIDATE.md | documented limit |
| G2.1–G2.3 | Phase 8m publication note; ledger and README entries; deployed loaders already refuse schema or hash mismatches | — | closed |

## 3. Training stability

- **What causes unstable predictions?**
  - **Not optimizer randomness alone:** 0 flips at r = 0, the only clean contrast.
  - **Changes of the training data do:** subsample draw, source-host bootstrap, network weights.
    Under these, 7 of 24 single-attacker-day cases flip.
  - **Removing `new_dst_frac`, `log_flows` or `log_dst_ports` also does:** these collapse whole
    networks.
- **Are the NF-CIC failures explained?** Yes.
  - The Phase 8m variants all lost `new_dst_frac` from training.
  - On single-attacker days the attack windows form one dense cluster near the benign tail, which
    a small change of the learned boundary moves across T0 as a block.
- **Did the changes reduce instability?**
  - **M2** (5-member subsample and seed ensemble) did. On the fresh fits, unstable entities fall
    from 11 to 1 at "≥ 1 window" and from 14 to 10 at "≥ 20 % of windows", and window collapses
    from 1 to 0.
  - **M3** (regularisation) did not hold up on fresh fits.
  - **M1** (bagging over hosts) made it worse. As implemented in the stress regime it is a double
    bootstrap, so this says little about bagging in general.
- **New failures:** M2's worst fit on 03-02 is 0.14 on the fresh fits, and NF-ToN/NF-BoT recall
  dips slightly.

## 4. ML details

- **Models trained:** about 975 LightGBM model × domain runs across the three runs.
  - Experiment A: 23 arms × 3 replicates × 4 source sets.
  - Experiment C: M0–M3 × 2 regimes × 3 replicates.
  - Replication: M0, M2, M3 × 2 regimes × 3 fresh replicates.
- **Configuration:** Phase 8i LightGBM; the 12 registered features; leave-one-network-out
  sources; P1x calibration; T0 at α = 1 %.
- **Per-network results over the fresh replication fits,** M0 → M2:

  | network | recall | false alerts |
  |---|---|---|
  | NF-CIC | 0.567 → 0.656 | 1,359 → 1,383 |
  | NF-UNSW | 0.870 → 0.919 | 505 → 529 |
  | NF-ToN | 0.614 → 0.593 | 1,080 → 1,120 |
  | NF-BoT | 0.898 → 0.869 | 91 → 61 |

- **Worst-entity behaviour:** M2 detects the NF-CIC 02-16 entity at 0.96 window recall in 12/12
  fits. M0's recall on it falls below 0.3 in 5 of 12 fits, and to 0 in 2.
- **Coverage limit:** 19 web-attack entities on 02-22 and 1 DDoS source on 02-20 are missed by
  every model in every fit.
- **Detection delay:** lower for M2 in the Experiment C fits, where it is defined (MODEL_COMPARISON.md); not
  recomputed for the replication.
- **Cost:** M2 = 5× B0 (median fit 37 s vs 7.9 s per source set).

## 5. Scientific verdicts

| hypothesis / decision | label | verdict |
|---|---|---|
| HA1: training-data perturbations alone cause catastrophic failures (≥ 3/9) | registered development diagnostic | **supported at the threshold**, as registered. The evidence is one entity-day, partly seed-confounded |
| HA2: losing `new_dst_frac` information is catastrophic, while no-op changes are not | same | **supported** (9/9 vs 0/9) |
| HA3: other removals and mechanism | descriptive | `log_flows` and `log_dst_ports` collapse whole networks; the focus failures are ranking failures |
| Amendment 1 selection (G1–G3) | registered development | **M2 selected** (M3 also passed). The review showed that G3 rested on one already-seen fit |
| Amendment 2 replication (RP1–RP4) | registered development | **all met: replicated development GO for M2** (RP3 by a margin of 1) |
| independent confirmation | — | **not evaluable** (no eligible fresh network) |

## 6. Deployment readiness

| decision | verdict |
|---|---|
| research usefulness | **GO.** The mechanism of refit fragility is documented and controlled, with a reusable perturbation harness |
| development improvement | **GO (replicated, narrow).** M2 removes whole-entity flips on single-attacker days; recall is mixed across networks |
| independent confirmation | **NOT EVALUABLE.** No eligible untouched network |
| deployment | **NO-GO.** The deployed detector is unchanged. M2 is frozen as a candidate (FREEZE_CANDIDATE.md) |

## 7. Portfolio achievements (verified)

- **Diagnosed a refit collapse from 0.99 to 0 recall with a 23-arm controlled factorial**
  (≈ 600 model × domain runs, every reference fit reproducing the historical baseline bit for bit).
  It separated feature-information dependence from training-data sensitivity and from ranking or
  threshold effects.
- **Pre-registered, tested and replicated a stability fix.** A 5-member seed ensemble cut unstable
  attack-entity outcomes from 11 to 1 (fresh replicates), with false alerts within a registered
  1.25× budget on all four networks.
- **Corrected an initial positive result after an independent review.** The first G3 pass rested on
  one previously seen fit. A fresh-randomness replication was registered and run, and negative
  side effects are reported (NF-ToN/NF-BoT recall −0.02/−0.03).

**Suggested descriptions:**
- **GitHub (one line):** "Leakage-controlled ML research on a network-intrusion detector:
  pre-registered experiments, reproducible baselines, failure analysis and a replicated training
  stability fix, with negative results reported."
- **ML Engineer résumé:** "Built a reproducible LightGBM evaluation harness (bit-exact baseline
  reproduction, memory-capped runs, atomic outputs, provenance) and ran ≈ 1,000 controlled model ×
  domain experiments to isolate the cause of a refit collapse. Shipped a 5-model ensemble that
  removed whole-entity detection flips in a replicated test."
- **ML Research Engineer résumé:** "Designed a factorial perturbation study separating feature,
  data-sampling and threshold effects. Pre-registered decision rules, ran an independent review that
  overturned an over-confident result, and replicated the fix on fresh randomness; reported
  development-only status because no independent test set exists."
- **Do not claim:** production-grade IDS performance, cross-network generalisation, or a new
  algorithm.

## 8. Remaining problems

1. **No independent confirmation.** Every Phase 8n number comes from 4 consumed development
   networks, with selection made on them. Resolving this needs a fresh eligible network (Phase 8l
   criteria), which public data does not currently offer.
2. **`new_dst_frac` is both the main detection signal and the main false-alert source.** Its
   frozen-memory semantics differ between calibration and evaluation (Phase 8m). NF-ToN-IoT's
   evaluation FPR stays at about 15 % for every model. Fixing this needs a representation that
   keeps the attack information without the staleness, which Phase 8m showed is hard.
3. **Correlated units.** 52 of 75 entities come from one network, and 2 key days have one attacker
   each. Gains are counts with no interval. Resolving this needs more independent attack entities,
   meaning more networks and campaigns.

## 9. Next experiments (at most 3; none started)

1. **A source-side ablation of the `new_dst_frac` dependence.** Retrain with the feature's
   calibration-vs-evaluation semantics aligned in the *training* windows (frozen-memory semantics
   in the sources too), to test whether the dependence is a train/eval semantic mismatch.
   Development data only, about 1 h.
2. **An ensemble-size and cost curve** (K = 2, 3, 5, 10) under the amendment 2 protocol, with
   fresh seeds, to find the smallest K that keeps RP2–RP4.
3. **A desk search for an independent eligible network** (no download until approved), to test the
   frozen M2 and B0 side by side.

## Editorial addendum (2026-11-03, Phase 8o)

Section 1 says "Nothing pushed; no release". That was true when the report was written. The user
then authorized a push, and `80c0b5c..1ea3243` has been on `origin/main` since 2026-11-03. No
tag or release exists. No result, verdict or number in this report is changed by this note.
