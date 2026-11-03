# Phase 8n Experiment A: why the detector breaks when it is refitted

**Sources:**
- `reports/phase8n/fragility_analysis.json`, from `scripts/phase8n/analyze_fragility.py`;
- the fits from `scripts/phase8n/fragility.py`: 597 model × domain runs, 35 min, peak 1.79 GiB,
  authorized by the user on 2026-11-03;
- the protocol in PREREGISTRATION.md, Experiment A.

**Label:** REGISTERED DEVELOPMENT DIAGNOSTIC, on consumed development networks. No model is
selected from it.

**Reproduction.** All 27 P_ref fits (9 domains × 3 replicates) reproduce the Phase 8j B0 scores
exactly (max |Δ| = 0.0).

## Registered hypotheses

The focus cases are NF-CIC 02-14, 02-16 and 02-21, 3 replicates each (9 per arm). A case is
*catastrophic* when window recall falls by ≥ 0.5 against P_ref, or a detected entity is lost.

| hypothesis | result | evidence |
|---|---|---|
| HA2: removing `new_dst_frac` is catastrophic (≥ 6/9) while no no-op arm exceeds 2 | **SUPPORTED** | `A4_drop_new_dst_frac` 9/9 and `A4_shuffle_new_dst_frac` 9/9 (recall 0.00 in every case); the 3 A2 arms 0/9 |
| HA1: an information-preserving arm is catastrophic in ≥ 3/9 | **SUPPORTED, at the threshold, as registered** | `A5_host_bootstrap` 3/9; `A5_sample_seed` 2/9; `A6_double_nfton` 1/9; `A6_double_nfunsw` 1/9; `A5_lgb_seed` 0/9; A2 0/9. All 3 bootstrap cases are the *same* 02-16 entity, which the pre-registration counts as one unit, and 2 of the 3 are confounded by seed choice (point 2), so the evidence is one entity-day |
| HA3: other removals and mechanism (descriptive) | see below | all recall failures in the focus cases are *ranking* failures except where noted |

## What breaks and how

**1. The pipeline itself is sound.**
- A constant column and a monotone transform of `new_dst_frac` give bit-identical scores
  (Spearman 1.000).
- Reversing the column order changes the scores slightly (Spearman 0.98). The cause is
  `colsample_bytree`, which samples columns by position. No case becomes catastrophic.

**2. Optimizer randomness alone gave no flips, but that rests on one clean replicate.**
- The LightGBM-seed arm gives 0 catastrophic cases in 27 domain-replicates, and the focus days
  stay at 0.96–1.00.
- **The arms were not single-factor for r = 1 and 2** (corrected after review):
  - `A5_lgb_seed` uses seeds (100 + r, 0) and `A5_sample_seed` (0, 100 + r), yet both are compared
    with P_ref at (r, r);
  - `A5_host_bootstrap` uses (0, 0) for every r.
- **A clean one-factor contrast exists only at r = 0:** LightGBM seed only, 0 flips; subsample
  seed only, 1 flip (02-16).

**3. Small changes of the training *data* flip whole attack entities.** Focus-day window recall
per replicate:

| arm | 02-14 | 02-16 | 02-21 |
|---|---|---|---|
| P_ref | 1.00 / 0.995 / 0.995 | 0.963 / 0.963 / 0.963 | 0.998 / 0.997 / 0.979 |
| A5 subsample seed | 1.00 / **0.022** / 1.00 | **0.333** / 0.963 / 0.926 | 0.998 / 0.985 / 0.982 |
| A5 host bootstrap | 1.00 / 1.00 / 1.00 | **0.074 / 0.185 / 0.000** | 0.997 / 0.998 / 0.737 |
| A6 NF-ToN weight × 2 | 1.00 / **0.011** / 0.995 | 0.963 / 0.963 / 0.963 | 0.997 / 0.966 / 0.968 |

- Each of 02-14 and 02-16 has **one attacker entity**, whose windows are homogeneous (brute
  force; DoS).
- So recall on these days is close to all-or-nothing. The whole cluster of attack windows sits
  either above or below the benign tail.
- Every one of these failures is classed *ranking* by the registered rule: the ranking recall at
  the benign 99th percentile falls with it.
  - On NF-CIC the FPR is close to α, so T0 is close to the benign 99th percentile. A recall
    failure there is almost necessarily classed "ranking" (REVIEW).
- **The overall score order changes little.** Mean Spearman with P_ref is 0.90–0.98 across the
  randomness arms. The host bootstrap goes down to 0.78 overall and 0.85–0.93 on the focus days,
  the very failing cases.
- These are not many independent misses. They are one entity, observed once per day.

**4. Detection depends on a few features, and which ones depends on the network.**

| feature removed | catastrophic cases (all domains × reps) | network recall P_ref → removed |
|---|---|---|
| `new_dst_frac` (drop) | 24 | NF-CIC 0.581 → 0.004, NF-ToN 0.609 → 0.170, NF-BoT 0.883 → 0.428, NF-UNSW 0.971 → 0.732 |
| `new_dst_frac` (values shuffled) | 26 | NF-CIC 0.005, NF-UNSW 0.460, NF-ToN 0.160, NF-BoT 0.423 |
| `log_flows` | 20 | NF-CIC 0.072, NF-BoT 0.183, NF-UNSW 0.623, NF-ToN 0.410 |
| `log_dst_ports` | 19 | **NF-UNSW 0.971 → 0.027** (a *threshold* failure in all 3 reps), NF-CIC 0.259 |
| `udp_share` | 5 | NF-ToN 0.392 |
| every other single feature | 0–3 | network-mean changes ≤ 0.17, but some single-domain collapses (below) |

- **Network means hide single-domain collapses** (corrected after review):
  - `A4_drop_log_dst_hosts` collapses 02-16 in 2 of 3 replicates;
  - `A4_drop_log_dst_ports` collapses 02-14 in 3 of 3;
  - removing `log_down_bytes`, `log_pkts`, `no_reply_frac` or `upload_share` collapses 03-02 in
    replicate 0, where B0 itself is near its threshold.
- **The shuffle control removes the information but keeps the column.** It is as damaging as
  dropping the column, so the effect is the information in `new_dst_frac`, not the change of
  column count.
- **NF-CIC 02-16 shows this is not simple.** Its attack windows have `new_dst_frac` = 0, yet
  without the feature the model misses them. In B0 the attack score there comes through `rst_frac`
  (GAP_REGISTER contributions). The learned *interactions* that involve `new_dst_frac` carry the
  detection, not only its value in the attack window.

**5. Entity-level view.** Of 75 entities (225 entity-replicate cases):

| arm | entity-replicate cases undetected |
|---|---|
| P_ref | 60 |
| LightGBM-seed arm | 60 |
| subsample-seed arm | 60 |
| host bootstrap | 69 |
| `new_dst_frac` dropped | 170 |

So the randomness arms mostly *move* detections between entities rather than lose them in total.
The exception is the host bootstrap, which loses 9 more.

## What this explains, and what it does not

- **The Phase 8m NF-CIC collapse is explained:**
  - every Phase 8m variant that lost `new_dst_frac` from training lost its NF-CIC detections, as
    `A4_drop_new_dst_frac` does here;
  - Q1 kept them because the B0 model was not refitted.
  - It is a feature-information dependence, amplified by entity-level all-or-nothing behaviour on
    single-attacker days.
- **Separately, B0 is fragile to its training sample.**
  - Under the four data-perturbation arms (subsample seed, host bootstrap, ×2 weight of NF-ToN or
    NF-UNSW), 7 of 24 single-attacker-day cases (29 %) flip.
  - The 03-02 seed instability (GAP_REGISTER G1.1) is the same phenomenon, with the cluster near
    the threshold.
- **Not established:**
  - *why* the source networks (NF-UNSW + NF-ToN for an NF-CIC target) teach this particular
    interaction;
  - whether a model that does *not* depend on it could still detect these attacks.
  - Feature attributions are not causal evidence.
