# Phase 8v: registered model comparison and failure analysis

**Status:** REGISTERED (PREREGISTRATION, commit `e5c08a6`, before any registered fit).

**Sources:**
- registered: `reports/phase8v/evaluation_screening.json` (+ `.sha256`; commit `f43ac20`),
  `fit_ledger.json`;
- EXPLORATORY: `reports/phase8v/posthoc.json`.

**Run:**
- 16 of the 24 approved LightGBM fits, all at seed 1060; each variant started from a clean
  commit;
- 637 s in the ledger (this includes assembling the training matrices);
- peak memory: 1.47 GiB resident in the training process (ledger); 1.9 GiB for the whole capped
  process tree (runner console output, not saved in a report);
- no neural run.

**Data:** development networks only, already consumed. Deployable-memory features. Exact partial
AUC.

## 1. Registered verdict: no candidate passes screening

| candidate | Δ partial AUC, NF-UNSW + NF-ToN mean (need ≥ +0.02) | Δ macro (need ≥ 0) | guardrails | screening |
|---|---|---|---|---|
| `FLOW` | +0.004 | +0.026 | 4 of 4 fail | **fail** |
| `TIME` | **+0.117** | +0.094 | as-calibrated FPR and entities missed fail | **fail** |
| `BIDIR` | +0.035 | +0.060 | as-calibrated FPR and entities missed fail | **fail** |
| `INV` | −0.006 | −0.163 | 4 of 4 fail | **fail** |

**No replication was run:** the registered rule stops when no candidate passes. 8 approved fits
were left unused.

| gate | verdict |
|---|---|
| G0 telemetry availability | **COMPLETE** (flow records; no packet data) |
| G1 representation information (`FLOW`) | **NOT SUPPORTED** |
| G2 temporal features (`TIME`; H1, H3) | **NOT SUPPORTED** by the registered rule. Its ranking criteria were met and its operational guardrails were not (§ 3) |
| G3 bidirectional features (`BIDIR`; H2) | **NOT SUPPORTED** |
| G4 sequence learning (H4) | **NOT ATTEMPTED** |
| G5 cross-network generalisation (H5) | **NOT SUPPORTED** |
| model development | **DEVELOPMENT NO-GO** |
| independent validation | **NOT READY** |
| deployment | **NO-GO** |

## 2. Results (single member, seed 1060, vs the frozen member with the same seed)

**Ranking at the retrospective 1 % FPR** (each cell is exact partial AUC / recall):

| model | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | macro | ROC-AUC |
|---|---|---|---|---|---|---|
| frozen member | 0.331 / 0.364 | 0.006 / 0.017 | 0.008 / 0.013 | 0.671 / 0.671 | 0.254 / 0.266 | 0.847 |
| `FLOW` | 0.160 / 0.171 | 0.006 / 0.013 | 0.017 / 0.120 | 0.938 / 0.938 | 0.280 / 0.311 | 0.790 |
| `TIME` | 0.444 / 0.465 | **0.001 / 0.002** | **0.247 / 0.345** | 0.700 / 0.744 | 0.348 / 0.389 | 0.850 |
| `BIDIR` | 0.289 / 0.332 | 0.002 / 0.004 | 0.082 / 0.147 | 0.883 / 0.883 | 0.314 / 0.342 | 0.858 |
| `INV` | 0.013 / 0.043 | 0.000 / 0.000 | 0.001 / 0.002 | 0.352 / 0.352 | 0.091 / 0.099 | 0.569 |

**As calibrated on the benign hold-out (CAL_T):**

| model | macro recall | FPR: NF-CIC / NF-UNSW / NF-ToN / NF-BoT | false alerts per hour (same order) | entities missed |
|---|---|---|---|---|
| frozen member | 0.611 | 1.1 % / 4.0 % / 15.9 % / 18.5 % | 289 / 54 / 16 / 0.3 | 8 |
| `FLOW` | 0.573 | 1.4 % / 3.7 % / 23.6 % / 10.8 % | 348 / 49 / 24 / 0.2 | 17 |
| `TIME` | 0.693 | 1.5 % / 3.4 % / **24.3 %** / **31.0 %** | 375 / 45 / 25 / 0.5 | 11 |
| `BIDIR` | 0.591 | 1.3 % / 3.3 % / 23.6 % / 6.9 % | 324 / 44 / 24 / 0.1 | 17 |
| `INV` | 0.330 | 1.4 % / 3.4 % / 24.4 % / 7.4 % | 342 / 45 / 25 / 0.1 | 31 |

**No hold-out threshold reaches the 1 % target** on NF-UNSW, NF-ToN or NF-BoT for any model, as
in Phases 8s–8u.

## 3. What happened (EXPLORATORY; single seed)

**`TIME` moved NF-ToN for the first time in this research line.**
- Partial AUC 0.008 → 0.247; recall at 1 % FPR 0.013 → 0.345. The baseline's seed SD there is
  about 0.0025.
- **The gain sits in two attack labels:**

  | NF-ToN label | windows | baseline recall | `TIME` recall |
  |---|---|---|---|
  | `password` | 3,203 | 0.020 | 0.446 |
  | `xss` | 1,847 | 0.004 | 0.271 |
  | `backdoor`, `mitm`, `ransomware` | 548 | 0.000 | 0.000 |

- NF-ToN attackers detected at ≥ 20 % of their windows: 0 → 4 of 10; missed entirely: 6 → 3.
- The added columns carry 8–19 % of the models' split gain.
  - In three of the four models the largest added contributor is the host's activity over the
    previous two minutes (`prev4_mean_log_flows`).
  - In the model that scores NF-ToN it is `gap_cv`, at 3 % of the gain. That model's added columns
    carry 8 % in total, so a small share of the splits produced the large NF-ToN change.

**Why `TIME` still fails the registered rule:**
- **As calibrated, its FPR rises** on NF-ToN (15.9 % → 24.3 %) and NF-BoT (18.5 % → 31.0 %). The
  limit was baseline + 1 point.
- **It misses three more entities as calibrated** (8 → 11; the limit was + 2). On NF-CIC 02-20,
  entities missed go from 1 to 5 of 10 at the retrospective threshold.
- **NF-UNSW gets worse** (partial AUC 0.006 → 0.001).

So the ranking improved on one hard network while calibration and entity coverage degraded. The
guardrails exist for exactly that pattern.

**NF-UNSW did not improve under any candidate, and got worse.**
- Partial AUC stayed at the floor or below it: 0.006 → 0.000–0.006 (`TIME` 0.001).
- **As calibrated, its recall collapsed under every candidate:** 0.706 → 0.463 (`TIME`), 0.327
  (`FLOW`), 0.225 (`BIDIR`), 0.001 (`INV`).
- This matches the exploratory finding. Its attackers are quieter than its benign hosts, and no
  source network can teach that direction. The evidence rests on 4 attacker hosts against 34
  benign hosts, so it is a property of that testbed.
- **Its limit is cross-network shift, not missing information.**

**`FLOW` and `BIDIR` trade networks against each other.**
- `FLOW`: NF-BoT + 0.27; NF-CIC 02-14 − 0.90, where the single SSH brute-force attacker is lost.
- `BIDIR`: NF-BoT + 0.21 and NF-ToN + 0.07; NF-CIC 02-21 − 0.14 and NF-UNSW − 0.004.
- Both miss 17 entities as calibrated, against the baseline's 8.

**`INV` collapses** (macro 0.254 → 0.091; 31 entities missed).
- It drops 5–16 columns per fit, including the volume features wherever the source networks
  disagree.
- That removes most of the signal: NF-CIC 02-14 − 0.90, NF-CIC 02-21 − 0.97, NF-BoT − 0.32.
- **Agreement of direction between two or three source networks is not a usable criterion here.**
  The transferable signal and the conflicting signal are largely the same volume features. And
  the selection cannot see a conflict with the target, which is NF-UNSW's whole problem.

## 3a. Two checks prompted by the independent review (EXPLORATORY; `ton_concentration.json`)

**`TIME`'s NF-ToN gain is volume and host persistence in a few hosts, not new attack evidence.**
- At the retrospective 1 % threshold, **63 % of its true positives come from one attacker host
  and 90 % from three.** Five of the ten attackers stay at ≤ 4 % recall.
- **A single raw feature beats the model on NF-ToN:**

  | score | exact partial AUC on NF-ToN |
  |---|---|
  | `log_flows` alone (already one of the 12 features) | 0.793 |
  | `prev4_mean_log_flows` alone | 0.855 |
  | `TIME` model, trained on NF-CIC and NF-UNSW | 0.247 |
  | frozen member | 0.008 |

  The information was already in the original representation. The transferred model does not use
  the volume direction strongly, because NF-UNSW teaches the opposite one.
- The same context feature is inverted on NF-UNSW (univariate AUC 0.13), where `TIME` got worse.

**The as-calibrated FPR increase on NF-ToN is not specific to any feature family.**
- All four candidates, with disjoint added columns, land at 23.6–24.4 % FPR against the baseline's
  15.9 %.
- Of `TIME`'s 626 new false-alert windows, **511 are shared by all four candidates**, and about
  80 % of each candidate's false alerts come from three benign hosts.
- So that change comes from the pipeline, not from the features. Adding columns changes which
  columns every tree samples (`colsample_bytree` = 0.8), so "same seed" is not a strictly paired
  comparison.
- **Phase 8v has no null control** (for example a permuted or constant added column). Without
  one, no family's effect can be separated from this pipeline effect.

**The deciding guardrail is noisy.**
- NF-BoT's false alerts all come from one host; the baseline's own seeds span 7–19 % FPR there,
  against a tolerance of 1 point.
- Seed 1060 is the baseline's weakest member on NF-CIC and its strongest on NF-BoT.

**Weight of one seed, per network:**
- NF-ToN: + 0.239 is far above the baseline seed SD (0.0024), but that SD is compressed at the
  floor and the candidate's own SD is unknown.
- NF-UNSW: supports only "no improvement".
- NF-CIC (+ 0.113; one day and one host give + 0.687) and NF-BoT: no support.

## 4. What this does and does not establish

- **Established (registered, development):** none of the four representations passes the
  registered screening. Model development is a NO-GO.
- **Observed (exploratory, one seed):** with the temporal columns the transferred model ranks
  NF-ToN's two high-volume attack labels far better, with worse calibration and entity coverage.
  - The evidence points to **volume and host persistence in three hosts** (§ 3a), not to attack
    behaviour newly made visible.
  - It is not established as a real effect: one seed, no null control, no ensemble.
- **Not established:** any improvement on NF-UNSW by any representation.

## 5. Artifacts and reproducibility

- **Ledger:** 16 fits; variant, target, seed, fit time, model SHA-256, git SHA, clean-tree flag
  and UTC time for each.
- **Manifests** (`data/derived/phase8v/manifests/`): columns used and dropped; for `INV` the
  source-side direction table; score hashes.
- **Models:** 350–356 kB each. They were saved with CRLF line endings (amendment V-1). Each one,
  normalised, matches its recorded hash.
- **Scoring speed:** about 49,000 windows per second, including the feature join (research code
  on one machine; not a deployment benchmark).
- **Derived data:** 106 MB under `data/derived/phase8v/` (git-ignored); table hashes in
  `reports/phase8v/build_enriched.json`.
