# Phase 8n pre-registration

**Written:** 2026-11-03.
- **Seen beforehand:** the Phase 8m results and the first Phase 8n diagnostic (GAP_REGISTER.md).
- **Not yet run:** no Experiment A perturbation, apart from the P_ref reproduction check on
  NF-CIC seed 0.

**Status: REGISTERED DEVELOPMENT DIAGNOSTIC.**
- The four development networks are consumed.
- Nothing here is independent confirmation, and no model is selected by Experiment A.
- **Experiments B and C** (candidate training changes and the GO/NO-GO rule) are registered as an
  amendment *after* Experiment A's results and *before* any candidate is trained. They depend on
  the mechanism A finds, and fixing them first would be guessing.

## Experiment A: isolating refit fragility

**Code:** `scripts/phase8n/fragility.py` (fits) and `scripts/phase8n/analyze_fragility.py`
(metrics).

**Protocol: Phase 8j P1x, unchanged.**
- B-raw LightGBM: 200 trees, 15 leaves, learning rate 0.05, `min_child_samples` 20, `subsample`
  and `colsample_bytree` 0.8, `n_jobs` 2 (`scripts/phase8i/common.py` `LGB`).
- Network-balanced and class-balanced weights; 50,000-window cap per source domain.
- Leave-one-network-out sources; P1x calibration; T0 = conformal rank at α = 1 % on the last 30 %
  of calibration slots.

**Replicates r ∈ {0, 1, 2}.** Each replicate fixes the LightGBM seed and the subsample seed
(P_ref: both = r).

| factor | arm | what changes | information |
|---|---|---|---|
| reference | P_ref | nothing; must reproduce the Phase 8j B0 scores (max \|Δ\| recorded) | — |
| A2 no-op | `A2_reverse_columns`, `A2_constant_column`, `A2_sqrt_new_dst_frac` | column order; an extra constant column; a monotone transform | preserved |
| A3 substitution | Q1 from Phase 8m (reused) | the B0 model; novelty input replaced, no refit | changed input only |
| A4 removal | `A4_drop_<f>` for each of the 12 features | one column removed, then refit | one feature lost |
| A4 control | `A4_shuffle_new_dst_frac` | column kept, values permuted within each training domain | lost, layout kept |
| A5 randomness | `A5_lgb_seed` (LightGBM seed 100 + r, sample 0); `A5_sample_seed` (LightGBM 0, sample 100 + r); `A5_host_bootstrap` (source hosts resampled with replacement, whole hosts) | randomness only | preserved |
| A6 weighting | `A6_double_<net>`: one source network's weight × 2 | domain influence | preserved |

**Measures** (per domain and replicate, from saved scores):
- T0;
- window recall;
- verified-benign FPR and false alerts;
- ROC AUC;
- ranking recall at the benign 99th percentile (an oracle quantity, used only to separate ranking
  from threshold effects);
- entity recall and undetected entities (sources with ≥ 5 attack windows);
- median delay;
- Spearman correlation of the scores with P_ref.

**Definitions, fixed now:**
- **Catastrophic failure:**
  - on one domain and replicate, window recall falls by ≥ 0.5 against P_ref of the same
    replicate; **or**
  - an entity that P_ref detects is not detected at all.
- **Mechanism of a recall failure:** *ranking* if the ranking recall at the benign 99th percentile
  also falls by ≥ 0.5; otherwise *threshold*.

**Diagnostic hypotheses.** Focus cases: NF-CIC 02-14, 02-16 and 02-21, 3 replicates each, so 9
cases per arm.

| hypothesis | statement | reading |
|---|---|---|
| HA1, generic fragility | the information-preserving arms (A2, A5, A6) cause catastrophic failures in ≥ 3 of the 9 focus cases per arm | supported if ≥ 1 such arm reaches 3 |
| HA2, feature-specific | removing `new_dst_frac` (`A4_drop_new_dst_frac` **and** `A4_shuffle_new_dst_frac`) causes catastrophic failure in ≥ 6 of 9 focus cases, while no A2 arm exceeds 2 | supported / not supported |
| HA3, descriptive | which other single-feature removals cause catastrophic focus failures, and the dominant mechanism (ranking or threshold) | descriptive |

**How the results will be used:**
- **HA1 supported:** training stability (seed and sample aggregation, regularisation) is the
  primary target of Experiment B.
- **HA2 supported and HA1 not:** the problem is feature dependence. Experiment B then targets the
  model's reliance on interactions involving that feature, for example feature-bagged ensembles
  or regularisation of split usage.
- **Both, or neither:** reported as found. Experiment B is then designed for the observed
  mechanism.

**Statistical units and their limits:**
- A day with 1 attacker entity is 1 unit, whatever its window count.
- Focus-day results are reported per case (domain × replicate), with no interval.
- Network means are descriptive.

**Resources:**
- 23 arms × 3 replicates × 4 source sets, ≈ 270 LightGBM fits plus scoring;
- measured ≈ 7 s per fit and 1.5 s per scored domain;
- estimate 45–75 min, peak ≈ 1.6–2.2 GiB under `run_capped` (3.4 GiB);
- CPU only, sequential;
- run only after the user authorizes it (CLAUDE.md: training > 2 min).

## Amendments

None yet.
