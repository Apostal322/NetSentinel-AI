# Phase 8h audit trail

How the protocol, the code, the runs and the first look at results were ordered. Times are
local (UTC+3) on 2026-10-29, from git commit times and output file times.

## 1. Chronology

| time | event | commit / artifact |
|---|---|---|
| 08:48 | Research audit and pre-registration (H1a, H1b, H2, H3) committed before any analysis | `6de0a47` |
| 08:55 | NF-CIC development windows built. **Amendment A1**: web-attack day 02-22 made secondary (victim-side labels); H3 comparator made operational; attacking-entity windows defined | `6fbb494` |
| about 09:00 | Timing smoke runs. IoT-23 34-1, seed 0: per-model T0 window recall was printed (B-raw 0.999, B-loc 0.997, N-dis 0.315, B-lr 0.989). NF-CIC 02-16 at a 20k cap: only timing was printed | `reports/phase8h/smoke/` (not committed) |
| 09:05 | **Amendment A2**: domains without label-benign windows (34-1, 8-1, …) leave H1 and stay in H3. Harness committed | `4476fc8` |
| 09:07 | Registered grid started with code `4476fc8` | `reports/phase8h/run.status` (overwritten later; start time recorded in the A3 commit context) |
| 09:08 | Decision-rule script committed, before any result was inspected | `4b60e3a` |
| 09:10–09:29 | Independent read-only code review (3 reviewers, 2 skeptics per finding), blind to results | workflow `wf_3eab0957-27b` |
| 09:32 | **Amendment A3**: review fixes and disclosures. Grid still running | `68cc563` |
| 09:43 | Registered grid finished (35.5 min, peak 1.78 GB) | `reports/phase8h/lodo/` |
| 09:45–09:58 | Screening sensitivity check: 7 of 10 folds change one feature under strict screening | `1912cae`, `reports/phase8h/screen_check.json` |
| 10:05–10:22 | Corrective runs required by A3: B-rz with the registered T1 (`lodo_h2/`) and N-dis with strict screening (`lodo_ndis_strict/`) | — |
| **10:23** | **First inspection of registered results** (`analyze.py`) | `reports/phase8h/analysis.json` |
| 10:24 | Registered results committed | `26300a2` |
| 10:27 onward | Exploratory work: figures, ablations, calibration-size study | `9b589a9` and later |

## 2. Correction to amendment A2's wording

A2 states that the timing smoke run's outputs were not used and that "no comparison between
methods was looked at". That is **inaccurate**:
- the 34-1 smoke output printed the four supervised models' T0 window recall, one seed, at
  the registered cap;
- nothing in A2 depended on those numbers, which concerned the absence of label-benign
  windows on 34-1.

**Exposure.**
- 34-1 is not an H1 domain.
- In H3 it is one of nine domains. On 34-1 all components detected the single attacker, and
  its H3 difference is 0.0.
- No decision rule, domain set or method was changed after that output.

The correction is recorded here rather than by editing A2, which keeps its original text.

## 3. Independent code review: the 8 surviving findings

The review ran blind to results, before the first inspection.

| # | finding | fixed? | protocol affected | fix timing | regression test |
|---|---|---|---|---|---|
| 1 | H2 unit set included the secondary domain 02-22 (statistics lens) | yes: `analyze.py` excludes secondary domains | yes: H2 units | before inspection (A3) | `tests/unit/test_phase8h_stats.py::test_h2_units_exclude_secondary` |
| 2 | T1 floored at T0 (T1 = max(q90, T0)), not the registered bound (leakage lens) | yes: T1 = q90; B-rz re-run (`lodo_h2/`) | yes: H2 primary | before inspection (A3) | `test_phase8h_stats.py::test_t1_is_the_bootstrap_bound_not_floored` |
| 3 | Seed averaging fell back to seed 0 when a seed had None (leakage lens) | yes: means recomputed from per-seed results | secondary metrics only (delays) | before inspection (A3) | `test_phase8h_stats.py::test_seed_mean_ignores_missing_values` |
| 4 | B-loc arm of H2 cannot cover benign-only units (leakage lens) | disclosed, not fixed | secondary arm only | A3 | — |
| 5 | Screening used clean calibration windows of attacking entities too (leakage lens) | yes: strict screening re-run (`lodo_ndis_strict/`); 7 of 10 folds changed one feature | yes: H1b | before inspection (A3) | `test_phase8h_stats.py::test_strict_screening_drops_attacking_entities` |
| 6 | `mean_dict` seed fallback (metrics lens) | duplicate of 3 | — | — | — |
| 7 | T1 clamp (metrics lens) | duplicate of 2 | — | — | — |
| 8 | Micro PR-AUC and ROC-AUC not computed (metrics lens) | disclosed, not fixed: scores are not stored | descriptive only | A3 | — |

The six refuted claims (scaler fitted on the hold-out, 02-22 as a training source, cap
stratification, polars join order, block definition, oracle threshold on small benign sets)
needed no change. Their rebuttals are in the workflow journal.

## 4. Other deviations recorded after the first inspection

- **Score calibration** (Brier score, ECE) of LightGBM probabilities was pre-registered as a
  separately reported secondary analysis. It was **not computed**, because scores are not
  stored. Not evaluated.
- **F-learn** (logistic stacking) was pre-registered as exploratory. **Not run**: it needs
  nested out-of-fold scores on the source domains. Not evaluated.
- **Exploratory interruption.** The exploratory batch (ablations, calibration size) was
  interrupted by a session end after two ablations had completed. Both have complete outputs
  (32 files, 3 seeds per attack fold). The remaining runs were resumed into `*.partial`
  directories, which are renamed only on a clean exit.

## 5. Classification of every Phase 8h result

| result | class |
|---|---|
| H1a, H1b, H2, H3 decisions | registered tests on development data → **exploratory [E]** (all data inspected in earlier phases) |
| ablations, calibration size, cross-domain diagnostics | **exploratory, post hoc** |
| reconciliation of exceedance figures | reporting audit |
| nothing in Phase 8h | **confirmatory** (no fresh data) |
