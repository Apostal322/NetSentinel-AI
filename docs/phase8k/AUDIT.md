# Phase 8k audit: independent review, statistics and reproducibility

**Date:** 2026-11-02. **Before** any fresh data, and before the freeze.

## 1. Independent audit

A separate, read-only reviewer checked:
- the protocol: PREREGISTRATION, RESEARCH_DESIGN, DATASET_INDEPENDENCE, DEVELOPMENT_EXPERIMENTS;
- the code: `confirm_analysis.py`, `dev_experiments.py`, and the Phase 8i/8j functions they
  import;
- the outputs.

It was given the files, not conclusions.

**Checked and found correct:**
- **No leakage.**
  - `decisions()` reads calibration fields only, and the RNG it uses feeds no rule.
  - P1x excludes only calibration-period attackers.
  - The hold-out split uses calibration windows only.
- **Statistics:**
  - Kish effective n, the one-way ANOVA ICC and 30-min session splits;
  - grouped exceedance;
  - the PAC threshold, max(T0, PAC), with abstention when l < 1;
  - the hypergeometric control and the Clopper-Pearson intervals.
- **Numbers:** every development table matches `dev_experiments.json`, including the
  runtime and memory record.
- **Chronology:** M1's circularity is disclosed.

**Findings and dispositions:**

| finding | severity | disposition |
|---|---|---|
| (d) can be unattainable while E1/E2 say K1 is evaluable: a perfect rule has p = 1/C(N, K), e.g. 0.167 at N = 4, K = 2 | blocking | gate **E3** added (discrimination NOT EVALUABLE when 1/C(N, K) > 0.05); (d)'s implied FRR stated with examples |
| The protected run could crash: an accepted unit with no verified-benign windows (bootstrap division by zero); missing seed files (IndexError; 1–1 ties unregistered) | blocking | such units are left out of the bootstrap (as in `pooled`); exactly 3 seed files required, checked before any evaluation field; acceptance is ≥ 2 of 3 seeds; regression tests added |
| Phase 8k M1 dropped Phase 8j's check 4 (block recency) without disclosure | should fix | disclosed with its reason (time-coverage policy vs adequacy decision); recency added as descriptive **K4** (FPR in the first 24 h after the hold-out vs later) |
| Units judged by two standards: NF-CIC days counted as one unit, F2 weeks as several | should fix | **(f)** per-family conditions; registered sensitivity analysis with each family collapsed to one unit; a success that depends on it is labelled "dependent on unit exchangeability" |
| No rule for a single surviving family; bootstrap limits not stated | should fix | verdict labelled "single environment family"; bootstrap limits (families not resampled) stated |
| K3 adequacy judged at T0, not M2's own threshold; one seed without a PAC rank fell back to T0 | should fix | adequacy is now at each rule's own threshold; a seed without a PAC rank uses the hold-out maximum (PAC count 0) |
| (b) counted indeterminate units as accepted | should fix | (b) counts accepted *determinable* units |
| Adequacy label ignores dependence (200 windows ≠ 200 independent observations) | should fix | host-bootstrap interval per unit; borderline units flagged; verdict without them reported as a sensitivity analysis |
| Status claims ahead of the facts ("Done" before the audit file existed) | should fix | corrected: the order of work is updated only as steps complete |
| Weak confirm guards: optional `--families`; proper-subset check; FREEZE.md presence only | should fix | `--families` required; `names <= set(fam)`; FREEZE.md must contain the script's SHA-256 |
| K3 always written; weighting of accepted recall and false alerts per hour unstated; a unit drawn twice reused one host resample; entities taken from a metadata field; unverified facts not marked; dry-run time; NF-ToN grouped exceedance quoted at seed 0 | minor | K3 "not read" unless K1 succeeds; weighting registered; a fresh host resample per draw slot; entities derived from labels; facts marked; numbers corrected (3-seed mean 0.028) |

**After the fixes:**
- The dry run peaked at 2,877 MiB: the host bootstrap materialised a 2,000 × 6,000 matrix on
  NF-CIC. Draws are now generated in chunks: 861 MiB, 142 s.
- The development dry-run verdicts are unchanged: K1 "success", K3 "failure". Neither is
  evidence.
- Its sensitivity analysis shows that the K1 "success" needs NF-CIC's 6 days counted as 6
  units. Collapsed, discrimination is NOT EVALUABLE (E2).

## 2. Statistical audit

- **Independent units:** 4 development networks from 2 institutions. Every cross-network
  statement in Phase 8k is descriptive. Exact intervals are given where counts are reported:
  - 0 of 3 unsafe networks falsely accepted has a 95% interval of 0–71%;
  - 0 false rejects of 6 adequate rows has 0–46%.
- **Within-network stress tests** (544 episodes) are labelled as such. They are not counted as
  network samples.
- **Observed FPR vs bounds:** every accepted-unit FPR comes with a two-level bootstrap upper
  bound. No "1% FPR" claim is made anywhere.
- **Multiplicity:** one primary confirmatory test (K1); K3 is hierarchical; development
  comparisons are exploratory and all of them are reported, including the negative ones (HB,
  HC5, M3, M4).

## 3. Reproducibility

| run | command | time | peak memory (cap 3.4 GiB) |
|---|---|---|---|
| development experiments | `scripts/run_capped.py -- python scripts/phase8k/dev_experiments.py` | 523 s | 574 MiB |
| confirmatory dry run (final code) | `scripts/run_capped.py -- python scripts/phase8k/confirm_analysis.py --stand-in --scores data/derived/phase8j/dev` | 142 s | 861 MiB |

- **Inputs:** the Phase 8j P1x score files `data/derived/phase8j/dev/*__seed{0,1,2}.npz`.
  They are re-creatable with `scripts/phase8j/build_p1x.py` and `dev_scores.py`, under the
  Phase 8j records.
- **Process note:** the development experiments were estimated at about 5 minutes and took
  523 s. They are re-thresholding only (no model training) and stayed well within the memory
  cap.
- **Tests:** the Phase 8k unit tests (8) cover:
  - the weighted threshold and host weights;
  - the hypergeometric control, E3 and the intervals;
  - every verdict criterion;
  - family pooling;
  - the bootstrap, including units with no verified-benign windows.
