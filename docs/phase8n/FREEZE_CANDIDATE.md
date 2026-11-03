# Phase 8n: frozen candidate specification (M2)

**Status:** a replicated development GO. It is a candidate for an independent test, **not** for
deployment, and the deployed detector is unchanged.
- The amendment 1 selection passed on consumed development networks.
- Amendment 2 replicated it with fresh randomness.

## Specification

| item | value |
|---|---|
| model | mean predicted probability of 5 LightGBM classifiers |
| members | Phase 8i B-raw settings (`scripts/phase8i/common.py` `LGB`: 200 trees, 15 leaves, learning rate 0.05, `min_child_samples` 20, `subsample` 0.8 every iteration, `colsample_bytree` 0.8, `n_jobs` 2) |
| member m of replicate r | LightGBM seed and training-subsample seed 1000 + 10r + m. A deployment candidate fixes one replicate; r = 0 is the reference |
| features | the 12 registered window features (`netsentinel.behavior.windows.WINDOW_FEATURES`, unchanged order), including the frozen `new_dst_frac` |
| training data | leave-one-network-out source networks (Phase 8j `leakage_audit.targets`); Phase 8i clean windows; 50,000-window cap per domain; network-balanced and class-balanced weights |
| calibration | Phase 8j P1x (calibration-period attackers purged; this assumes confirmed calibration labels); T0 = conformal rank at α = 1 % on the last 30 % of calibration slots, computed on the **ensemble** score |
| alert | ensemble score > T0 |

## Code and protocol hashes

SHA-256 of the LF-normalised files, first 16 hex digits, at the commit that adds this file:

| file | sha256 |
|---|---|
| `scripts/phase8n/candidates.py` | `3d3ce299a28096e9` |
| `scripts/phase8n/fragility.py` | `4d378b41cac0b292` |
| `scripts/phase8n/compare_candidates.py` | `63049a00b50189be` |
| `scripts/phase8n/analyze_fragility.py` | `a2ddd2323ec73cb7` |
| `scripts/phase8n/entity_sensitivity.py` | `5aefe60cd08ee193` |
| `scripts/phase8n/replication_check.py` | `147d9d2f652f4b57` |
| `docs/phase8n/PREREGISTRATION.md` | `76fe23b4247a364c` |
| `scripts/phase8i/common.py` | `90aa27d49167f3ea` |
| `scripts/phase8h/lodo.py` | `f6764a87a51e25a6` |
| `scripts/phase8b/scorers.py` | `af01e63fbcc3da5f` |
| `scripts/phase8j/dev_scores.py` | `4dd7408dd890311d` |
| `scripts/phase8j/leakage_audit.py` | `bebdb058728ff64a` |
| `scripts/phase8j/build_p1x.py` | `3d7c657e23410aa0` |
| `src/netsentinel/behavior/windows.py` | `4e3b9df125964685` |

**Libraries:** LightGBM 4.7.0, NumPy 2.5.4, Polars 2.0.0, scikit-learn 1.9.1, Python 3.12.

**Determinism.** Reproduction is verified on this machine only. LightGBM's `deterministic` flag is
not set.

## Independent evaluation: none available

| dataset | why it cannot serve |
|---|---|
| DEDALE | consumed (Phase 8l confirmatory run) |
| NF-BoT-IoT-v3 | consumed (Phase 8i) |
| AIT | label limits (Phase 8k/8l) |
| UWF | no benign calibration traffic (Phase 8k) |
| the 4 development networks | used for selection |

- No eligible untouched network is known (Phase 8l power analysis: 15–30 would be needed for a
  network-level claim).
- Any future test needs a new dataset identified, licence- and label-checked, and the user's
  approval before access.
- Until then, M2 is **development-only**.
