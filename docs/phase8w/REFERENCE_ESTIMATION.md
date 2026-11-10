# Phase 8w: reference estimation, representations and the null control

Code: `scripts/phase8w/relative.py` (schema `relwin-1.0.0`), `references.py`, `experiment.py`.
Tests: `tests/unit/test_phase8w.py`.

## 1. Estimator

For each of the 12 window features, over a set of reference windows:

| quantity | definition |
|---|---|
| location | median |
| scale | max(1.4826 · MAD, floor) |
| floor | 0.15 for `no_reply_frac`, `rst_frac`, `udp_share`, `upload_share`, `new_dst_frac`; 0.25 for the others |
| deviation | z = clip((x − location) / scale, −10, 10); a missing value has z = 0 |

- **Identical to the product's `RobustScaler`** and therefore to Phase 8h's `B-loc` (unit test).
- **No alternative estimator is searched.** Trimmed means, mean/SD and quantile references are
  not fitted: the phase tests one registered estimator, the one with a history in this project.
- **Every reference records** its population, window count, time interval, raw MAD, which scales
  were floored and the share of missing values. Floored scales are common (5–9 of 12 features
  per domain): destination counts and the fraction features are near-constant in benign traffic.

## 2. Failure states (never silently substituted)

| state | behaviour |
|---|---|
| fewer than 200 reference windows | `insufficient_history`; using it raises an error |
| non-finite values, wrong shape, unknown population | error at fit time |
| constant feature (MAD 0) | the documented floor; flagged per feature |
| scenario unavailable for a domain | that scenario's scores are not written; an incomplete scenario is not aggregated |

An unlabelled reference carries the note "centre of the observed mixture; NOT a benign reference"
and `benign_reference: false` in every manifest.

## 3. Representations

All arms have **12 columns in the original order**. Only the cell values differ.

| arm | cell value | role |
|---|---|---|
| `R0` | raw feature | matched null control |
| `S` | z | signed deviation = Phase 8h `B-loc`, rerun as a contrast (HISTORICAL_NORMALIZATION_AUDIT § 4) |
| `A` | \|z\| | unsigned deviation: the new candidate |

**Not fitted, with reasons:**

| candidate | reason |
|---|---|
| positive/negative split | the same tree hypothesis class as `S` (unit test) |
| absolute + relative (24 columns) | keeps the absolute scale the hypothesis calls the shortcut, and needs its own 24-column null control; outside this budget |
| context-conditioned | IDENTIFIABILITY § 5: self-normalising attackers; G2 NOT EVALUABLE |

## 4. The null control

Phase 8v added columns, which changed LightGBM's per-tree column draw, so "same seed" was not a
paired comparison. Here:

- every arm is built from **one** set of rows, labels and weights per fit (`training_set`), then
  transformed cell by cell;
- the row set is checked row for row against the frozen recipe (`fragility.train_rows`);
- column count, column order, seed and hyper-parameters are identical;
- `R0` is refitted through this driver and compared with the saved Phase 8o member of the same
  seed; the largest score difference is written to the ledger. Phase 8u found the refit
  bit-identical; any difference here is reported, not assumed away;
- every reported effect is candidate − `R0` at the same seed.

**Dry run (no real fit, `reports/phase8w/dry_run.json`):**
- all three arms have the same shape and are finite in the four folds (80,085 to 580,618 rows × 12);
- `A` equals |`S`| exactly;
- every scenario's reference is usable for all nine evaluated domains;
- peak memory 1.7 GiB.

## 5. Causality

| check | how |
|---|---|
| a reference uses only windows before the hold-out cut | `calibration_parts` masks by the cut; hold-out and evaluation frames are separate objects |
| scoring cannot update a reference | references are not modified by scoring (unit test) |
| source references use training labels only | label-benign calibration windows of the source domain |
| evaluation labels never reach a reference | only `Z2`, `Z3` and `T` read labels, and only calibration-period labels |
| audited population = scored windows | row-for-row key and window check (`references.aligned`) |

## 6. Known limits

- **Reference mismatch:** source references are label-benign (clean features); the deployable
  target reference is unlabelled. `T` is the train-consistent oracle variant.
- **`Z2` is a simulation:** a uniform draw of 800 windows and a perfect reviewer. It keeps 308
  windows on NF-BoT and 693 on NF-ToN.
- **The hold-out threshold still uses calibration labels** (the best case of trusted review), as
  in Phases 8s–8v.
