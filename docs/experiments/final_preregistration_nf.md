# Final-evaluation pre-registration: NetFlow-v3 datasets (Mission 5)

Written 2026-10-20, **before any NF-v3 test-partition row was evaluated**. Inputs to this
document are validation results only:
- `reports/experiments/results_v4.*` and `results_v5.*`;
- `reports/audit/transfer.json`, `autoencoder_unsw.json` and `nf_test_overlap.json`.

After the final runs, nothing listed here (data, partitions, features, models, thresholds,
calibration sizes, seeds, metrics, hypotheses) may change on the basis of test results.
Every final run writes a marker file `reports/final/<experiment>.json`. The adapt stage
refuses to run an experiment again once its marker exists.

## 1. Data (frozen)

| Dataset | Archive SHA-256 | Processed |
|---|---|---|
| NF-CICIDS2018-v3 (UQ, BagIt SHA-1 verified at ingest) | `7399bdef...823d97f` | `data/processed/nf_cicids2018_v3`, schema `nf-1.0.0` |
| NF-UNSW-NB15-v3 (UQ, BagIt SHA-1 verified at ingest) | `6d51554d...4c9cdfd` | `data/processed/nf_unsw_nb15_v3`, schema `nf-1.0.0` |

Full hashes of the archives and of every processed day file are in
`reports/audit/dataset_hashes_2026-10-20.txt`. Data preparation:
- NF-IDS2018: drop `infiltration`, label cleaning v2.
- NF-UNSW: no cleaning.
- Both: stratified sample with inverse-probability `sample_weight`; all metrics are weighted.

CSE-CIC-IDS2018 (CICFlowMeter) is **excluded**. Its test split was used once on 2026-10-19
(`docs/experiments/test_preregistration.md`). CIC v5 results stay validation-only.

## 2. Final test partition (frozen)

Two split protocols have touched these datasets:
- `episode` (block 30 min, purge 150 s, 0.6/0.2/0.2): v4 in-domain, open-set and transfer
  sources.
- `chronological` (purge 150 s, 0.6/0.2/0.2): v5 adaptation targets.

The final test set of a dataset is the set of rows that are in the **test partition under
both protocols**. These rows were never used to fit, calibrate, threshold or select anything.
Composition (sampled rows; `nf_test_overlap.json`):

| Dataset | Rows | Benign | Attack families present |
|---|---|---|---|
| NF-UNSW-NB15 | 39,151 | 18,530 | exploit 6,983; fuzzing 5,738; generic 3,602; recon 3,441; dos 857 |
| NF-IDS2018 | 21,408 | 15,498 | botnet 5,890; web_attack 20 |

Known limitation: on NF-IDS2018 the intersection contains no brute-force, DoS or DDoS rows.
IDS-target results therefore speak to benign false alarms and botnet detection only. Web
attack (20 rows) is reported but not interpreted.

## 3. Procedures (frozen; code `src/netsentinel/training/adapt.py`, `evaluation: final_test`)

Every final run repeats the validated procedure with the same seeds, only swapping the
evaluation rows:
- **Source model:** LightGBM (`model_params: {}`), trained on the source episode-train
  partition (cap 300,000 rows).
- **Source threshold:** weighted FPR <= 1e-3 on source episode-validation.
- **Calibration pool:** chronological-train partition of the target; benign rows only
  (`clean`) or all rows (`unlabelled`). Samples are drawn proportional to sample weight.
  Sizes: 1,000, 10,000 and 50,000.
- **Methods:**
  - source model with source threshold;
  - source model with target-calibration threshold;
  - robust per-domain normalisation with source or target threshold;
  - KS < 0.3 shift-robust feature subset;
  - one-class detectors (robust-z, Isolation Forest, autoencoder) fit on half the
    calibration sample and thresholded at FPR 1e-3 on the other half. Feature views: flow,
    ctx, all, and flow without the TTL/TCP-window shortcut suspects (`flow_noshortcut`; its
    only validation evidence is `autoencoder_unsw.json`, seed 42).
- No target attack label is used by any procedure.
- **Seeds:** 42, 1, 2. These vary the source subsample, the calibration draw and the
  detector initialisation.

| Experiment | Source -> target | Features |
|---|---|---|
| `final_unsw2unsw_nf_flow_ctx_s{seed}` | NF-UNSW -> NF-UNSW (in-domain) | nf_flow_ctx |
| `final_ids2ids_nf_flow_ctx_s{seed}` | NF-IDS2018 -> NF-IDS2018 (in-domain) | nf_flow_ctx |
| `final_ids2unsw_nf_flow_ctx_s{seed}` | NF-IDS2018 -> NF-UNSW | nf_flow_ctx |
| `final_ids2unsw_nf_portable_ctx_s{seed}` | NF-IDS2018 -> NF-UNSW | nf_portable_ctx |
| `final_unsw2ids_nf_flow_ctx_s{seed}` | NF-UNSW -> NF-IDS2018 | nf_flow_ctx |

In-domain rows: the "source model, source threshold" result is the supervised in-domain
retraining baseline. It is trained on episode-train, so the intersection rows are unseen.

## 4. Metrics (frozen)

- Recall and FPR at the procedure's threshold, with 95% CIs from a 200-replicate bootstrap
  over 15-minute blocks.
- False-alert flows per hour (prevalence-weighted false positives ÷ observed test hours).
- ROC-AUC and PR-AUC.
- Recall at FPR 1e-3 read off the test scores (an oracle ranking diagnostic, not an
  operating point).
- Each seed is reported, plus the mean across seeds.

## 5. Hypotheses (frozen; predicate on the mean over the 3 seeds)

| ID | Hypothesis | Supported if |
|---|---|---|
| H1 | In-domain supervised retraining detects the test attacks | UNSW and IDS: recall >= 0.95 and FPR <= 0.002 |
| H2 | Supervised models do not transfer | all three transfer settings: source-only ROC-AUC < 0.6 or source-threshold FPR > 0.1 |
| H3 | Label-free target threshold calibration controls false alarms but does not restore detection | transfer settings, clean 50k: FPR <= 0.003 and recall < 0.05 |
| H4 | Target-benign normal models do not detect NF-IDS2018 test attacks at operational FPR | IDS target (in-domain and UNSW->IDS), every detector and view, clean 50k: recall < 0.05 |
| H5 | On NF-UNSW the autoencoder separates attacks, and not only through TTL/window fields | UNSW target, clean 50k: `target_autoencoder_flow` recall >= 0.9 and `target_autoencoder_flow_noshortcut` recall >= 0.8 |
| H6 | Unlabelled calibration with realistic contamination is harmful | for each setting, mean recall of `target_autoencoder_flow` and `source_model_target_threshold` at unlabelled 50k <= the clean 50k value |

Interpretation fixed in advance. H5 holding would **not** be evidence of unknown-attack
detection in general. On validation the effect depends on host-stack fields such as TTL and
minimum packet length that are constant for UNSW benign traffic (`autoencoder_unsw.json`).
It is a statement about this testbed.

## 6. Not part of the final evaluation

- Application identification (Mission 4). This is validation only: it predicts a DPI label,
  and no decision of this project depends on its test score.
- Temporal models.
- Open-set holdout groups on NF data. The intersection lacks most IDS groups.
- The real-traffic CTU-Normal-26 capture, which is benign only and used for telemetry
  validation.

---

## Addendum after the final runs (2026-10-20, 03:30): protocol deviation

*Appended after the test results; the text above is unchanged since commit 47d0817.*

The episode split draws its segment phase from the run seed (`splits._episodic`,
`rng.integers(0, 10)`). Section 2's composition was computed with seed 42 only. Consequences:
- **Seed 42:** the final test set is exactly the pre-registered intersection (NF-IDS2018:
  21,408 rows; NF-UNSW: 39,151 rows; row counts identical to section 2; see
  `reports/final/*_s42.json`).
- **Seeds 1 and 2** used their own episode phase, so their test sets differ: NF-IDS2018
  18,210 and 22,869 rows (5,890 botnet and 20 web rows each time; only the benign count
  changes); NF-UNSW 39,234 and 39,154.
- Within each run the protocol stays leak-free. The run's source model is trained on that
  seed's episode-train partition, which excludes that run's test rows, and the target
  calibration pool (chronological train) excludes the chronological test.
- But for seeds 1 and 2, section 2's claim that test rows "were never used to fit, calibrate,
  threshold or select anything" is not guaranteed across the whole project. Some of those
  rows may lie in train/validation partitions of v4 runs with seed 42. Strictly, the same
  applies to seed 42 relative to the v4 runs with seeds 1–4.
- No hyper-parameter was tuned on those runs (all models use defaults). The exposure is
  limited to knowing the validation results that motivated the hypotheses.

Handling:
- The pre-registered primary analysis (mean over seeds 42, 1, 2) is reported unchanged.
- A seed-42-only analysis, the only one whose test set exactly matches section 2, is
  reported as a labelled sensitivity analysis:
  `reports/experiments/results_final_nf{,_seeds42}.md`.
- Where the two disagree, the report says so.
