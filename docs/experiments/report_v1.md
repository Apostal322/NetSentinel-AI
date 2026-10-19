# NetSentinel AI - Research report v1

Status: **measured** results of experiment batch v1 (2026-10-19) on CSE-CIC-IDS2018, one seed
(42), CPU, development sample of the data (see *Data*). Tables with every run id:
`reports/experiments/results_v1.md`; raw artifacts: `runs/<run id>/`. Hypotheses and protocol:
`docs/research/research_questions.md`. Literature: `docs/research/literature_review.md`.

## 1. Question

Does modelling temporal network context and normal (benign) behaviour improve flow-based
intrusion detection over conventional per-flow classifiers, and how much of the performance
reported on IDS2018 survives leakage-aware evaluation?

## 2. Data and protocol

* **Data.** All 10 CSE-CIC-IDS2018 processed CSV days (16.2 M flows), checksum-verified,
  with three ingestion corrections (12-hour clock without AM/PM, 14 invalid 1970 rows,
  repeated headers) - see `docs/datasets/cse_cic_ids2018.md`.
* **Label decisions** (from our label-quality probes): Infiltration excluded (84.5 % / 17.5 % of
  its rows are byte-identical to benign rows); FTP-BruteForce and DoS-SlowHTTPTest merged into
  `port21_failed_conn` for attack-type tasks (52 shared feature vectors cover >99.99 % of both);
  191 sampled web/LOIC-HTTP rows dropped as non-HTTP mislabels.
* **Sample.** Causal context features are computed on the *full* day streams; then 50 k benign
  flows/day and up to 25 k flows per attack label and day are sampled (765,584 rows) with
  inverse-probability weights. All metrics are prevalence-weighted. Training is capped at
  300 k rows (8 GB RAM machine).
* **Split (default `episode`).** Each attack episode is cut chronologically 60/20/20 into
  train/val/test, benign-only stretches in 30-min blocks, 150 s purge around every boundary
  (partitions >= 300 s apart = longest context window). Episodes < 15 min (DoS-Hulk) go to
  train only. Leakage checks run on every split.
* **Thresholds** are set on validation at weighted benign FPR <= 1e-3. The **test split was
  used once**, for four runs pre-registered in `docs/experiments/test_preregistration.md`.

## 3. Results

### 3.1 Binary detection (validation, LightGBM unless noted)

| Feature set | PR-AUC | Recall @ FPR 1e-3 | Note |
|---|---|---|---|
| Dummy (prior) | 0.084 | 0 | trivial baseline |
| Logistic regression, flow | 0.816 | 0.001 | probabilities saturate at 1.0 for some benign flows, no usable threshold at 1e-3 |
| Random forest / HistGB / LightGBM, flow | 0.9999 / 1.000 / 1.000 | 0.999 / 1.000 / 1.000 | saturated |
| LightGBM, flow without the 4 shortcut fields | 0.997 | 0.874 | |
| LightGBM, flow + 5 s context | 1.000 | 1.000 | |
| LightGBM, flow + 5/30/300 s context | 1.000 | 1.000 | |
| LightGBM, context only (no flow fields) | 0.978 | 0.607 | |

**Test split (pre-registered, measured once; 95 % CI = bootstrap over 15-min blocks):**

| Run | Recall @ thr | PR-AUC | FPR | False-alert flows / h |
|---|---|---|---|---|
| LightGBM flow | 0.983 [0.932, 1.000] | 0.991 [0.954, 1.000] | 0.0009 | 91 |
| LightGBM flow, no shortcut fields | 0.735 [0.434, 0.939] | 0.982 [0.937, 0.997] | 0.0009 | 89 |
| LightGBM flow + context | 0.983 [0.933, 1.000] | 0.998 [0.987, 1.000] | 0.0008 | 85 |

Per-label test recall (flow -> no-shortcut): HOIC 1.000 -> **0.068**, FTP-BF 1.000 -> 0.443,
SlowHTTPTest 1.000 -> 0.437, SQLi 0.983 -> 0.000, Bot 0.942 -> 0.926, SSH/LOIC/Slowloris ~1.0
in both (`runs/*/test_breakdown.json`). "False-alert flows / h" counts flows, not incidents;
incident-level aggregation is implemented in the dashboard but was not evaluated here.

### 3.2 Attack-type classification

Validation macro-F1 0.974 (label, flow) / 0.966 (label, flow+ctx); family: 0.887 (flow) vs
0.983 (flow+ctx). Test (label, flow, pre-registered): macro-F1 **0.889**, balanced accuracy
0.884; all classes >= 0.94 recall except **SQL injection (recall 0.017; 6 training rows)**.

### 3.3 Anomaly detection (H2)

Label-free detectors fit on benign training flows are weak on IDS2018 flows: best validation
ROC-AUC 0.86 (Isolation Forest, flow+ctx), recall at FPR 1e-2 <= 0.18 for every variant.
Service conditioning (port-derived categories) changes Isolation Forest PR-AUC 0.195 -> 0.244
(flow) and 0.325 -> 0.376 (flow+ctx) but lowers the robust-z baseline (0.258 -> 0.114).

### 3.4 Unseen attack families (H4), validation-time estimate

Recall on all rows of a held-out family at benign FPR <= 1e-3 (supervised model trained
without that family):

| Held-out family | flow | flow + context | anomaly only | fused (flow+ctx) |
|---|---|---|---|---|
| bruteforce | 0.512 | **0.998** | 0.000 | 0.997 |
| dos | 0.229 | **0.968** | 0.000 | 0.957 |
| ddos | 0.226 | **0.722** | 0.001 | 0.542 |
| botnet | 0.004 | **0.613** | 0.000 | 0.440 |
| web_attack | 0.117 | 0.027 | 0.000 | 0.016 |

### 3.5 Split protocol (H5), LightGBM, validation

| Protocol | flow PR-AUC / recall@1e-3 | flow+ctx PR-AUC / recall@1e-3 |
|---|---|---|
| random rows | 1.000 / 1.000 | 1.000 / 1.000 |
| episode (default) | 1.000 / 1.000 | 1.000 / 1.000 |
| random 15-min blocks | 0.789 / 0.335 | 0.991 / 0.950 |

## 4. Hypotheses: verdicts (validation unless stated; single seed)

| | Verdict | Evidence |
|---|---|---|
| H1 temporal context reduces false positives | **Not testable in-distribution** (both saturate; test FPR 0.0008 vs 0.0009 within CI); **supported for robustness**: context lifts recall on unseen families at equal FPR | 3.1, 3.4 |
| H2 service-conditioned anomaly detection helps | **Not supported in a useful sense**: small PR-AUC gain for Isolation Forest, loss for robust-z, absolute recall stays near 0 at operational FPR | 3.3 |
| H3 multi-scale context captures what single flows miss | **Partially supported**: within known attacks single flows already suffice; under family hold-out, 5/30/300 s context raises recall from 0.00-0.51 to 0.61-1.00 for volumetric/brute-force families, but not for web attacks | 3.4 |
| H4 supervised + anomaly improves unseen-attack detection | **Refuted here**: anomaly recall ~0; OR-fusion lowers recall because it halves each FPR budget | 3.4 |
| H5 random vs leakage-aware splits differ | **Supported, with a refinement**: random rows and within-episode splits are equally saturated; performance drops only when whole attack episodes are unseen. The inflation comes from evaluating on attack sessions seen in training, not from row adjacency alone | 3.5 |

## 5. Error analysis

* **Shortcut dependence.** Without `fwd_seg_size_min`, `init_fwd_win_byts`,
  `init_bwd_win_byts`, `fwd_header_len`, LightGBM loses HOIC (1.00 -> 0.07 test recall), both
  port-21 failure classes and SQLi. These fields reflect TCP stack / tool defaults of the
  attack machines; high scores on IDS2018 partly measure that the attack hosts differ from the
  benign ones, which is unlikely to transfer to another network.
* **Context as day identity.** For the *family* task, identical port-21 flows belong to
  `bruteforce` (02-14) or `dos` (02-16); context features separate them only because the days
  differ. The family-level gain from context (0.887 -> 0.983 macro-F1) is therefore partly an
  artefact; the label-level task (merged class) does not show it (0.974 vs 0.966).
* **Forward-in-time generalisation.** Bot test recall 0.94: the later Bot session (afternoon)
  is detected less well than the morning session used for training.
* **Rare classes.** SQLi (34 + 53 flows total) is essentially unlearnable for attack typing.
* **Logistic regression** saturates probabilities on heavy-tailed rates despite the signed-log
  transform, so its scores tie at 1.0 for some benign flows; a strict FPR threshold is then
  unattainable (recall 0.001 at 1e-3, 0.69 at 1e-2).
* **Fragile operating points.** Frozen LightGBM thresholds are ~1e-4: almost all benign
  validation scores are ~0, so small distribution shifts can move the realised FPR a lot
  (test benign FPR per day ranged 0 - 0.0016 for the flow model).

## 6. Threats to validity

* One dataset, one seed, one sample. CIs come from a block bootstrap of the test rows only;
  no repeated-training variance was measured.
* Labels are the original IDS2018 labels with documented errors; corrected relabellings
  (DistriNet 2023, LycoS 2024) were not used.
* Sampling (50 k benign/day, capped attacks) is reweighted, but rare-pattern coverage of the
  benign sample is limited; 7 of 10 source files are truncated at the Excel row limit.
* Episode boundaries come from labels (the published attack schedule), which a deployment does
  not know; they only define the evaluation split, never a feature.
* Open-set results (3.4) use validation benign and all rows of the held-out family; they are
  development estimates, not locked-test results.
* No packet-level, per-host or application-identity information exists in this data, so the
  application-aware parts of the original project vision could not be tested.

## 7. Conclusions

1. On IDS2018, standard tree ensembles reach near-perfect detection of attacks *seen in
   training*, under any split that keeps attack episodes on both sides. These numbers say
   little about real-world detection: a large part of the signal comes from collection
   artefacts.
2. Short-horizon causal context features are the most useful addition we measured: they make
   detection of *unseen* volumetric and brute-force families possible at FPR 1e-3.
3. Label-free anomaly scores, global or service-conditioned, were not useful at operational
   false-positive rates on these features, and fusing them hurt.
4. Leakage-aware evaluation changes conclusions mainly through *which attack sessions* are
   held out. A random-row split and a within-episode split give the same (saturated) numbers.

## 8. Next steps

* Temporal deep learning (GRU over causal per-port sequences vs MLP control) - implemented,
  awaiting approval to train.
* Repeat key comparisons over 5 seeds; report variance.
* Cross-dataset check (e.g. CICIoT2023 or the corrected DistriNet IDS2018) for the shortcut and
  context findings.
* Calibrated fusion with a learned (out-of-fold) combiner instead of the OR rule.
