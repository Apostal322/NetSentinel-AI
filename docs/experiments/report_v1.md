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

> **Audit correction (2026-10-19, `docs/audit/validity_audit_2026-10-19.md`, finding V1):**
> the `bruteforce` and `dos` rows here and in 3.7 are inflated by a twin-class leak
> (FTP-BruteForce and DoS-SlowHTTPTest are identical traffic in different families).
> SSH-only and GoldenEye/Hulk/Slowloris-only recalls are listed in the audit. The robust-z
> anomaly variants in 3.3 were affected by a saturation defect (finding V5, fixed in v2).

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

### 3.6 Temporal deep learning (validation; approved run 2026-10-19 17:38-17:41)

Same split, label rules and 300 k training cap as the baselines; GTX 1050 Ti; early stopping
on validation PR-AUC. GRU input: the previous 16 flows to the same destination port that
ended in strictly earlier seconds (from the full day stream), plus the target flow features.

| Model | Run | PR-AUC | Recall @ FPR 1e-3 | Params | Epochs | Fit s | Inference us/row |
|---|---|---|---|---|---|---|---|
| MLP (flow only, control) | `20261019-173929_temporal_mlp` | 0.9997 | 0.9990 | 17,665 | 11 | 44.9 | 0.7 |
| GRU (flow + per-port sequence) | `20261019-174049_temporal_gru` | 0.9999 | 0.9989 | 41,281 | 8 | 42.1 | 2.3 |
| LightGBM flow (batch v1, reference) | `20261019-124619_baseline_binary_lightgbm` | 1.000 | 1.000 | - | - | 15.7 | - |

Per-label validation recall is >= 0.998 for every label for both networks except web XSS
(MLP 0.546, GRU 0.632, LightGBM 1.000; 174 rows from a single episode segment). Process peak
working set 2.7 GB (measured); private memory reached ~3.8 GB while building sequences.
**Conclusion: no measurable benefit of temporal deep learning over gradient boosting on
attacks seen in training; all three saturate.** The informative test, unseen families with
the GRU, was not run. These two runs were not pre-registered, so their test splits were not
evaluated.

### 3.7 Seed variance and temporal open-set (batch v2, approved; `reports/experiments/results_v2.md`)

Seeds {42, 1, 2, 3, 4}; each seed changes the model seed **and** the split seed (benign-block
phase of the episode split). Validation only. Cost: 29 processes, 49.7 min, max peak working
set 3.4 GB (measured).

| Comparison | Result (mean +- std, n=5) |
|---|---|
| LightGBM binary, recall @ FPR 1e-3: flow / no-shortcut / flow+ctx | 0.9999 +- 0.0001 / **0.876 +- 0.002** / 1.000 +- 0.000 |
| Unseen-family recall, LightGBM flow vs flow+ctx: bruteforce | 0.65 +- 0.15 vs **0.999 +- 0.001** |
| ... dos | 0.34 +- 0.14 vs **0.967 +- 0.008** |
| ... ddos | 0.22 +- 0.13 vs **0.66 +- 0.10** |
| ... botnet | 0.18 +- 0.24 vs **0.68 +- 0.04** |
| ... web_attack | 0.09 +- 0.03 vs 0.01 +- 0.01 |
| Anomaly-only unseen-family recall (all families, all seeds) | 0.000 |
| GRU vs MLP on seen attacks, recall @ FPR 1e-3 | 0.9993 +- 0.0003 vs 0.9986 +- 0.0007 |
| GRU vs MLP, web XSS recall | 0.72 +- 0.11 vs 0.55 +- 0.05 |

Unseen family with the temporal networks (seed 42 only, n=1): recall @ FPR 1e-3 for MLP / GRU /
LightGBM flow+ctx = bruteforce 0.51 / 0.85 / 1.00, dos 0.20 / 0.41 / 0.97, ddos 0.006 / 0.06 /
0.72, botnet 0.00 / 0.00 / 0.61, web 0.01 / 0.01 / 0.03. GRU ranking quality on the unseen
family is high for brute force, DoS and DDoS (PR-AUC 0.98 / 0.91 / 0.94) but the threshold fixed
on seen attacks is too strict for them.

Reading: flow-only open-set results are **seed-sensitive** (std up to 0.24), so the single-seed
values in 3.4 should be read with that spread. The context-feature gains are stable across
seeds. Learned per-port sequences (GRU) add some unseen-family signal over flow-only models but
far less than explicit network-wide multi-scale context features.

### 3.8 Corrected open-set protocol (batch v3; audit V1; `results_v3.md`)

Twin classes held out together (port-21 group), label cleaning v2, 5 seeds, benign-val FPR
<= 1e-3. Supervised unseen-group recall, flow -> flow+ctx: port21_failed_conn 0.32 +- 0.44 ->
0.999 +- 0.002; ssh_bruteforce 0.60 +- 0.23 -> 0.998 +- 0.003; dos_http 0.05 +- 0.01 ->
0.951 +- 0.017; ddos 0.11 +- 0.14 -> 0.68 +- 0.09; botnet 0.25 +- 0.23 -> 0.66 +- 0.06;
web_attack 0.09 +- 0.03 -> 0.015 +- 0.008. Scale-invariant context only (fractions, shares,
surge ratios) gives the same numbers (e.g. dos_http 0.943, botnet 0.705 +- 0.004). Per label
(flow+ctx): Hulk 0.99, HOIC 1.00, LOIC-UDP 0.98, GoldenEye 0.73, LOIC-HTTP 0.37, Slowloris
0.09, web attacks <= 0.02. Anomaly-only recall 0.000 everywhere.

### 3.9 Second dataset: NetFlow v3 (batch v4; `results_v4.md`, `docs/datasets/nf_v3.md`)

Identical nProbe features in both datasets; validation splits only; cost 93 processes,
62.5 min, peak 2.0 GB.

* **In-domain retraining saturates on both** NF-UNSW-NB15-v3 and NF-IDS2018-v3: LightGBM
  PR-AUC 1.000 and recall@1e-3 >= 0.999 for every feature set (including without TTL / TCP
  window and with only the 15 Zeek-compatible "portable" fields), 5 seeds.
* **Cross-dataset transfer fails in both directions** (3 seeds): IDS2018 -> UNSW target ROC-AUC
  0.24-0.44 (below chance; partially inverted ranking), target PR-AUC 0.04-0.05, recall at an
  oracle threshold chosen on the target <= 0.01. UNSW -> IDS2018: ROC-AUC 0.26-0.75; the frozen
  source threshold flags 59-99.9 % of benign target flows. Context features give the best
  ranking (0.44 / 0.75) but remain operationally useless.
* **Open-set replication on NF-IDS2018** (same groups, 3 seeds), flow -> flow+ctx: port21
  0.000 -> 0.996; ssh 0.33 +- 0.58 -> 1.000; dos_http 0.51 +- 0.36 -> 0.85 +- 0.05; ddos
  0.993 -> 0.994; web 0.19 +- 0.32 -> 0.74 +- 0.38; **botnet 0.00 -> 0.00** (CIC: 0.66).
  The context effect replicates for floods / brute force / failed-connection storms with a
  different extractor, not for the botnet, and web results are unstable.
* The NF timestamps independently confirm the 12-hour-clock correction to the second.

### 3.10 Application demonstration (synthetic capture; not an evaluation)

The portable bundle (NF-IDS2018, `nf_portable_ctx`) applied by `netsentinel analyze` to a
generated 10-minute capture (`scripts/make_demo_pcap.py`; 19,800 packets -> 4,200 flows,
41 s): all 3,000 generated SSH-attempt flows were rated *unusual* but none *suspicious*; 191
benign-looking HTTPS flows were rated *suspicious*; nearly all flows exceeded the anomaly
threshold. On unfamiliar traffic the shipped model behaves as the transfer results predict.

## 4. Hypotheses: verdicts

(Revised 2026-10-19 after the validity audit and batches v3/v4; v1 wording superseded.)

| | Verdict | Evidence |
|---|---|---|
| H1 temporal context reduces false positives | **Not testable in-distribution** (saturated); context improves recall on unseen flood / brute-force groups at equal FPR *within a network*, but also raises flow-level FPR on benign flows that co-occur with floods (audit V4) | 3.1, 3.8, audit |
| H2 service-conditioned anomaly detection helps | **Not supported**: small PR-AUC changes, recall ~0 at FPR 1e-3; the robust-z conditioned variant was additionally defective in v1 (fixed; still no useful detection) | 3.3, audit V5-V7 |
| H3 multi-scale context captures what single flows miss | **Supported within a network, for high-volume / failure-storm attacks**, robust to a leak-free protocol, to the absolute-rate scale, and partly to a different flow extractor (3.9); not for low-volume application-layer attacks; largely reproducible with single context statistics (audit V2); **does not transfer to another network** | 3.8, 3.9 |
| H4 supervised + anomaly improves unseen-attack detection | **Refuted** (5 seeds, both protocols): anomaly recall 0.000; OR-fusion never helps | 3.7, 3.8 |
| H5 random vs leakage-aware splits differ | **Supported, refined**: inflation comes from evaluating on attack sessions seen in training (and from twin classes, audit V1), not from row adjacency alone | 3.5, audit |
| (new) Cross-network generalisation | **Not supported**: near-perfect in-domain detectors with identical features score at or below chance on another network | 3.9 |

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

* One dataset, one sample. Seed variance (5 seeds, model + split) was measured for the main
  validation comparisons (3.7) but not for the test evaluation, the anomaly variants or the GRU
  open-set runs (n=1).
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
* NetFlow v3: the CIC and NF releases of IDS2018 disagree on labels (no web labels on 02-23 in
  NF; shifted web/infiltration windows), so the extractor cross-check is not label-identical.
  The UNSW-NB15 time-zone offset is an assumption (affects day boundaries only). Transfer used
  3 seeds and validation splits only.
* The PCAP flow assembler approximates nProbe; field-level agreement is unverified (no paired
  PCAP + NF-v3 data was available).

## 7. Conclusions (revised 2026-10-19)

1. On both IDS2018 (CICFlowMeter and nProbe features) and UNSW-NB15 (nProbe), standard tree
   ensembles reach near-perfect detection of attacks *seen in training*. These numbers say
   little about real-world detection: they rest partly on collection artefacts and, as the
   transfer experiments show, on network-specific traffic properties.
2. Causal context features (5/30/300 s) are the most useful addition we measured **within a
   network**: unseen flood, brute-force and failed-connection families are detected at FPR
   1e-3, robustly across seeds, protocols and extractors. The mechanism is that these attacks
   make the surrounding traffic unusual, not that the model learns attack semantics; low-volume
   application-layer attacks are not detected.
3. **Nothing we trained transfers across networks**, even with identical features from the same
   extractor. Any deployment needs training and threshold calibration on the target network.
4. Label-free anomaly scores were not useful at operational FPRs; fusing them never helped.
5. Leakage-aware evaluation changes conclusions through which attack sessions are held out and
   through twin classes hidden in the labels; both must be audited before claiming
   generalisation.

## 8. Next steps

* Locked test evaluation of the final configurations (pre-registration to be written before
  any access; the NF test splits are untouched).
* Incident-level (not flow-level) false-alert evaluation for context models.
* Domain adaptation / target-calibrated thresholds as an explicit experiment, since transfer
  without target data fails.
* Real PCAP validation of the flow assembler against nProbe on paired data.
