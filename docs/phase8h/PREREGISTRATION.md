# Phase 8h pre-registration: shift-robust window detection (development protocol)

**Status:** fixed before any Phase 8h analysis was run. Committed before the NF-CIC-IDS2018
development windows were built.

**Role of the results.**
- Every dataset used here was inspected in earlier phases. Phase 8h results are therefore
  **exploratory [E]**, but decided by the rules below, written in advance.
- A confirmatory test needs fresh data. That is section 9, and it needs operator approval to
  download.

**Background.** [RESEARCH_AUDIT.md](RESEARCH_AUDIT.md).

## 1. Research questions

Why does a model that ranks attack windows well (PR-AUC about 0.9) not yield a reliable
operating point on a new domain? And can that be improved by any of:
- (H1) the representation;
- (H2) the threshold calibration;
- (H3) combining supervised and anomaly evidence?

The three are separated deliberately:
- H1 is judged on **ranking at a fixed false-positive rate**, with a threshold-free oracle
  per domain;
- H2 is judged on **threshold reliability**;
- H3 is judged on **operational detection at a calibrated threshold**.

## 2. Data, domains and units

**Telemetry families are never pooled silently.**
- **Zeek** (conn.log). Same lab (Stratosphere), so cross-capture, not cross-network:
  - IoT-23 development ×9;
  - CTU-Normal ×13 (benign only);
  - CTU-Honeypot 4-1 and 5-1.
- **NetFlow** (nProbe, NetFlow v3):
  - NF-UNSW-NB15-v3 development part;
  - NF-CIC-IDS2018-v3 development part: first 78% of each day's time span, built with the
    same `WindowBuilder` as Phase 8b. Each of its 10 days is one domain.
- **Cross-telemetry** transfer (train on one family, test on the other) is reported
  separately as a secondary analysis, because `no_reply_frac` and `rst_frac` are derived from
  different fields.

**Windows and splits.**
- Windows: 30 s device windows (source address) with the 12 `WINDOW_FEATURES`.
- Calibration: windows ending before the domain's time midpoint. Evaluation: the rest.
  This is the Phase 8b split.
- Variants: `clean` and `unlabelled` calibration. **Primary = clean.**

**Eligibility.**
- **Attack domain:** at least 60 evaluation windows, and at least one attacking entity with
  ≥ 5 attack windows in evaluation.
- **Benign evaluation unit:** at least 60 label-benign evaluation windows.

**Labels.**
- **Label-benign:** windows of entities with no attack-labelled flow in the domain. They are
  verified benign only for CTU-Normal; elsewhere they are the dataset's benign label.
- NF-CIC `infiltration` windows are excluded from positives and negatives (label noise:
  84.5% identical to benign).

**Unit of inference: the held-out domain.** Entities and windows inside a domain are
correlated and are never treated as independent replicates.

## 3. Models and methods

| id | model | trained on |
|---|---|---|
| B-rz | deployed robust median/MAD baseline (product `calibrate_windows`, cross-fit, top-2 \|z\|) | target's own calibration windows |
| B-lr | logistic regression (L2, C = 1) on locally standardised features | source domains (interpretable baseline) |
| B-raw | LightGBM on the 12 raw features (`lgbm_raw`, Phase 8b settings) | source domains |
| B-loc | LightGBM on locally standardised features (`lgbm_local`) | source domains |
| **N-dis** | **new: domain-invariance-screened LightGBM** (below) | source domains |
| **N-fuse** | **new: conservative evidence fusion** (H3) | B-loc score plus B-rz score |

All source-trained models use equal total weight per source domain and balanced classes
within each domain (the Phase 8b scheme). Seeds 0, 1 and 2 are averaged for the stochastic
LightGBM models; logistic regression and screening are deterministic.

**Domain-invariance screening (N-dis), fixed in advance.**
1. For a feature f and a source domain d, take the locally standardised label-benign
   calibration windows: z = (x − median_d) / (1.4826 · MAD_d), with MAD floored as in
   `RobustScaler`, clipped to [−10, 10].
2. Instability: I_f = median over pairs of source domains (d, d′) of the Wasserstein-1
   distance W1(z_f^d, z_f^d′).
3. Keep the features with I_f ≤ median_f(I_f). Ties are kept.
4. Train B-loc's LightGBM on the kept features only.

Screening uses only the **training fold's source benign windows**: no target data and no
labels of attack windows.

**Mechanism.**
- Local standardisation removes each domain's location and scale.
- Features whose *shape* still differs between benign domains carry network identity (e.g.
  service mix, scan-like `new_dst_frac` on gateways), so a model trained on them learns
  domain-specific shortcuts.

**Threshold calibrators (H2)**, all at target α = 1% and on the same score:
- **T0 split-conformal.** Phase 8b method (the deployed cross-fit threshold is also reported for B-rz): quantile of the calibration hold-out (last 30% of
  the calibration windows).
- **T1 block-bootstrap upper bound.** The 90% upper bound of the (1 − α) quantile of the
  calibration hold-out, under a moving-block bootstrap (block = 20 windows = 10 min,
  1,000 resamples). Mechanism: windows are autocorrelated, so the exchangeability assumption
  of split-conformal fails and the effective sample size is smaller than n.
- **T2 population-conditional.** Separate T0 thresholds for windows of entities with ≥ 30
  calibration windows (own profile) and for all other windows (pooled fallback / transient).
- **T3 selective.** T1, but the domain is abstained ("no decision") when the bootstrap 90%
  interval width of the threshold exceeds 50% of T0. Coverage is reported.

**Fusion (H3).** Let s_A = B-loc probability and s_B = B-rz score, with thresholds from T0
at α/2 each on the target calibration hold-out.

| id | rule |
|---|---|
| F-or | alert if s_A > t_A(α/2) **or** s_B > t_B(α/2) (Bonferroni: total FPR ≤ α under the calibration assumption) |
| F-and | alert if both exceed their α thresholds (high-confidence tier; reported, not tested) |
| F-learn | logistic stacking on [rank(s_A), s_B] fitted on source domains. **Exploratory only; never deployed.** |

## 4. Hypotheses, metrics and decision rules

Family-wise α = 0.05, Holm over the four primary tests (H1a, H1b, H2, H3). Every test is
paired by held-out domain.

### H1a: local standardisation transfers better than raw features
- **Comparison:** B-loc vs B-raw. Leave-one-domain-out within each telemetry family, over
  eligible attack domains.
- **Primary metric (P1):** macro mean over held-out attack domains of **window recall at
  FPR = 1% on that domain's label-benign evaluation windows** (oracle per-domain threshold).
  This isolates ranking from calibration.
- **Secondary metrics:**
  - PR-AUC and ROC-AUC (macro and micro);
  - entity recall at that FPR;
  - recall per attack family;
  - recall macro-averaged by entity, so heavy sources cannot dominate.
- **Success:** mean Δ ≥ +0.05, and a one-sided sign-flip permutation test over domains with
  p below its Holm threshold.
- **Failure:** mean Δ ≤ 0, or the test is not significant. A significant difference below
  0.05 is reported as "not practically relevant".

### H1b: invariance screening transfers better than all features
- **Comparison:** N-dis vs B-loc, same protocol and decision rule as H1a.
- An additional failure condition: N-dis loses more than 0.20 on any held-out domain. That
  is reported as a harmful failure even if the mean passes.

### H2: autocorrelation-aware thresholds reduce FPR exceedance
- **Comparison:** T1 vs T0, applied to B-rz and to B-loc scores. **B-rz is primary**: it is
  the deployed scorer.
- **Units:** every eligible benign evaluation unit across both families (label-benign windows
  of each domain).
- **Primary metric (P2):** exceedance rate = share of units whose realised FPR > 2α.
- **Secondary metrics:**
  - realised FPR distribution (median, p90);
  - window and entity recall on attack domains (cost);
  - T2 and T3 vs T0;
  - T3 coverage.
- **Success:**
  - exceedance(T1) ≤ 0.5 × exceedance(T0), and exact one-sided McNemar on the paired unit
    indicators below its Holm threshold;
  - **and** median absolute recall loss on attack domains ≤ 0.10.
- **Failure:** otherwise. If T0 exceedance is already ≤ 10%, H2 is "not testable here".
- Score calibration (reliability of LightGBM probabilities: Brier score and ECE in 10 bins on
  held-out domains vs source) is reported separately. It is not part of P2.

### H3: conservative fusion adds detection beyond the better component
- **Comparison:** F-or vs the better of B-loc@T0(α) and B-rz@T0(α), chosen **per held-out
  domain on its calibration data only**: the component with the higher calibration hold-out
  separation. No evaluation labels are used for the choice.
- **Primary metric (P3):** macro mean window recall at the operational threshold over
  eligible attack domains.
- **Secondary metrics:**
  - entity (initiator) recall;
  - detection delay;
  - realised label-benign FPR and false alerts per hour;
  - complementarity: entities detected by only one component at α/2;
  - F-learn (exploratory);
  - failure on cross-telemetry domains.
- **Success:**
  - mean Δ ≥ +0.05 with a sign-flip permutation p below its Holm threshold;
  - **and** median realised FPR of F-or ≤ 1.5α;
  - **and** F-or entity recall ≥ the better component's in at least 75% of domains.
- **Failure:** otherwise. In particular: "fusion only inherits the better model" if Δ < 0.05.

## 5. Uncertainty and reporting

- **Intervals:**
  - over domains: 95% percentile bootstrap of the macro mean (resampling domains, 10,000);
  - inside a domain: 1 h moving-block bootstrap of window metrics (2,000).
- **Reporting:** macro (domain), micro (pooled windows) and entity-macro, side by side.
  Families with ≥ 2 domains are reported separately.
- **Expected power is low.** Attack domains: about 10 NF-CIC days, NF-UNSW, and 3 IoT-23. A
  sign-flip test over 13 domains detects only large, consistent effects. A null result is
  reported as "no evidence of an effect", not "no effect".
- **Negative results are reported with the same prominence as positive ones.**

## 6. Ablations and error analysis (exploratory, after the primary tests)

**Ablations** for N-dis, B-loc and F-or. Remove:
- temporal context (`new_dst_frac`, which depends on history);
- volume features (`log_flows`, `log_*_bytes`, `log_pkts`);
- the shortcut suspect `new_dst_frac` alone;
- service-composition features (`udp_share`);
- conditional calibration (T2 → T0);
- either fusion component.

**Calibration sample size:** T0 vs T1 with the calibration period truncated to 15, 30, 60
and 120 minutes.

**Error analysis:**
- false alerts on label-benign windows: per entity, per feature explanation, own-profile vs
  pooled;
- missed attack entities;
- per-family failures;
- the cross-telemetry failure.

## 7. Confounders (declared)

- One attack family per NF-CIC day: day and family effects are inseparable.
- The same lab network for all NF-CIC domains, and for all IoT-23 captures.
- Heavy single sources (one device produces all attack windows in several IoT-23 captures).
- Label noise (NF-CIC infiltration, twin classes).
- Different field semantics between NetFlow and Zeek.
- Time of day; class imbalance; window autocorrelation.
- Small benign units (CTU-Normal-21 has 72 windows).
- All data were inspected before, so results are exploratory.

## 8. Compute and safety

**Limits.**
- One heavy process at a time, 3.4 GB watchdog, CPU only.
- LightGBM with `n_jobs=2`, training samples capped at 200,000 windows per source domain
  (stratified by label, seeded).

**Estimates** (to be confirmed by a smoke run):
- building NF-CIC development windows: 5–10 minutes, at most 2 GB;
- the full leave-one-domain-out grid: 20–40 minutes, at most 2 GB.

**Integrity.**
- Nothing here changes the deployed detector, thresholds or defaults. All new methods are
  research code under `scripts/phase8h/`.
- Outputs go to `reports/phase8h/`. Seeds, configuration, git SHA and package versions are
  recorded per run.

## 9. Confirmatory stage (not part of this run)

- **Choosing the method to confirm:** after the development analysis, the single method with
  the best primary metric **among those meeting their success rule** is frozen (code SHA). If
  none does, no confirmatory run is made, and Phase 8h reports the negative result.
- **Fresh data:** confirmation requires captures never opened by this project (further
  IoT-23 captures or CTU-13 scenarios other than 9/10). Downloading them needs operator
  approval.
- **Next step:** a separate pre-registration amendment, written before the download, will fix
  the data and the decision rule.

## Amendment A1 (2026-10-29): after building the NF-CIC windows, before any model was run

**Domain inventory, built** (`reports/phase8h/nf_cic_windows.json`):
- Eligible NF-CIC attack domains: 02-14 SSH brute force (1 attacker), 02-16 DoS-Hulk (1),
  02-20 DDoS LOIC-HTTP (10), 02-21 DDoS HOIC (10), 02-22 web attacks, 03-02 bot (7).
- Benign units only: 02-15, 02-23, 02-28 and 03-01. On 02-28 and 03-01 the infiltration
  windows are excluded as noisy: 5,689 and 3,038 windows.
- Ineligible: 02-27 (304 windows).

**Change 1: 02-22 (web attacks) is excluded from the primary analyses.**
- Its 2,538 attack-labelled flows come from 562 sources aimed at one victim (172.31.69.28).
- The top destination ports are 500 (IKE), 80 and 445.
- So the labels mark the victim's traffic during the attack period, not the attacker. This
  matches the documented CIC problem (41.7% of web brute force is non-HTTP).
- 02-22 is reported as a secondary, label-noisy domain.
- The decision uses label provenance only, not any model result.

**Primary attack domains (9):**
- NetFlow: NF-CIC 02-14, 02-16, 02-20, 02-21 and 03-02, plus NF-UNSW;
- Zeek: IoT-23 3-1, 34-1 and 8-1.

**Change 2: the H3 comparator, made operational.**
- "Calibration hold-out separation" cannot be computed: clean calibration windows contain no
  attacks.
- H3 therefore compares F-or with **the better of B-loc@T0(α) and B-rz@T0(α) per held-out
  domain, chosen with that domain's evaluation labels** (an oracle choice).
- No deployable selection rule can beat this oracle, so the change makes the H3 test
  stricter.

**Change 3: definitions for windows of attacking entities.**
- An entity is *attacking* if any of its evaluation windows is an attack window.
- Label-benign negatives are the evaluation windows of non-attacking entities, minus noisy
  windows.
- Non-attack windows of attacking entities are excluded from both FPR and recall.

## Amendment A2 (2026-10-29): after a timing smoke run, before the registered run

**Finding.** The smoke run used one seed and a reduced training cap. Its outputs are not
used, and no comparison between methods was looked at. It showed that IoT-23 34-1 and 8-1
contain **only the attacking device**: 0 label-benign evaluation windows. IoT-23 20-1 and
21-1 have the same property.

**Change.**
- H1's metric P1 (recall at FPR 1% on the domain's own label-benign windows) and every FPR
  measure need label-benign windows. A domain with fewer than 60 is therefore excluded from
  H1 and from FPR summaries.
- It stays in H3: P3 is recall at the threshold set from its own calibration data, and is
  defined there.
- H1 primary domains (7): NF-CIC 02-14, 02-16, 02-20, 02-21, 03-02; NF-UNSW; IoT-23 3-1.
  The smallest attainable sign-flip p is 1/128.
- H3 primary domains (9): as amendment A1.
- H3's FPR condition (median realised FPR ≤ 1.5α) is computed over the H3 domains that have
  label-benign windows.

**Implementation note.**
- B-rz scores the hold-out and the evaluation windows in separate calls from one
  deterministic fit, because the window spanning the midpoint exists in both.
- The `--cap` option is for timing only. The registered run uses the default cap of 200,000.
