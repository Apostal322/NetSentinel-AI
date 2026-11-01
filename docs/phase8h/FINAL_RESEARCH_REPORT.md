# Window-level network attack detection under distribution shift: a pre-registered negative study (NetSentinel AI, Phase 8h)

**Status.**
- Every result here is **exploratory [E]**: all data were inspected in earlier phases of the
  project.
- No result is confirmatory, and no Phase 8h method changes the deployed detector.
- **Phase 8h is closed.**

**Artifacts.**
- Protocol: [PREREGISTRATION.md](PREREGISTRATION.md) (amendments A1–A3).
- Order of events and deviations: [AUDIT_TRAIL.md](AUDIT_TRAIL.md).
- Registered analysis: `reports/phase8h/analysis.json`.
- Exploratory analysis: `reports/phase8h/exploratory_summary.json` and
  `shift_diagnostics.json`.

**Revision note (2026-11-01).** A skeptical review of the first draft upheld 45 findings
about numbers, populations and over-strong mechanisms. This version corrects them; the
upheld list is summarised in [AUDIT_TRAIL.md](AUDIT_TRAIL.md) §6. No registered verdict
changed.

## Abstract

**Question.** Supervised models rank network-attack windows almost perfectly inside the
network they were trained on, but fail on another network. Thresholds calibrated on a short
benign period overrun their false-alert target. We test whether any of these helps:
- a different representation: per-network robust standardisation (H1a), or a new screening
  of benign-unstable features (H1b);
- block-bootstrap thresholds for dependent windows (H2);
- conservative fusion of a supervised and an anomaly score (H3).

**Setup.**
- Leave-one-domain-out over 30 s device windows from two telemetry families: NetFlow
  (5 NF-CIC-IDS2018 attack days plus NF-UNSW-NB15) and Zeek (IoT-23, CTU-Normal).
- 9 primary attack domains, 27 benign evaluation units, 3 seeds.

**Result. All four pre-registered hypotheses fail.**
- H1a: Δ oracle recall at 1% FPR = −0.256 (95% CI −0.57 to +0.04).
- H1b: Δ = −0.081, and harmful on one domain.
- H2: units over 2% FPR, 8/27 for both thresholds.
- H3: Δ = −0.093.

**Exploratory diagnostics.**
- **Benign traffic is nearly identical across days of one network** (median KS ≤ 0.054 on 11
  of 12 features) and differs strongly between two networks (KS up to 0.85). A classifier
  identifies the network from benign windows alone with ROC-AUC 0.9999.
- **Raw-feature LightGBM ranks within NF-CIC almost perfectly**: oracle recall ≈ 1.0 at 1%
  FPR, with the threshold set on the target's own labels. That holds on 5 of 5 held-out
  attack days (4 families; LOIC and HOIC are both DDoS). At its calibrated threshold the
  realised FPR was 1.8–3.5%.
- **On NF-UNSW it reaches 0.03.**
- **Removing the four volume features** costs within-network detection of floods, but raises
  NF-UNSW ROC-AUC from 0.39 to 0.93 and PR-AUC from 0.25 to 0.67. Recall at 1% FPR does not
  recover.

**Conclusion.** Neither standardisation, invariance screening, resampling-based thresholds
nor fusion removes the cross-network failure. Volume features that shift between networks
are one supported, exploratory contributor.

## 1. Introduction

Flow-based intrusion detection is usually evaluated within one dataset: one network, one
labelling policy, one tool. Earlier phases of this project showed that:
- supervised flow models reach recall 0.98–1.00 at FPR 10⁻³ in-dataset, but ROC-AUC
  0.37–0.66 across datasets (Phase 5, confirmatory);
- a local robust baseline keeps its false-alert budget on some fresh captures but misses
  attackers (Phase 8b: 0 of 4);
- on CTU-13, the baseline found 10 of 10 bots at window recall 0.21 (Phase 8g).

Phase 8h asks which part of this failure is due to representation, to calibration, or to
missing evidence fusion.

## 2. Research questions

- **RQ1.** Do per-network standardisation or benign-stability feature screening transfer
  attack ranking across domains better than raw features?
- **RQ2.** Do thresholds that account for temporal dependence keep a 1% false-alert target
  better than split-conformal thresholds?
- **RQ3.** Does conservative fusion of a supervised and an anomaly score detect more than
  the better single score at a controlled false-alert rate?

## 3. Related method families (no claim of novelty)

- **Robust location/scale anomaly scores.** Median/MAD z-scores with a top-k aggregate,
  i.e. the deployed baseline.
- **Gradient-boosted trees for tabular detection.** LightGBM.
- **Split-conformal thresholds** and their exchangeability assumption.
- **Moving-block bootstrap** for dependent data.
- **Score fusion with Bonferroni-style budget splitting.**
- **Invariance-based feature selection.** N-dis, below, is a simple instance of this family,
  not a new principle.

## 4. Data, telemetry and labels

| family | domains | attackers | role |
|---|---|---|---|
| NetFlow (nProbe v3) | NF-CIC-IDS2018 development part, one domain per day (first 78% of each day; the consumed one-shot test starts at 80%): 02-14 SSH-BF, 02-16 DoS-Hulk, 02-20 DDoS-LOIC, 02-21 DDoS-HOIC, 03-02 Bot | 1, 1, 10, 10, 7 | primary attack domains |
| NetFlow | NF-CIC 02-15, 02-23, 02-27 (304 windows; too small to be an attack domain), 02-28, 03-01 | — | benign evaluation units (H2) |
| NetFlow | NF-UNSW-NB15-v3 development part (another network) | 4 | primary |
| NetFlow | NF-CIC 02-22 web attacks | labels mark the victim's traffic (562 sources to one host) | secondary (A1) |
| Zeek conn.log | IoT-23 3-1, 34-1, 8-1 (one attacking device each); CTU-Normal, honeypots, other IoT-23 | 1 each | primary / benign units |

**Windows.**
- 30 s windows per source address, with 12 features:
  - `log_flows`, `log_up_bytes`, `log_down_bytes`, `log_pkts`, `log_dst_hosts`,
    `log_dst_ports`;
  - `no_reply_frac`, `rst_frac`, `udp_share`, `med_log_dur`, `upload_share`,
    `new_dst_frac`.
- Calibration: windows ending before each domain's time midpoint. Evaluation: the rest.

**Labels.**
- An attack window contains an attack-labelled flow.
- *Label-benign* windows belong to entities that never attack in the domain. They are
  verified benign only for CTU-Normal; elsewhere they carry the dataset's benign label.
- NF-CIC infiltration windows are excluded (label noise).

**Telemetry is never pooled.** `no_reply_frac` and `rst_frac` come from TCP flags in
NetFlow and from `conn_state` in Zeek. Models are trained and evaluated within one family.

## 5. Methods

Notation:
- x ∈ ℝ¹² is a window's feature vector; d a domain.
- C_d are d's clean calibration windows.
- m_d and s_d are the per-feature median and MAD of C_d, with s_d floored at 0.15 for
  fractions and 0.25 otherwise.

**Scorers.**
- **B-raw:** LightGBM on x. 200 trees, learning rate 0.05, 15 leaves, row and column
  subsampling 0.8. Equal total weight per source domain; balanced classes within a domain;
  at most 200,000 training windows per domain.
- **B-loc:** the same model on z = clip((x − m_d) / (1.4826 · s_d), −10, 10). The target uses
  its own calibration statistics, with no labels.
- **N-dis (new).**
  - For each feature f, the instability I_f is the median over pairs of source domains
    (d, d′) of W₁(z_f^d, z_f^d′).
  - The Wasserstein-1 distances are computed on calibration windows of non-attacking
    entities, at most 5,000 per domain. z uses the scaler fitted on all of d's calibration
    windows.
  - Features with I_f ≤ median_f I_f are kept, and B-loc is retrained on them.
- **B-lr:** L2 logistic regression (C = 1) on z.
- **B-rz:** the deployed robust baseline. Per-entity or pooled median/MAD z, score = mean of
  the two largest |z|. It is fitted on the first 70% of the target's calibration windows.

**Thresholds** (target α = 0.01), from the hold-out H, i.e. the last 30% of calibration
windows (n = |H|):
- **T0:** the k-th order statistic of the hold-out scores, k = ⌈(n+1)(1−α)⌉. If k > n, it is
  the maximum. At α = 0.01, k = n (the maximum) for every n ≤ 198.
- **T1:** the 90th percentile, over 1,000 moving-block resamples (blocks of 20 occupied
  window slots), of T0 recomputed on the resample. If there are fewer than 40 slots, T1 = T0.
- **T2:** separate T0 thresholds for entities with ≥ 30 calibration windows and for the rest.
- **T3:** T1, but the domain abstains when the bootstrap 5–95% width exceeds 0.5 · T0.
- **Deployed cross-fit (reference):** the product threshold from cross-fitted scores of
  B-rz refitted on all calibration windows.

**Fusion.**
- F-or alerts if s_A > T0_A(α/2) or s_B > T0_B(α/2), with A = B-loc and B = B-rz.
- Its comparator is the better of A@T0(α) and B@T0(α) per domain, chosen with evaluation
  labels (an oracle choice).

**Metrics** (per held-out domain):
- **Oracle recall at FPR 1%:** recall of attack windows at the 99th percentile of that
  domain's label-benign scores. A ranking metric: the threshold uses target labels.
- **Window recall, entity recall and FPR at the operating threshold.**
- **False alerts per hour, PR-AUC and ROC-AUC** (attack vs label-benign windows).
- **Delay:** first alerted attack window minus the entity's first attack window.

**Statistics.**
- The unit is the held-out domain.
- Exact one-sided sign-flip test on paired differences, 95% bootstrap CI over domains.
- Exact one-sided McNemar test for H2.
- Holm correction over the four primary tests (family α = 0.05).

## 6. Experimental protocol

**Order of events** (git and file times; [AUDIT_TRAIL.md](AUDIT_TRAIL.md)):
1. Pre-registration.
2. A1, after building the NF-CIC windows.
3. Timing smoke runs. One printed per-model recalls for IoT-23 34-1; the 02-16 run also wrote
   a per-model results file. Both are disclosed.
4. A2.
5. The registered grid started (code `4476fc8`).
6. The analysis script was committed.
7. The blind code review and A3 happened while the grid ran. A3 fixed 3 defects and
   disclosed 3 deviations; the screening issue was then resolved by a strict re-run.
8. The grid finished. The A3 corrective runs followed.
9. First inspection of results.

**Seeds.** LightGBM seeds 0, 1 and 2; metrics are averaged over seeds per domain.

**Exploratory work after the registered tests**, with deviations from pre-registration §6:
- ablations were run for B-raw, not for N-dis, B-loc and F-or;
- the calibration-length study compares T0 with the deployed cross-fit rule, not T0 with T1;
- shift diagnostics.

**Compute.** 8 GB RAM, CPU, 3.4 GB watchdog (never triggered). Peak process RSS was about
2.0 GB (calibration-length run); the watchdog's sampled peak was 1.91 GB.

## 7. Results

### 7.1 Registered hypotheses (H1 over 7 domains, H3 over 9, H2 over 27 units)

| hypothesis | comparison | mean Δ [95% CI] | one-sided p | registered rule | verdict |
|---|---|---|---|---|---|
| H1a | B-loc − B-raw, oracle recall at FPR 1% | −0.256 [−0.571, +0.039] | 0.875 | mean Δ ≥ 0.05 and Holm | **fail** |
| H1b | N-dis − B-loc | −0.081 [−0.421, +0.161] | 0.609 | as H1a; harmful if any Δ < −0.20 | **fail (harmful on DDoS-HOIC: −0.999)** |
| H2 | B-rz T1 vs T0, units with FPR > 2% | 8/27 vs 8/27 (0 discordant) | 1.0 | exceedance(T1) ≤ ½ exceedance(T0), McNemar under Holm, median recall loss ≤ 0.10 | **fail** |
| H3 | F-or − oracle-best single, window recall at threshold | −0.093 [−0.231, −0.000] | 1.0 | mean Δ ≥ 0.05, median FPR ≤ 1.5%, entity recall not worse in ≥ 75% | **fail** (median FPR 1.54%; entity recall not worse in 67%) |

**Per domain** (oracle recall at FPR 1%), [Figure 1](figures/fig1_oracle_recall.png) and
[Figure 2](figures/fig2_paired_deltas.png):

| domain (family) | B-rz | B-lr | B-raw | B-loc | N-dis | F-or |
|---|---|---|---|---|---|---|
| NF-UNSW (other network) | 0.00 | 0.32 | 0.03 | 0.00 | 0.03 | 0.00 |
| CIC 02-14 SSH-BF | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| CIC 02-16 DoS-Hulk | 0.07 | 0.96 | 1.00 | 1.00 | 0.96 | 1.00 |
| CIC 02-20 DDoS-LOIC | 0.00 | 0.09 | 0.99 | 0.08 | 0.00 | 0.08 |
| CIC 02-21 DDoS-HOIC | 0.00 | 0.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| CIC 03-02 Bot | 0.00 | 0.97 | 1.00 | 0.00 | 0.38 | 0.00 |
| IoT-23 3-1 (Zeek) | 1.00 | 0.95 | 0.71 | 0.86 | 1.00 | 1.00 |

**Macro means, both families:**

| model | ranking (7 domains) | | | operating point, T0 (9 domains) | | | |
|---|---|---|---|---|---|---|---|
| | PR-AUC | ROC-AUC | oracle recall | window recall | entity recall | FPR | false alerts/h |
| B-raw | 0.749 | 0.889 | 0.818 | 0.856 | 1.000 | 0.026 | 340 |
| B-lr | 0.555 | 0.804 | 0.613 | 0.714 | 0.889 | 0.015 | 184 |
| B-loc | 0.621 | 0.933 | 0.562 | 0.704 | 0.896 | 0.021 | 301 |
| N-dis | 0.450 | 0.936 | 0.481 | 0.796 | 1.000 | 0.023 | 325 |
| F-or | 0.627 | 0.962 | 0.582 | 0.622 | 0.853 | 0.015 | 268 |
| B-rz (deployed baseline) | 0.267 | 0.944 | 0.153 | 0.194 | 0.444 | 0.009 | 160 |

**Notes on the table.**
- FPR and false alerts/h cover only the domains that have label-benign windows.
- **B-rz on NetFlow alone** (6 domains): oracle recall 0.012 (non-zero only on DoS-Hulk,
  0.07); entity recall at T0 1 of 6 (0.17). Its all-domain macros (0.153, 0.444) are lifted
  by the Zeek domains.
- Micro window recall at T0: B-raw 0.644, B-lr 0.713, B-rz 0.162.
- **B-raw on NF-CIC at T0:** realised FPR 1.8–3.5% per day, above the 1% target.
- False alerts per hour are large because each NF-CIC day has about 11,000–24,000 source
  addresses. They count label-benign windows above threshold and are not verified-benign.

### 7.2 Threshold reliability and calibration length

([Figure 3](figures/fig3_threshold_fpr.png), [Figure 5](figures/fig5_calibration_length.png))

| rule (B-rz, 27 units, full calibration) | units with FPR > 2% | median FPR |
|---|---|---|
| T0 split-conformal | 8/27 (29.6%) | 1.03% |
| T1 block bootstrap | 8/27 (29.6%) | 1.01% |
| T2 population-conditional | 10/27 (37.0%) | 1.07% |
| T3 selective | 3/19 (15.8%), coverage 70% | 0.96% |
| deployed cross-fit | 3/27 (11.1%) | 0.73% |

**Reconciliation of "8 of 27" and "11% vs 30%".**
- Both describe the **same 27 units** (`reports/phase8h/lodo_h2/`: ≥ 60 label-benign
  windows, secondary domain excluded), counted as units whose FPR exceeded **twice** the 1%
  target.
- 8/27 is T0 (and T1). 3/27 is the deployed cross-fit rule.
- They don't contradict each other.

**Cross-fit vs T0 (exploratory, untested).** 6 units overrun only under T0 and 1 only under
the cross-fit rule: exact one-sided McNemar p = 0.0625. This is suggestive at most.

**Why H2 could hardly succeed.**
- At α = 1%, T0 is the hold-out maximum whenever n ≤ 198. That is true for **17 of the 27
  units**, including all 8 overrunning ones (hold-outs of 21–121 windows).
- A bootstrap quantile cannot exceed the sample maximum, so T1 ≤ T0 there by construction.
  For 5 of the 8, the bootstrap was skipped entirely (fewer than 40 slots) and T1 = T0.
- With n exchangeable scores, the maximum's expected exceedance probability is 1/(n+1). That
  is ≥ 2% for n < 49, with no shift at all.
- So these overruns are consistent with **small-sample** effects. Phase 8h does not show
  whether shift contributes; that is Phase 8i's I2.
- The pre-registration did not anticipate this. It is a design limitation of H2.

**Calibration length (exploratory).** On the 11 units eligible at every length:

| calibration length | cross-fit: units with FPR > 2% | T0: units with FPR > 2% |
|---|---|---|
| 15 min | 4/11 | 2/11 |
| 30 min | 2/11 | 3/11 |
| 60 min | 1/11 | 2/11 |
| 120 min | 1/11 | 2/11 |

- The cross-fit rule improves with longer history, but is worse than T0 at 15 minutes. T0 is
  flat. There is no test, and the trend rests on 3 units.
- The unpaired summary, where units change with length, is non-monotonic.
- Calibration *length* is varied here, not calibration *age*: the windows always end at
  evaluation start.
- B-rz's median window recall on attack domains at its threshold is 0 at every length.

### 7.3 Feature ablations of B-raw (exploratory)

([Figure 4](figures/fig4_ablations.png))

| ablation | macro Δ oracle recall (7 domains; NF-CIC only) | domains collapsing (full → ablated) | NF-UNSW: oracle recall / ROC-AUC / PR-AUC |
|---|---|---|---|
| without volume (4 features) | −0.473; −0.597 | DoS-Hulk 1.00 → 0.01, LOIC 0.99 → 0.00, HOIC 1.00 → 0.00, IoT-23 3-1 0.71 → 0.40 | 0.03 → 0.01 / **0.39 → 0.93** / **0.25 → 0.67** |
| without `new_dst_frac` | −0.284; −0.392 | LOIC 0.99 → 0.00, Bot 1.00 → 0.03 | 0.03 → 0.00 / — / 0.25 → 0.24 |
| without `udp_share` | −0.110; −0.079 | LOIC 0.99 → 0.61, IoT-23 3-1 0.71 → 0.34 | 0.03 → 0.02 / — / 0.25 → 0.28 |

- **Within one network, every feature group helps.**
- **Across networks, removing volume features greatly improves overall ranking on NF-UNSW**
  (ROC-AUC 0.39 → 0.93, PR-AUC 0.25 → 0.67).
- At the calibrated threshold it also raises recall (0.09 → 0.38) while lowering FPR
  (6.1% → 4.4%).
- **Only the extreme tail does not improve:** recall at 1% FPR stays near 0. One
  cross-network pair, three seeds.

## 8. Error analysis: why transfer fails (exploratory)

1. **Covariate shift between networks is large; between days it is not**
   ([Figure 6](figures/fig6_benign_shift.png)).
   - Benign windows: median KS between one NF-CIC day and the other days is ≤ 0.054 for 11
     of 12 features (0.10 for `new_dst_frac`).
   - NF-CIC vs NF-UNSW: KS 0.78–0.85 for the six count and volume features; 0.70–0.71 for
     `udp_share` and `upload_share`; 0.50 for `rst_frac`; 0.13 for `new_dst_frac`.
   - So leave-one-day-out within NF-CIC tests **new attacks against familiar benign
     traffic**, not domain generalisation.
2. **Network identity is fully encoded.**
   - LightGBM separates NF-CIC from NF-UNSW benign windows with test ROC-AUC 0.99994 (train on
     the first half of each domain, test on the second).
   - Top features: `log_pkts`, `log_up_bytes`, `upload_share`, `med_log_dur`,
     `log_dst_ports`.
3. **Volume features: a supported, not proven, contributor.**
   - NF-UNSW benign windows have median `log_flows` 4.3, against 1.1 for NF-CIC benign
     (NF-CIC benign 95th percentile: 3.3).
   - Among the NF-CIC attack days, DoS-Hulk and HOIC (and SSH-BF) sit at 6.9–8.1. LOIC (2.4)
     and Bot (3.4) sit below NF-UNSW's benign median.
   - Removing volume features raises NF-UNSW ROC-AUC from 0.39 to 0.93, which is consistent
     with volume carrying network identity. The extreme tail does not recover, so other
     factors remain.
4. **`new_dst_frac` is necessary for LOIC and Bot, in different ways.**
   - Removing it collapses both. On Bot it is 1.0 for ≥ 95% of attack windows: a direct
     novelty signal.
   - On LOIC the attack windows have value 0, like most benign windows, so its role there is
     through interactions.
   - SSH-BF has value 1.0 too, but does not depend on it.
   - The feature depends on history and topology. It shifts little between the two networks
     (KS 0.13) and is not among the domain-identity features.
5. **Standardisation (H1a) fails on the `new_dst_frac`-dependent domains.**
   - B-loc collapses on LOIC (0.08) and Bot (0.00), exactly the domains that the
     `new_dst_frac` ablation collapses. It keeps DoS-Hulk and HOIC at 1.00.
   - The mechanism is a hypothesis: no B-loc ablation was run.
6. **Invariance screening (H1b) is unstable.**
   - Compared with the as-run screening, the registered strict screening changed the kept set
     in 5 of 10 folds, by 1–2 of 6 features.
   - On HOIC, the strict set (without `log_flows` and `log_down_bytes`) scored 0. The as-run
     set scored 0.47. Which features matter for HOIC under B-loc was not tested.
   - A separate pre-check (`screen_check.py`, which refits the scaler on the strict windows)
     reported 7 of 10 changed folds. It does not describe the registered run.
7. **Fusion halves each component's budget** (H3). With B-loc the better component in 8 of
   9 domains, splitting α costs more recall than B-rz adds.
8. **Few attackers.**
   - 29 attacking sources across the 5 NF-CIC days; SSH-BF and DoS-Hulk have one attacker
     each.
   - IoT-23 34-1 and 8-1 contain only the attacker, so they have no FPR and no ranking
     metric.

**Label and taxonomy.**
- Attack labels mean different things: CIC flow labels per attack session; IoT-23
  per-capture malware labels; NF-CIC web-attack labels that mark victims.
- Phase 8h never pools labels across families, and it excludes the victim-labelled domain
  from primary tests.

## 9. Statistical interpretation

- **Uncertainty is large.** 7 (H1) and 9 (H3) domains. The CIs for H1a and H1b span about
  0.6. A sign-flip test over 7 domains reaches p = 1/128 only if every domain agrees.
- **Single domains dominate.**
  - H1a's negative mean comes from two catastrophic domains (LOIC, Bot).
  - H1b's comes from one (HOIC, −0.999), partly offset by a large gain (Bot, +0.38).
  - H3's comes mainly from LOIC.
  - Most domains show Δ ≈ 0.
- **Windows are not independent.** Inference is over domains, and window counts are never
  used as sample sizes.
- **Multiplicity.** Four registered tests with Holm correction. Everything else is
  exploratory and untested.
- **Selection.** No method was selected on these results for deployment.

## 10. Discussion

**What was learned.**
- **Within one network, LightGBM on raw window features ranks new attack days almost
  perfectly:** oracle recall ≈ 1.0 on 5 of 5 days, with familiar benign traffic. At its
  calibrated threshold it overruns the false-alert target. Neither result is evidence of
  portability.
- **Across networks it fails.** The benign feature distributions differ so much that the
  network is identifiable from benign traffic alone. Removing volume features improves
  overall cross-network ranking, but not the extreme tail that a 1% false-alert budget
  needs.
- **The deployed robust baseline is insensitive on NetFlow attacks:** oracle recall 0.012,
  1 of 6 domains detected. It works on the Zeek IoT-23 domains.
- **H2's null is uninformative about shift.** The overrunning units have small hold-outs,
  where neither T0 nor a bootstrap bound can be reliable.

## 11. Limitations

- **No fresh confirmation.** Every dataset was inspected in earlier phases.
- **One cross-network NetFlow pair** (NF-CIC → NF-UNSW). The Zeek family adds one attack
  domain with benign windows.
- **One lab per family.** The NF-CIC days share hosts and topology.
- **Not computed:** score calibration (Brier score, ECE), micro AUCs, F-learn.
- **Ablations only for B-raw.**
- **H2's design limit** for small hold-outs (section 7.2).
- **Protocol lapses before the rules were final** ([AUDIT_TRAIL.md](AUDIT_TRAIL.md) §2):
  printed recalls on one domain, and a per-model results file written for another.
- **Label-benign is not verified benign** outside CTU-Normal.

## 12. Reproducibility

```bash
uv run python scripts/phase8h/build_nf_cic.py
uv run python scripts/phase8h/lodo.py --family netflow --family zeek --seeds 0,1,2
uv run python scripts/phase8h/lodo.py --family netflow --family zeek --h2-only --out reports/phase8h/lodo_h2
uv run python scripts/phase8h/lodo.py --family netflow --family zeek --ndis-strict --seeds 0,1,2 --out reports/phase8h/lodo_ndis_strict
uv run python scripts/phase8h/analyze.py
uv run python scripts/phase8h/lodo.py --family netflow --family zeek --seeds 0,1,2 --ablate no_volume --out reports/phase8h/ablation_no_volume
uv run python scripts/phase8h/lodo.py --family netflow --family zeek --calsize 15,30,60,120 --out reports/phase8h/calsize
uv run python scripts/phase8h/explore_summary.py
uv run python scripts/phase8h/shift_diagnostics.py
uv run python scripts/phase8h/figures.py
```

- **Ablations:** repeat the ablation command with `--ablate no_new_dst_frac` and with
  `--ablate no_udp_share`, each with its own `--out`.
- **Inputs:** the Phase 8b development windows (`data/derived/phase8b/`); the NF-CIC interim
  Parquet (`data/interim/nf_cicids2018_v3/`, SHA-1 checked at ingest).
- **Environment:** Python 3.12 and LightGBM from `uv.lock`, with fixed seeds.
- **Models:** not serialised; the results are deterministic given seeds and inputs.
- **Tests:** `tests/unit/test_phase8h_stats.py` checks the statistics and threshold
  calculations.

## 13. Conclusion

**Main finding.** A pre-registered evaluation finds no support for any of the four
remedies.

**Exploratory evidence:**
- benign traffic differs between networks far more than between days of one network;
- the strongest model's within-network ranking relies on volume features, which carry
  network identity, and on a history-dependent novelty feature;
- removing the volume features improves overall cross-network ranking but not the extreme
  tail that operating budgets need.

**Implication.** Cross-network detection likely needs target-network information:
- a few labels (Phase 8i, I1);
- a shift-aware decision to abstain (I2);
- or features chosen against a domain-identity criterion (I3), validated on a fresh network.

See [PHASE8I_PROPOSAL.md](PHASE8I_PROPOSAL.md).

## Appendix: issue register

| # | severity | component | issue | evidence | status | blocks closure |
|---|---|---|---|---|---|---|
| 1 | medium | streaming | late records do not mark telemetry as degraded | Phase 8g scenario 10: 90 late records, health `ok` | open, documented (needs a validated rate threshold) | no |
| 2 | low | research scripts | `confirm_49_1.py` and `eval_incidents.py` leave `ns-h6-*` / `ns-inc-*` temp folders | listing of the temp directory | documented; frozen or unsafe to change | no |
| 3 | low | temp directories | existing orphaned `netsentinel-spill-*` and `ns-*` folders | provenance not provable | left in place | no |
| 4 | medium | protocol | pre-rule smoke outputs (34-1 printed; 02-16 file written) | audit trail §2 | disclosed | no |
| 5 | medium | H2 design | T0 is the hold-out maximum for n ≤ 198 (17/27 units); T1 ≤ T0 there | §7.2 | documented limitation | no |
| 6 | low | analysis | score calibration, micro AUCs, F-learn, ablations beyond B-raw not done | §11 | documented | no |
| — | research | generalisation | cross-network collapse | §8 | a research result, not a defect | no |
