# NetSentinel AI: Research Questions and Hypotheses

- **Date:** 2026-10-19
- **Status:** Every statement in the "Proposed experiments" sections is a **hypothesis, not a finding**. This document reports **no NetSentinel results**. Evidence cited from other work is in `literature_review.md` (section numbers in brackets, e.g. [3.2]).

## Core research question

> Does modelling normal behaviour per application/service, combined with temporal representations of traffic, improve flow-based intrusion detection over flow-level classifiers? Improvement is judged on operational false-alarm cost and on detection of attack families not seen in training, under leakage-aware evaluation on CSE-CIC-IDS2018.

## Data constraints that bound every hypothesis

| Constraint | Consequence |
|---|---|
| The processed CSVs have no IPs (except 2018-02-20). | Per-host baselines and per-host temporal state (Kitsune-style channels [4.1], host graphs [5.6]) are **infeasible**. Temporal context can only be network-wide or per destination port, from trailing windows. |
| Each attack family appears on only one or two of 10 days. | Family and day are confounded. Leave-family-out is in effect leave-day(s)-out, so day-level shift cannot be separated from family novelty. |
| Original labels are partly wrong [3.1, 3.2]. | Results on original labels measure artefacts as well as detection. A corrected-label track is required wherever corrected labels can be aligned. |
| No service/application ground truth. | "Application conditioning" can only use **port-derived service categories** (for example 21/22/80/443/445/3389/53/other). Real application conditioning requires adding ISCX VPN-nonVPN [2.3], which has its own shortcut risks [5.4]. |
| Destination port is a known shortcut [3.1]. | Attacks in IDS2018 target fixed ports. Conditioning on port can leak the label, so every port-conditioned result needs a port-shuffled or port-ablated control. |
| No port-scan label. | The Nmap scan inside the Infiltration days [3.2] is the only scan behaviour present, and it is labelled "Infiltration". |
| Machine: 8 GB RAM, 4 GB VRAM. | Develop on samples of 10k rows or 5% or less of the data. Full 16M-flow runs need chunked feature building or Colab. Training runs over 2 minutes need approval. |

---

## Part A: Established methods we reuse (not novel, not under test)

These are tools taken from prior work. Using them is a design decision, not a claim.

| Component | Source | Use in NetSentinel |
|---|---|---|
| Trivial baselines | Arp et al. [1.5] | Majority/Dummy classifier; boxplot/IQR threshold on trailing flow counts per window. |
| Linear and tree classifiers | Grinsztajn et al. [8.1] | LogReg, RF, HistGB, LightGBM on per-flow features. |
| Isolation Forest, robust z / median-MAD scores | Standard | Unsupervised anomaly baselines, fitted on benign training flows only. |
| Autoencoder reconstruction score | Kitsune [4.1], USAD [4.2] | Benign-only AE on flow features and on window aggregates. |
| GRU and TCN sequence encoders | Bai et al. [4.5] | Compact temporal models over trailing windows of flows or aggregates. |
| Max-softmax OOD score | Hendrycks & Gimpel [6.2] | Required baseline for unseen-family detection. |
| Open-set framing | Scheirer et al. [6.1] | Leave-attack-family-out protocol. |
| Time-aware splits; spatial/temporal bias | TESSERACT [6.3], Arp et al. [1.5] | Chronological and day-held-out splits with realistic test prevalence. |
| Temperature / Platt / isotonic calibration | Guo et al. [7.1] | Calibrate on the validation split before fusion. |
| Undersampling correction | Dal Pozzolo et al. [7.3] | Map posteriors back to the true base rate after benign subsampling. |
| Per-class calibration reporting | Wallace & Dahabreh [7.2] | Stratified Brier score and per-class reliability curves. |
| Corrected labels and "Attempted" category | Engelen et al. [3.1], Liu et al. [3.2] | Corrected-label evaluation track; label-suspect class flags. |

### Common evaluation protocol (applies to H1-H5)

1. **Splits** (indices saved to disk; seeds recorded in the run ledger):
   - **S-rand:** stratified random row split. Reported only as the H5 contrast.
   - **S-block:** within-day contiguous time blocks with an embargo gap at least as long as the longest trailing window. Closed-set: each attack family has blocks in train and test.
   - **S-day:** whole days held out (chronological where possible). This makes most test families unseen, so it is partly open-set.
   - **S-LOFO:** leave-one-attack-family-out. Train on all other days and families plus benign. Test on the held-out family's day(s) plus the benign flows from those days.
2. **Test set is touched once.** All model, threshold and calibration choices use validation data carved from the training period with the same split logic.
3. **Primary operating point:** thresholds are fixed on validation benign flows at FPR = 1e-3. FPR = 1e-4 is reported as secondary.
4. **Metrics reported for every run:**
   - recall at fixed FPR;
   - PR-AUC at the test period's true prevalence (after undoing subsampling);
   - macro-F1 over attack classes;
   - false alerts per hour of capture;
   - per-class recall and precision;
   - ECE and stratified Brier for probabilistic outputs.
5. **Uncertainty:** report the mean and spread over 5 seeds. Report bootstrap CIs over time blocks (not rows), because rows are correlated.
6. **Label tracks:**
   - (a) original labels, with suspect classes flagged [3.2];
   - (b) corrected DistriNet labels where they can be aligned. Their features come from a modified CICFlowMeter, so track (b) may need its own feature extraction.
7. **Leakage guards:**
   - Timestamp, Flow ID, IPs and ports are excluded as raw features. Port is used only through the explicit service-category variable, with a control.
   - Shortcut-feature ablations: Init Win bytes Fwd/Bwd, Fwd Header Len, Min Seg Size Fwd, flag counts.
   - Window features are strictly trailing (causal).
8. **Error analysis after every serious run:** confusion matrix, metrics per day / per port category / per class, worst false positives and false negatives.

---

## Part B: Proposed experiments (untested hypotheses)

### H1: Temporal context reduces false positives

- **Hypothesis.** At a fixed recall, adding trailing-window context features to a per-flow classifier lowers the benign false-alarm rate compared with the same classifier on per-flow features only.
- **Operational definition.**
  - *Temporal context* means features computed only from flows strictly before the current flow's start time. Window lengths are 10 s, 60 s and 600 s, computed (a) network-wide and (b) per destination-port category.
  - Features: flow count, unique destination-port count (network-wide only), median and IQR of duration and bytes, SYN/RST ratios, inter-arrival statistics.
  - *False positive* means a benign flow (under the label track in use) scored above the threshold.
- **Comparison.**
  - **F0:** LightGBM on per-flow features.
  - **F1:** F0 plus network-wide windows.
  - **F2:** F0 plus per-port-category windows.
  - **F3:** F1 plus F2.
  - **B0:** boxplot/IQR on window flow counts alone (Arp-style trivial baseline [1.5]).
  - All variants share the same splits: S-block primary, S-day secondary.
- **Primary metric:** false alerts per hour at recall matched to F0's recall at validation FPR = 1e-3. Secondary: recall at FPR 1e-3, PR-AUC.
- **Supports H1:** F1, F2 or F3 reduces false alerts per hour by a margin whose block-bootstrap 95% CI excludes 0 on S-block, and the reduction remains on S-day.
- **Refutes H1:** no reduction, a reduction only on S-rand, or B0 alone matches F1-F3. B0 matching would mean the gain is a volume signal, not contextual discrimination.
- **Threats to validity.**
  - **Schedule leakage:** network-wide load rises during the one or two scheduled attacks per day, so windows can encode "attack is running now". Control: S-day; a per-port-only variant (F2); a test on benign flows inside attack windows versus outside them.
  - The timestamp time zone or offset is not documented [2.2]. A wrong alignment corrupts window features near attack boundaries.
  - Flows split by the 120 s timeout inflate counts for long attacks such as Slowloris.
- **Feasibility:** **feasible** with network-wide and per-port windows only. Per-host context is **infeasible**. Window building over about 16M rows needs chunked, sorted processing to stay within RAM.

### H2: Service-conditioned anomaly detection separates harmless-unusual from suspicious

- **Hypothesis.** An anomaly score computed relative to a benign model of the flow's own service category separates benign-but-rare flows from attack flows better than a global benign model.
- **Operational definition.**
  - *Service category* is derived from destination port (and protocol) into about 8-12 buckets, plus "other".
  - Optionally, the category is a predicted service from a classifier with abstention. A flow is abstained (falls back to the global model) when max probability is below a threshold chosen on validation.
  - *Harmless-unusual* means benign flows in the top 1% of the global anomaly score.
  - *Suspicious* means attack flows.
- **Comparison.**
  - **A-global:** Isolation Forest / robust-z / AE fitted on all benign training flows.
  - **A-cond:** the same detectors fitted per service category.
  - **A-cond-shuf:** A-cond with service categories randomly permuted. This is the control for the port shortcut.
  - **A-cond-pred:** conditioned on predicted service with abstention.
  - Splits: S-block and S-LOFO.
- **Primary metric:** PR-AUC for attack vs benign restricted to the top-1% global-anomaly set (the "unusual" pool). Secondary: recall at FPR 1e-3 over all flows; false alerts per hour.
- **Supports H2:** A-cond beats A-global on the unusual-pool PR-AUC (CI excludes 0), A-cond-shuf does not, and the gain holds under S-LOFO.
- **Refutes H2:** no gain; or the gain disappears under shuffling or S-LOFO, which would indicate port-identity leakage rather than better normal-behaviour modelling.
- **Threats to validity.**
  - Attacks use fixed destination ports (21, 22, 80, 8080, and others). A per-port model can flag "any traffic on a rarely-benign port".
  - Port-derived categories are not applications: port 80/443 mixes many applications. Benign generation by B-Profile agents is synthetic [2.1], so "harmless-unusual" benign traffic may be scarce or unrealistic.
  - Category sample sizes are uneven, and small categories give unstable detectors.
- **Feasibility:** **partially feasible.** Only port-derived categories are possible on IDS2018. True application conditioning is **infeasible** unless ISCX VPN-nonVPN [2.3] is added. Even then, it is a different capture and network, application inference would need session-aware splits because of the shortcut risk [5.4], and only cross-dataset transfer of the service model could be tested.

### H3: Multi-scale temporal modelling captures attacks hard to see from single flows

- **Hypothesis.** For attack classes where single-flow detection is weak, a compact sequence model over multi-scale trailing windows improves recall at fixed FPR over (a) the per-flow GBDT and (b) the GBDT with hand-built window aggregates.
- **Operational definition.**
  - *Hard to see from single flows* means classes whose F0 recall at validation FPR 1e-3 is below 0.5 on S-block. The class list is set from validation, not test.
  - *Multi-scale* means the input contains sequences at two or more window lengths (for example the last 32 flows plus 60 s and 600 s aggregate series).
  - Padding and masking conventions are fixed in advance and reported [6.5].
- **Comparison.**
  - **F0:** per-flow GBDT.
  - **F3:** GBDT with window aggregates, as in H1.
  - **T-GRU:** GRU over multi-scale sequences.
  - **T-TCN:** TCN over multi-scale sequences.
  - **T-single:** T-GRU/T-TCN with a single scale (ablation).
  - **B0:** IQR window baseline.
  - Splits: S-block primary, S-day secondary.
- **Primary metric:** recall at FPR 1e-3 on the pre-registered hard classes. Secondary: macro-F1 over all classes; false alerts per hour; compute and memory cost.
- **Supports H3:** T-GRU or T-TCN beats **F3**, not just F0, on hard-class recall with a CI that excludes 0, and multi-scale beats single-scale.
- **Refutes H3:** the temporal models do not beat F3. That would mean the window aggregates carry the signal and sequence modelling adds nothing. The hypothesis is also refuted if the gain appears only on S-rand, or vanishes when padding is changed.
- **Threats to validity.**
  - Many hard classes are label-suspect (web brute force, XSS, SQLi, Infiltration) [3.2]. Gains could come from learning label-window artefacts, so the corrected-label track is required for H3 claims.
  - Network-wide sequences mix flows from unrelated hosts because no IPs are available.
  - Few positive examples exist (SQLi is tiny), so CIs will be wide.
- **Feasibility:** **feasible locally** for GRU/TCN with batch 16-32, sampled sequences and 1-epoch GPU smoke tests. Full training probably exceeds 2 minutes and therefore requires approval, with Colab as an option.

### H4: Fusing supervised probability and anomaly score improves detection of unseen attack families

- **Hypothesis.** Under leave-attack-family-out evaluation, a calibrated fusion of the supervised attack probability and a benign-trained anomaly score detects the held-out family better than either score alone and better than the max-softmax OOD baseline.
- **Operational definition.**
  - *Unseen family:* one of {brute force (FTP/SSH), DoS, DDoS, web, infiltration, bot}, removed entirely from training and validation.
  - *Fusion:* logistic regression (stacking) over [calibrated P(attack), calibrated anomaly percentile]. A noisy-OR variant is the comparator.
  - Calibration and fusion weights are fit on validation folds that also exclude the held-out family.
- **Comparison.**
  - **S:** supervised GBDT P(attack).
  - **U:** best anomaly detector from H2.
  - **MSP:** 1 - max softmax of the multi-class GBDT [6.2].
  - **Fuse:** fusion of S and U.
  - **Fuse-uncal:** fusion without calibration (ablation).
  - Split: S-LOFO, one run per family.
- **Primary metric:** recall of the held-out family at FPR 1e-3 on benign flows from the same test day(s). Secondary: PR-AUC at true prevalence; ECE and stratified Brier; false alerts per hour.
- **Supports H4:** Fuse beats S, U and MSP on held-out-family recall in the majority of families (pre-registered threshold: at least 4 of 6), with no family losing more than a pre-set margin. Calibration also matters (Fuse beats Fuse-uncal).
- **Refutes H4:** Fuse is no better than the better of S and U, or gains appear only for volumetric families that cross-dataset work already finds easy [3.5].
- **Threats to validity.**
  - Family is confounded with day, so a gain may reflect day shift, not novelty.
  - A family's held-out day also has a different benign mix.
  - Families share tooling (for example DoS and DDoS both hit HTTP), so "unseen" is partial.
  - Labels for infiltration and bot are unreliable [3.2].
  - Only 6 folds, so per-family results are anecdotal and must be reported individually, not only averaged.
- **Feasibility:** **feasible**. GBDT plus classical anomaly detectors run on CPU. Six folds times five seeds on sampled data fits locally. A full-data version needs approval or Colab.

### H5: Random row splits and temporal/group-aware splits give materially different results

- **Hypothesis.** For the same models and features, S-rand gives materially higher scores than S-block, S-day and S-LOFO, and the size of the gap differs by model family.
- **Operational definition.** *Materially different* means a pre-registered gap of at least 0.05 absolute in macro-F1, or at least a 2x ratio in false alerts per hour at matched recall. Gaps are measured per class as well as in aggregate.
- **Comparison.** Models F0, F3, T-GRU, T-TCN, IsolationForest and AE, each evaluated on S-rand vs S-block vs S-day vs S-LOFO. The test-set prevalence is identical across splits where possible. Both label tracks are used.
- **Primary metric:** macro-F1 gap and false-alerts-per-hour ratio, S-rand versus each leakage-aware split. Secondary: the change in model ranking across splits (Kendall tau).
- **Supports H5:** the gap meets the pre-registered threshold for at least one model family, and the model ranking changes.
- **Refutes H5:** gaps fall below the threshold for all models and the ranking is stable. This would be a useful negative result and must be reported as such.
- **Threats to validity.**
  - S-day changes the class set, so it is not a pure "leakage" contrast. S-block is the cleaner contrast against S-rand.
  - The embargo length is a design choice, so sensitivity to it must be reported.
  - Label noise may shrink or inflate gaps differently on the two label tracks.
- **Feasibility:** **feasible**. This is the cheapest hypothesis and should run first, because its outcome determines how H1-H4 are reported.

---

## Recommended order and decision points

1. **Before any modelling (data audit):**
   - Align timestamps to the documented attack windows and determine the time zone/offset empirically.
   - Build label-suspect flags [3.2].
   - Check for protocol-0, ARP-as-IP and duplicate header rows.
2. **H5 first.** It fixes the reporting protocol.
3. **Baselines** (Dummy, B0, LogReg, RF, HistGB, LightGBM) on S-block and S-day.
4. **H1, then H3.** H3 is only worth running if F3 leaves hard classes unsolved.
5. **H2, then H4.** H4 reuses H2's anomaly detector.
6. **Optional extension:** add ISCX VPN-nonVPN for real application conditioning (H2). This requires a separate leakage review [5.4].

Every step above is a plan. None has been run, and no outcome is assumed.
