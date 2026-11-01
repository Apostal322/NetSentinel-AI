# NetSentinel AI: ML portfolio summary

NetSentinel AI is an applied machine-learning research project on network-attack detection
under distribution shift.
- It is **not a production intrusion-detection system.**
- The working software is a local, detection-only analysis tool.
- The research findings below concern model behaviour on public and lab datasets.

## 1. GitHub project description (short)

> Applied ML research on network-attack detection under distribution shift: LightGBM and
> robust-statistics anomaly detection on flow windows, pre-registered cross-domain
> evaluation, calibration and fusion studies, and documented negative results. Detection-only
> research prototype (Python, polars, LightGBM, scikit-learn, FastAPI, Streamlit).

## 2. Detailed portfolio entry

**Problem.** Supervised flow-based intrusion detectors often score near-perfectly inside one
dataset and fail elsewhere. The project measures when and why, under a strict protocol:
- pre-registration;
- held-out domains;
- independent code review before the registered results were inspected (one earlier
  smoke-run output is disclosed in the audit trail);
- results labelled confirmatory or exploratory.

**What I built and trained:**
- **Feature engineering.** 30-second per-source window features (volume, fan-out, protocol
  mix, history-dependent destination novelty). Causal and streaming-safe, with a streaming
  engine checked against an exact offline reference on 11.6M real records.
- **Supervised models.**
  - LightGBM on raw and per-network standardised features;
  - logistic regression;
  - a domain-invariance feature-screening method (Wasserstein-1 instability across training
    domains).
- **Anomaly detection.** A robust median/MAD baseline with per-entity profiles and a pooled
  fallback. Earlier phases compared it with EWMA, Isolation Forest, GRU and TCN; the robust
  baseline won on fresh captures.
- **Calibration.** Split-conformal, moving-block-bootstrap, population-conditional and
  selective thresholds, compared with a cross-fitted threshold.
- **Fusion.** Bonferroni-budgeted OR-fusion of the supervised and anomaly scores.
- **Statistics.** Domain-level inference: exact sign-flip and McNemar tests, bootstrap CIs
  over domains, Holm correction. Windows are never treated as independent samples.

**Key results.** Phase 8h, exploratory, development data:
- **Within one network**, raw-feature LightGBM ranks held-out attack days almost perfectly:
  recall ≈ 1.0 at a 1%-FPR threshold set on the target's labels, on 5 of 5 days and 4
  families. At its calibrated threshold, the realised FPR was 1.8–3.5%.
- **On a different network** (NF-UNSW-NB15) it reaches 0.03.
- **Diagnosis.**
  - Benign traffic is nearly identical across days of one network (median KS ≤ 0.054 on 11
    of 12 features) but differs strongly across networks (KS up to 0.85).
  - A classifier identifies the network from benign windows alone at ROC-AUC 0.9999.
  - Removing the four volume features raises cross-network ROC-AUC from 0.39 to 0.93, but
    not recall at 1% FPR, and it costs within-network flood detection.
- **All four pre-registered remedies failed:**
  - per-network standardisation: Δ −0.26;
  - invariance screening: Δ −0.08, harmful on one domain;
  - block-bootstrap thresholds: no change, 8/27 units over twice the target;
  - fusion: Δ −0.09.

**Earlier pre-registered results**, confirmatory on data used once:
- in-domain supervised recall 0.98–1.00 at FPR 10⁻³, and cross-network ROC-AUC 0.37–0.66
  (Phase 5);
- on the CTU-13 botnet capture, the deployed detector flagged all 10 documented infected hosts
  at window recall 0.21, with 0 alerts on 803 verified-benign windows (Phase 8g);
- a model-update gate absorbed 71% of the attack windows. Its root cause was found and a
  review safeguard was added.

**What it shows.**
- Rigorous evaluation design, with audit trails and two independent reviews.
- Honest negative results.
- Root-cause analysis of generalisation failure.
- Calibration under shift.
- Reproducible CPU-only experimentation on 8 GB RAM.

**What it does not show.**
- A universal or production-validated detector.
- Reliable cross-network transfer.
- A false-positive guarantee.
- A new state-of-the-art method.

## 3. Resume entry

**NetSentinel AI: ML research on network-attack detection under distribution shift**
(Python, LightGBM, scikit-learn, polars)
- Built window-level flow features and trained LightGBM, logistic-regression and
  robust-statistics anomaly detectors. Evaluated them with pre-registered
  leave-one-domain-out protocols: 9 attack domains, 27 benign units, exact domain-level
  tests with Holm correction.
- Showed that near-perfect within-network ranking collapses across networks: recall ≈ 1.0 vs
  0.03 at a 1%-FPR threshold. Traced the collapse to benign covariate shift (network
  identifiable at ROC-AUC 0.9999) and, through ablations, to volume features: removing them
  lifts cross-network ROC-AUC from 0.39 to 0.93.
- Tested and rejected four pre-registered remedies: standardisation, invariance-based
  feature screening, block-bootstrap thresholds and score fusion. Documented the negative
  results with full audit trails.
- Ran experiments reproducibly on CPU under an 8 GB memory budget.
