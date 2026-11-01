# Phase 8i proposal: what to test next (not started)

**Basis.** The Phase 8h findings ([FINAL_RESEARCH_REPORT.md](FINAL_RESEARCH_REPORT.md)):
- Supervised window models transfer across attack families **within** one network but
  collapse **across** networks.
- Operating thresholds overran on small calibration hold-outs. Small samples alone can
  explain that. Whether shift contributes is untested (I2).
- Removing volume features improved cross-network ranking (ROC-AUC 0.39 → 0.93) but not
  recall at 1% FPR.
- Fusion and invariance screening did not help.

**Rules.** Each hypothesis below is meant to address one of those failure mechanisms. Each
has a negative-result criterion fixed in advance. Each needs data this project has **not**
opened yet for its confirmatory test.

## Candidate directions, ranked

| rank | direction | addresses | data | compute | leakage risk | portfolio value |
|---|---|---|---|---|---|---|
| 1 | Few-label target adaptation (K labelled target windows) | cross-network collapse | development NetFlow (NF-CIC → NF-UNSW) plus one fresh network | low (LightGBM, CPU, minutes) | medium: the K labels must come from the calibration period only | high: a realistic deployment question |
| 2 | Shift-aware selective prediction (abstain when the target looks unlike the sources) | thresholds overrunning under shift; models scored blind on new networks | same | low | low | high: operating-point reliability |
| 3 | Domain-balanced training with a domain-identity penalty (sample weighting or feature removal guided by a domain classifier) | hidden network identity | same | low | low | medium |
| 4 | Few-shot calibration (threshold from K benign target minutes, with a shift test) | calibration size and shift | development | low | low | medium; partly covered by the Phase 8h calibration-size study |
| 5 | Self-supervised window representations | representation | needs much more unlabelled traffic | high (GPU or Colab) | medium | uncertain: temporal deep models lost three times |
| 6 | Device-conditional representations | pooled-fallback tail | development | medium | medium | low: device context was not supported in Phase 6 |
| 7 | Causal or mechanism-informed features | shortcuts | expert design | low | high (design choices) | low without new evidence |

## Recommended hypotheses (top three)

### I1: a few labelled target windows restore cross-network detection

- **Mechanism.** Raw-feature LightGBM ranks attacks well inside a network. Its failure on a
  new network is a shift in P(x) and P(y | x) that a small number of target labels can
  re-anchor.
- **Design.**
  - Source: NF-CIC development days. Target: NF-UNSW, then one fresh NetFlow network.
  - Fine-tune or reweight with K ∈ {0, 10, 50, 200} labelled target windows, all drawn from
    the target's calibration period.
  - Evaluate on the target's later evaluation period.
  - 3 seeds and 20 random draws of the K labels.
- **Primary metric.** Recall at 1% FPR on target label-benign windows, then entity recall.
- **Success.** K = 50 reaches ≥ 0.5 recall at FPR 1% on the fresh network, with a 95% CI over
  the draws excluding the K = 0 value.
- **Failure.** K = 200 is still < 0.3, or the gain is within the draw-to-draw variance.
- **Compute.** Under 30 minutes, under 2 GB.
- **Expected failure mode.** Labels concentrated in one attacker; target attacks absent from
  the calibration period.

### I2: a shift score predicts threshold overrun, so abstaining keeps the false-alert budget

- **Mechanism (hypothesis).** Overruns may come from shift as well as from small samples. A
  score computed from unlabelled
  target calibration windows (domain-classifier AUC between source and target, or
  calibration/evaluation KS) should separate the units that will overrun.
- **Design.**
  - The same 27 benign units, plus the fresh network.
  - The abstention rule is fixed on development data.
  - Report coverage and exceedance.
- **Success.** Exceedance ≤ 10% at coverage ≥ 60% on fresh data.
- **Failure.** At equal coverage, the shift score is no better than random abstention.
- **Compute.** Minutes.
- **Expected failure mode.** Shift between calibration and evaluation that is invisible in
  the calibration data (a later regime change).

### I3: removing domain-identifying signal improves cross-network ranking

- **Mechanism.** Benign windows identify their network almost perfectly (Phase 8h negative
  control). A model trained without the most domain-identifying features, or with domain
  weighting, must rely on attack-specific signal.
- **Design.**
  - Rank features by domain-classifier importance on source **benign** data only.
  - Retrain B-raw without the top-k (k ∈ {1, 2, 3}).
  - Leave-one-network-out across NF-CIC, NF-UNSW and one fresh NetFlow network.
- **Success.** Cross-network recall at 1% FPR improves by ≥ 0.10 without losing > 0.05
  within-network.
- **Failure.** Otherwise. Phase 8h's H1b already suggests the risk: removing features costs
  within-network detection of flood attacks.
- **Compute.** Under 30 minutes.

## Data needed

- At least one **fresh NetFlow network** with attack labels (download and pre-registration
  need operator approval).
- No Phase 8i result on NF-CIC or NF-UNSW alone can be confirmatory: both have been
  inspected.
