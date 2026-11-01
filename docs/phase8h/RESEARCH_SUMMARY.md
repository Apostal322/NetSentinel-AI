# Phase 8h research summary

**Full report:** [FINAL_RESEARCH_REPORT.md](FINAL_RESEARCH_REPORT.md).

**Status.** All results are exploratory: the data were used in earlier phases. No deployed
behaviour changed.

## What was investigated

- **The problem.** Detectors trained on network-flow windows look excellent on the network
  they were trained on, but become unreliable on a new one.
- **The question.** Can that be fixed with:
  - a better feature representation;
  - better threshold calibration;
  - or by combining a supervised model with an anomaly detector?

## What was built and trained

- **Models.** Three LightGBM variants and a logistic-regression baseline, all on 12 window
  features (30-second traffic summaries per source address):
  - raw features;
  - features standardised per network;
  - **a new feature-screening method** that keeps only features whose benign distribution
    is stable across training networks.
- **Comparator.** The project's deployed robust anomaly detector (median/MAD z-scores).
- **Thresholds.** Four threshold rules, including a block-bootstrap bound and a selective
  (abstaining) variant.
- **Fusion.** A conservative OR-fusion of the supervised and anomaly scores.
- **Evaluation.**
  - Leave-one-domain-out over 9 attack domains and 27 benign evaluation units.
  - Two telemetry families (NetFlow, Zeek), never mixed.
  - 3 seeds, paired tests over domains, Holm correction.

## What the pre-registered hypotheses predicted, and what happened

| prediction | result |
|---|---|
| Per-network standardisation transfers better than raw features | **No.** Recall at 1% FPR fell by 0.26 on average; collapsed on two domains (DDoS-LOIC, Bot) |
| Keeping only benign-stable features transfers better | **No.** Neutral on average, catastrophic on one domain; the kept set changed in 5 of 10 folds between two variants of the same rule |
| Block-bootstrap thresholds exceed twice the 1% target less often | **No.** 8 of 27 units under both rules |
| Fusion detects more than the better single model | **No.** −0.09 recall, and slightly above its false-alert limit |

## What the exploratory analysis suggests

- **Days of one network look alike; two networks do not.**
  - Benign traffic from different days of one network is almost identical (median KS
    ≤ 0.054 on 11 of 12 features).
  - Two networks differ by KS up to 0.85.
  - A classifier names the network from benign traffic alone with ROC-AUC 0.9999.
- **Within one network the best model ranks new attack days almost perfectly.** Its recall
  is about 1.0 at a 1%-FPR threshold set on the target's own labels, on 5 of 5 days (4
  families). At its calibrated threshold it overran the false-alert target (1.8–3.5%).
- **Across networks the same model scores 0.03.**
- **Removing its four volume features hurts within one network but helps across networks.**
  - Within one network: the floods are lost.
  - Across networks: overall ranking on the new network improves sharply (ROC-AUC
    0.39 → 0.93).
  - The extreme low-false-alert region that real budgets need does not recover.
- **The threshold overruns sat on small calibration hold-outs**, where the threshold is the
  largest calibration score. Small samples alone can explain them. Whether shift adds to
  them was not tested.

## What is useful

- A pre-registered negative result, with an audit trail, an independent code review, and a
  second review of the report itself.
- A precise diagnosis: what transfers (new attack days within one network), what does not
  (networks), and a supported contributor (volume features that carry network identity).
- **A suggestive calibration observation, not a tested finding.** The deployed cross-fit
  threshold exceeded twice the target in 3 of 27 units, against 8 of 27 for split-conformal
  (exact one-sided p = 0.06).
- **An honest map of the deployed anomaly detector.**
  - Across the 27 units its median FPR is 0.73%, with the cross-fit threshold. It exceeds 2%
    in 3 units with that threshold, and in 8 with split-conformal.
  - On the six NetFlow attack domains it detects almost nothing: recall at 1% FPR about
    0.01; 1 of 6 domains detected.
  - It detects the IoT-23 attackers.

## What remains uncertain

- Every effect rests on 7–9 domains, with one or two domains driving each mean.
- Only one cross-network NetFlow pair was available.
- "Label-benign" is the dataset's label, not verified benign, outside CTU-Normal.

## What to test next (Phase 8i, not started)

1. Does a small number of labelled target windows restore cross-network detection?
2. Can a shift score decide when to abstain, so the false-alert budget holds on a new network?
3. Does removing the features that identify the network improve cross-network
   low-false-alert detection, not just overall ranking?

Each needs a fresh, never-opened network for confirmation:
[PHASE8I_PROPOSAL.md](PHASE8I_PROPOSAL.md).
