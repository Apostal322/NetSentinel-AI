# Phase 8i pre-registration

**Written:** 2026-11-02, before any Phase 8i model was trained or scored. It is committed locally before the
first run. Amendments are appended (section 10) and never edited in place.

**Basis:** [../phase8h/PHASE8I_PROPOSAL.md](../phase8h/PHASE8I_PROPOSAL.md), which states the
hypotheses I1–I3. This document turns them into exact protocols. Where it differs from the
proposal, the difference is listed in section 9.

**Question.** Can limited target-network information (a few labelled windows), a shift-aware
decision policy, or a less network-identifying representation improve attack detection on an
unseen network while keeping false alerts within a 1% budget?

## 1. Status of every result

- **Development, exploratory [E]:** every result on NF-CIC-IDS2018-v3, NF-UNSW-NB15-v3 and
  NF-ToN-IoT-v3. All three networks have been inspected (ToN_IoT in Phase 8c), so nothing on
  them can confirm a hypothesis.
- **Confirmatory [C]:** only the single evaluation on **NF-BoT-IoT-v3**, which no phase has
  opened ([DATASET_AUDIT.md](DATASET_AUDIT.md)). It runs once, after `docs/phase8i/FREEZE.md`
  records the frozen code commit and the method choices made by the rules below.
  `scripts/phase8i/build_windows.py` refuses to read it before that.
- BoT-IoT is from the same institution (UNSW Canberra Cyber Range) as UNSW-NB15 and ToN_IoT,
  but from a different testbed, year and device set. A positive result there is evidence of
  transfer to an unseen **capture network**, not to an unrelated organisation (section 8).

## 2. Data and windows

- **Telemetry:** NetFlow v3 (nProbe) only. Zeek captures are used only in the I2 unit pool.
- **Windows:** the Phase 8h windows: 30 s, per source address (device level), 12
  `WINDOW_FEATURES`, rebuilt by `scripts/phase8i/build_windows.py`. Phase 8i adds two things:
  calibration-period labels (`cal_truth.parquet`), and carrying windows across day files so
  that none is split in two.
- **Domains:**

  | network | domain(s) | part used | role |
  |---|---|---|---|
  | N1 NF-CIC-IDS2018-v3 | one per day (the Phase 8h days) | development part (first 78% of each day; the consumed test starts at 80%) | development |
  | N2 NF-UNSW-NB15-v3 | one | development part | development |
  | N3 NF-ToN-IoT-v3 | one | all flows | development |
  | N4 NF-BoT-IoT-v3 | one | all flows | **protected confirmatory test** |

- **Per target domain:**
  - **Calibration period:** flows ending before the time midpoint. Evaluation period: the rest.
  - **Benign calibration:** clean calibration windows of entities that never attack in the
    domain (Phase 8h strict definition).
    - The first 70% (by time slot, `split_cut`) is **benign-train**.
    - The last 30% is the **threshold hold-out**.
  - **Labelled attack pool:** unlabelled-variant calibration windows whose `cal_truth` is an
    attack. This is what a deployed system would have seen in those windows.
  - **Evaluation labels:**
    - Attack = an evaluation window with an attack flow (NF-CIC `infiltration` windows are
      excluded as noisy).
    - Benign = windows of entities that never attack in the domain.
    - Other windows are scored but not counted.
- **Threshold, all methods:** split-conformal, α = 1%, fitted on the scores of the threshold
  hold-out (T0 in Phase 8h).
  - When the hold-out has n < 199 windows, the threshold is the hold-out maximum. Its
    realised FPR then cannot be controlled at 1%. Every table reports n_hold.
  - No result is described as "1% FPR" without its realised FPR.

## 3. Common models

- **Source model:** B-raw = LightGBM on the 12 raw features. Phase 8h settings: 200 trees,
  learning rate 0.05, 15 leaves, subsample and colsample 0.8.
- **Training data:** benign calibration plus evaluation windows of every source domain.
  - **Cap:** at most 50,000 windows per source domain, stratified as in Phase 8h. The cap is a
    compute choice (Phase 8h used 200,000) and is applied identically to every compared
    model.
- **Weights:** network-balanced. Each source network gets equal total weight, split equally
  across its domains. Within a domain, the classes are balanced.
- **Seeds:** {0, 1, 2}. Results are averaged over seeds; the seed spread is reported.
- **Cross-network folds:** target network T, sources = every other development network.
  - **Units:** N2, N3, and each attack-eligible N1 day (Phase 8h primary days 02-14, 02-16,
    02-20, 02-21, 03-02; 02-22 is secondary).
  - **Network-level summary:** N1 is the mean of its days. Development therefore has
    **3 network-level units**. That is too few for inference, so development statistics are
    descriptive.
- **Confirmatory fold:** target N4, sources N1 + N2 + N3.

## 4. I1: a few labelled target windows (Experiment A)

- **Label budgets.** Ka ∈ {0, 5, 25, 100} labelled **attack** windows from the target's
  labelled attack pool.
  - All benign-train windows serve as negatives. They are assumed benign, as every
    calibration is.
  - Ka = 25 is the proposal's "K = 50": 25 attack plus 25 benign labels. Benign labels add
    nothing here because benign-train is already available.
  - **Draws:** 20 per budget, uniform without replacement (rng seed = draw index). If the pool
    is smaller than Ka, the whole pool is used and flagged.
  - **Recorded per draw:** the number of windows, unique attacker entities, and unique time
    slots.
  - **Same-attacker caveat:** labelled windows come from the target's calibration period, so
    they may involve the same attacker hosts as the evaluation. That is realistic for an
    analyst confirming early alerts, but optimistic. The single-entity variant measures it:
    all Ka windows from one randomly chosen attacker.
- **Methods:**
  - **A0:** source model; threshold = 99th percentile of the source benign training scores
    (no target data).
  - **A1:** source model, target T0 threshold (benign-only target calibration). **This is the
    zero-label comparator.**
  - **A2:** monotone score recalibration (Platt or isotonic) on the labels. **Not run.** A
    monotone map leaves the ranking unchanged, and the T0 threshold is a quantile of
    transformed hold-out scores, so A2's alerts are identical to A1's. This is an analytic
    result, not an experiment.
  - **A3:** logistic-regression correction on [logit(source score), 12 target-locally
    standardised features]. C = 1, class-balanced, fitted on the Ka windows + benign-train.
  - **A4:** continued boosting. 50 more trees (learning rate 0.05, 7 leaves,
    min_child_samples 5, class-balanced), initialised from the source model, fitted on the Ka
    windows + benign-train.
  - **A5:** target-only LightGBM on raw features (100 trees, 7 leaves, min_child_samples 5,
    class-balanced) on the Ka windows + benign-train.
  - At Ka = 0, A3–A5 cannot be fitted (no positives) and equal A1.
- **Metrics:**
  - **Primary:** operational window recall at T0 on the target evaluation period, with
    realised FPR.
  - **Secondary:** ROC-AUC, PR-AUC, oracle recall at 1% FPR (ranking only), entity recall,
    median detection delay, false alerts per hour, draw-to-draw spread.
- **Development selection rule (decided now, applied before N4 is opened):**
  - The confirmatory method is the one of A3, A4, A5 with the highest median development
    operational recall at Ka = 25 across the 3 network-level units, among methods whose median
    realised FPR is ≤ 2%.
  - Ties go to the simpler method (A3 < A5 < A4).
  - If no method meets the FPR condition, A3 is used and the failure is reported.
- **Confirmatory criteria on N4, selected method:**
  - **Success:** at Ka = 25, median operational recall over draws × seeds ≥ 0.5; its 2.5th
    percentile over draws > A1's recall; median realised FPR ≤ 2%.
  - **Failure:** median recall at Ka = 100 < 0.3, or the 2.5th percentile at Ka = 25 ≤ A1.
  - **Otherwise:** inconclusive.
  - **Not evaluable:** if N4 has fewer than 25 labelled attack windows in its calibration
    period.

## 5. I2: a shift score marks unreliable calibration (Experiment B)

- **Detector.** The deployed robust baseline (B-rz; first 70% of benign calibration to fit,
  last 30% as hold-out, T0 threshold). Secondary: the A1 source model on cross-network units.
- **Units:** one-hour evaluation blocks of every domain that has ≥ 60 benign evaluation windows.
  - **Domain pool:** the Phase 8h benign units (NetFlow and Zeek) plus N3.
  - A block is used when it has ≥ 30 benign windows.
  - The first evaluation hour is used only to compute the shift scores. Blocks start after
    it.
- **Outcome:** overrun = the block's benign FPR > 2α (2%).
- **Shift scores.** All are unsupervised: no labels are used.
  - **S_score (primary):** two-sample KS statistic between the hold-out detector scores and
    the block's detector scores (all windows).
  - **S_feat:** median over the 12 features of the KS statistic between the hold-out windows
    and the block's windows (locally standardised features).
  - **S_cal:** within-calibration drift: the median feature KS between the fit part and the
    hold-out. It is constant within a domain.
  - **S_n:** 1 / n_hold, the sample-size risk that Phase 8h found sufficient to explain the
    overruns. It is the comparator a shift score must beat.
- **Decision policy.**
  - Abstention withholds only the claim that the block's false-alert rate is within budget,
    and with it any "normal" assessment.
  - **Alerts are never suppressed:** an alert in an abstained block is still reported, marked
    "calibration unsupported".
  - Abstention therefore cannot lower false alerts. It can only stop the system from
    promising a budget it does not meet.
- **Development analysis.**
  - ROC-AUC of each score for overrun, over blocks. Uncertainty is a bootstrap over
    **domains**, because blocks within a domain are correlated.
  - Risk–coverage curve: exceedance rate among covered blocks against coverage, against a
    random-abstention baseline.
  - **τ:** the S_score cut that gives 60% coverage on development blocks, pooled. It is fixed
    before N4.
- **Confirmatory criteria on N4, B-rz:**
  - **Success:** exceedance among covered blocks ≤ 10% at coverage ≥ 60% (τ fixed), and lower
    than among all blocks.
  - **Failure:** at the coverage τ produces, exceedance among covered blocks ≥ exceedance among
    all blocks (no better than random abstention).
  - Also reported: the share of attack windows that fall in abstained blocks.
  - **Not evaluable:** fewer than 5 eligible blocks.
  - One network, correlated blocks: the result is descriptive (section 7).

## 6. I3: less network-identifying representations (Experiment C)

- **C1, domain-guided removal.** Train a LightGBM network classifier on source benign-train
  windows only. Rank the 12 features by total gain, remove the top k, retrain B-raw.
  - Primary k = 2; k = 1 and 3 are a reported sensitivity analysis.
- **C2, relative volume.** The 4 volume features (log_flows, log_up_bytes, log_down_bytes,
  log_pkts) are replaced by their difference from that network's benign-train median. Source
  networks use their own medians; the target uses its benign-train median. The other 8
  features stay raw.
  - Motivation (Phase 8h): standardising everything lost floods (H1a), and removing volume
    lost floods within a network but improved cross-network ranking. C2 keeps "far above
    this network's normal" and drops the network's absolute traffic level.
- **Comparators:** B-raw (A1), no-volume B-raw (the Phase 8h ablation, re-run under section 3),
  and the robust baseline B-rz. All use the A1 setup: no target labels, T0 threshold.
- **Negative control:** cross-validated ROC-AUC of a network classifier on benign windows (all
  development networks) under raw, C1(k) and C2 features. A lower AUC alone is not counted as
  success.
- **Within-network check:** N1 leave-one-day-out, with sources = the other N1 days only, for
  B-raw, C1(k=2) and C2.
- **Development selection rule:**
  - The confirmatory C variant is whichever of C1(k=2) and C2 has the larger mean development
    gain in operational recall over B-raw across the 3 network-level units. It must also lose
    ≤ 0.05 within-network.
  - If neither meets this, C2 is still evaluated on N4 as registered and reported as failing
    development.
- **Confirmatory criteria on N4:**
  - **Success:** the selected variant's operational recall ≥ B-raw's + 0.10, with realised FPR
    ≤ 2%.
  - **Failure:** otherwise.

## 7. Statistics

- **Development:** 3 network-level units; reported descriptively as per-unit values and paired
  differences. No p-values are computed over 3 units.
- **N4:** a single network.
  - Intervals are percentiles over label draws × seeds (I1), and moving-block bootstrap
    intervals over one-hour blocks (I2, I3).
  - They describe within-capture uncertainty only. They cannot express how much the result
    would vary across networks.
  - The three confirmatory verdicts are reported together. The success criteria above are
    effect-size rules, not significance tests, so no multiplicity correction is applied. Every
    secondary comparison is labelled exploratory.
- Windows are never treated as independent. The number of attacker entities is always
  reported.

## 8. Threats to validity, stated in advance

- **Shared institution.** N2, N3 and N4 come from the same institution, and nProbe v3
  features were extracted by the same group for all four networks.
- **Few attacker entities.** BoT-IoT's attacks are generated by a handful of attacker hosts
  (UNSW-NB15 dev: 4). Entity-level conclusions rest on very few units.
- **BoT-IoT benign volume.** BoT-IoT is 99.7% attack flows (51,989 benign). Its benign
  hold-out may be small, which limits threshold resolution (section 2).
- **Labels.** Labels are the datasets' own. Phase 8c found the ToN_IoT labels do not identify
  initiators in files 1–4. N3 attack windows are therefore audited (initiator check) before
  use, and any exclusion is recorded as an amendment.

## 9. Differences from the proposal

1. **Draws and seeds.** The proposal's "3 seeds and 20 draws" is kept. Its "fine-tune or
   reweight" is made concrete as A3–A5.
2. **I2 units.** I2 uses one-hour blocks instead of whole units, because one fresh network
   gives only one whole unit.
3. **I3 metric.** I3's "recall at 1% FPR" is made operational: recall at the calibrated
   threshold, with realised FPR reported. Oracle recall is secondary.
4. **Third development network.** NF-ToN-IoT-v3 is added. It was approved for download on
   2026-11-02.

## 10. Amendments

### A1 (2026-11-02, before any Phase 8i run): implementation clarifications

1. **Negative cap.** The label-budget models (A3–A5) use at most 20,000 benign-train windows
   as negatives, a random subsample fixed by the seed. This is a compute bound, applied
   identically to every method and budget.
2. **C2 reference median.** C2's reference median is computed per **domain** (each NF-CIC day
   uses its own benign-train median), not per network. For the single-domain networks N2–N4
   the two definitions are identical. Per domain is symmetric between source and target, and
   needs no data from other days.
3. **Within-network C1 ranking.** With NF-CIC days as the only sources, a network classifier
   cannot be trained on the sources. The within-network check therefore removes the top
   features of a classifier trained on the benign-train windows of all three development
   networks. Benign-train windows are target information every method may use.
4. **Attackers.** The entities excluded from benign calibration and benign evaluation
   ("attackers") are those with an attack window in either the calibration or the
   evaluation period.

### A2 (2026-11-02, before any model run): calibration/evaluation split point

- **The defect.** The first window build split every domain at the median flow-end time. That
  is the Phase 8b NF-UNSW convention, not the "time midpoint" section 2 registers. NF-CIC
  counts then differed from Phase 8h (02-14: 133,835 vs 108,481 evaluation windows). The
  build was stopped and the windows discarded. No model had been trained or scored.
- **The rule.** Every domain splits at the time midpoint of its span (as registered, and as
  in Phase 8h).
  - **Exception: NF-UNSW** keeps the Phase 8b median split, so its windows stay identical to
    Phases 8b/8h. Its time midpoint falls in the 26-day gap between its two capture sessions,
    which would make the whole January session calibration.
  - The rule applies unchanged to N3 and N4.

### A3 (2026-11-02, before the full development runs): seeds of the label-budget models

- **What changes.** A3–A5 are fitted for **source seed 0 only**, with 20 label draws per
  budget, so 20 fits per budget and method instead of 60. A0 and A1 are still computed for
  seeds {0, 1, 2}, and their spread is reported as the source-model seed variability. The
  confirmatory run uses the same rule.
- **Reason: compute only.** A timing run on one NF-CIC day (117,126 evaluation windows)
  measured about 2 s per draw. The registered 3 seeds × 80 draws would put Experiment A alone
  near 60 min, against the approved development envelope of about 20–40 min for all runs. The
  label draw is the registered source of variation in I1. The seed changes only the source
  model, which A0/A1 measure directly.
- **What had been seen.** Code smoke runs, written to `reports/phase8i/smoke/` and never used
  as results: NF-UNSW (seed 0, 2 draws) and NF-CIC 02-21 (seed 0, 3 draws). Both are
  development data. They were run to test the code and measure time. The selection rules and
  criteria are unchanged.

### A4 (2026-11-02, before N4 was opened): I2 with no overrunning blocks

A code dry run of the confirmatory pipeline, with NF-UNSW standing in for N4, produced a case
the protocol did not anticipate: no block overran (exceedance 0 among all blocks). Read
literally, the failure rule then fires (0 ≥ 0), although nothing was testable. **Rule:** if no
eligible N4 block overruns, I2 is "not evaluable (no overrunning blocks)". The other criteria
are unchanged.

**Ceilings, same reasoning.**
- **I1:** if N4's zero-label A1 already reaches recall ≥ 0.95 with FPR ≤ 2%, the success
  criterion (2.5th percentile above A1) cannot be met by any method. I1 is then "not
  evaluable (zero-label ceiling)".
- **I3:** if B-raw's recall on N4 is > 0.90 with FPR ≤ 2%, a +0.10 gain is impossible. I3 is
  then "not evaluable (raw-model ceiling)".

Both are fixed before N4 is opened.
