# Phase 8j pre-registration: can a detector tell when its calibration is good enough?

**Written:** 2026-11-02.
- **Before:** any comparison of the methods below on development data, and any fresh dataset
  download.
- **After** two analyses that shaped it: the calibration-protocol audit
  ([DATA_INTEGRITY_AUDIT.md](DATA_INTEGRITY_AUDIT.md)), which selected P1x, and the
  simulation ([CALIBRATION_RELIABILITY_METHODOLOGY.md](CALIBRATION_RELIABILITY_METHODOLOGY.md)),
  which motivated M3.
- Amendments are appended (section 11) and never edited in place.

**Basis:**
- the Phase 8i final audit (FINAL_REPORT.md section 10);
- [DATASET_ELIGIBILITY.md](DATASET_ELIGIBILITY.md);
- [VALIDATION_PROTOCOL.md](VALIDATION_PROTOCOL.md).

**Question.** Given a fixed source detector and a benign calibration from the target network,
can a method recognise when that calibration is representative enough to support a 1%
false-alert budget? It must abstain where it is not, while still covering most traffic, most
benign evidence and most attacks.

**Research-only.** No Phase 8j method changes the deployed default. Phase 8h and 8i verdicts
are preserved.

## 1. Status of results

- **Development [E]:** everything on NF-CIC-IDS2018-v3, NF-UNSW-NB15-v3 and NF-ToN-IoT-v3
  (development parts), and NF-BoT-IoT-v3 (consumed in Phase 8i; usable as development, never
  as confirmation). There are **4 development network units**. NF-CIC's 6 day-domains are one
  unit: they are pooled with equal day weights, and held out together.
- **Confirmatory [C]:** one frozen run on the fresh families of VALIDATION_PROTOCOL.md:
  - F1 is AIT Netflow v2, 7 networks after the probe;
  - F2 is UWF-ZeekData24, the weeks after the probe; DARPA OpTC replaces it if the probe
    fails.
- **Post-hoc [R]:** anything decided after the confirmatory outputs exist. It changes no
  verdict.

## 2. Fixed components (not compared)

- **Windows:** the Phase 8h/8i windows (30 s, per source address, 12 `WINDOW_FEATURES`).
- **Calibration protocol: P1x** for every method.
  - All-flow windows.
  - Hosts with an attack before the calibration end are removed from the hold-out **and**
    from the destination memory used for evaluation features.
  - No evaluation-period label touches calibration (DATA_INTEGRITY_AUDIT.md section 5).
  - Secondary rows: P2 (no labels) and P1u (memory not purged).
- **Source detector:** B-raw LightGBM, Phase 8i settings, network-balanced.
  - Development folds: the target network's model is trained on the other development
    networks.
  - Confirmation: one model per seed {0, 1, 2}, trained on all 4 NF-v3 networks before the
    freeze. Results are the mean over seeds, with the seed spread reported.
- **Thresholds:** every threshold is an order statistic of hold-out scores (no interpolation),
  and a window alerts only when its score is **strictly above** it. Tie mass at each threshold
  is reported per network (it was 58% on N4).
- **Units:**
  - **Network:** the calibration unit. For F2, each week is a network: its own calibration is
    the first half of the week. F2 as a whole is still **one independent environment**.
  - **Evaluation block:** 1 hour of a network's evaluation period.
- **Block overrun:** the block's false alerts on verified-benign windows are significantly
  above α. The exact one-sided binomial test of FPR ≤ 1% gives p < 0.05. Only blocks with
  ≥ 30 verified-benign windows are scored. A perfectly calibrated block is therefore marked as
  overrun at most 5% of the time, whatever its size. A fixed "> 2%" cut was rejected: one
  false alert in 30–49 windows would count as an overrun.

## 3. Hypotheses

| id | claim | type |
|---|---|---|
| **J1** | The development-selected abstaining method S keeps the false-alert budget on what it covers, with meaningful coverage and useful sensitivity, better than random abstention at the same coverage. | **primary, confirmatory** |
| J2 | The four Phase 8i eligibility checks, as proposed, separate networks that hold the budget from networks that do not. | secondary; tested exactly as proposed, although the statistical analysis does not support each threshold individually |
| J3 | M3's network-level abstention falls on networks that would overrun, and M3 keeps the budget on the networks it covers. | secondary |
| J4 | The cost of not vetting the calibration period (P2 vs P1x) appears as lost recall, not as lower FPR. | descriptive |

## 4. Methods compared

All methods use the same source scores and P1x calibration.

| id | threshold | abstention | notes |
|---|---|---|---|
| **M0** | split-conformal T0 at α = 1% on the hold-out (Phase 8i A1) | never | comparator. **M0x**: the same over all calibration windows (the source model never saw them) |
| **M1** | T0 | at network level, if any of Phase 8i checks 1–3 fails (session effective n ≥ 199; effective hosts ≥ 10 and top host ≤ 25%; host-grouped exceedance ≤ 2α); at block level, if the block starts more than 24 h after the hold-out ends (check 4) | the proposed fixed rules, unchanged |
| **M2** | T0 | at block level, when the learned reliability score P(overrun) > τ | logistic regression on label-free features (METHODOLOGY section 4) |
| **M3** | max(T0, PAC threshold). The PAC threshold: take the largest exceedance count l with P(FPR > 2α) ≤ 5% under Beta(l, n_eff + 1 − l), use rank ⌈n(1 − l/(n_eff + 1))⌉ of all n hold-out scores, and never go below T0's rank. n_eff deflates each host's windows by the AR(1) design effect of the pooled within-host lag-1 autocorrelation, then applies the Kish host correction (METHODOLOGY section 5). | at network level, if fewer than 10 hosts or no l ≥ 1 exists | dependence- and diversity-aware calibration |
| **M4** | M3 | M3's network-level abstention, plus block-level abstention from M2 refitted on M3 thresholds | the full abstaining policy |
| **Controls** | Z: never alert. **RA** (random abstention), for each abstaining method: 1,000 draws of uniformly random evaluation blocks, pooled over all confirmation networks (not stratified), with the same total number of covered blocks as the method. Each draw is scored like the method. | | |

A source-aware variant (mixing source-domain benign scores into the target quantile) is **not**
registered: on development the source model mis-scores target benign traffic (P3 in the
integrity audit).

## 5. Metrics (all methods, every network, covered blocks unless stated)

- **Detection:**
  - window recall on attack windows;
  - entity recall (attackers with ≥ 5 attack windows);
  - median detection delay: from an attacker's first attack window to its first alert;
    abstained time counts as missed.
- **False alerts:**
  - verified-benign FPR per network: covered false alerts / covered verified-benign windows;
  - false alerts per benign hour.
- **Calibration reliability:**
  - block overrun rate;
  - for M2/M4, the AUROC and Brier score of the reliability score against overrun.
- **Coverage:**
  - share of evaluation blocks covered;
  - share of attack windows covered;
  - share of verified-benign windows covered;
  - coverage of attack windows vs verified-benign windows (attack-triggered abstention check).
- **Also reported:**
  - ranking: ROC-AUC and oracle recall at 1% FPR, all blocks;
  - tie mass at each threshold;
  - the P2 and P1u rows;
  - per-network tables.
- **Pooling:**
  - Within a family, every network has equal weight; the two families also have equal
    weight.
  - A network with no covered verified-benign windows does not enter the pooled FPR, but it
    counts in every coverage figure.
- **Uncertainty:** 95% intervals from a cluster bootstrap. Resample networks within a family,
  then hosts within a network (2,000 draws).
- **Coverage and conditional performance are always reported together**, in one table row.

## 6. Success criteria (registered)

**J1 success** requires all of the following for S on the confirmation networks.
- (a) **Budget:** pooled covered verified-benign FPR ≤ 2.0%, and its 95% cluster-bootstrap upper
  bound ≤ 3.0%.
- (b) **Coverage:** each of these covered shares is ≥ 50%:
  - evaluation blocks;
  - attack windows;
  - verified-benign windows.
- (c) **Sensitivity:** covered entity recall ≥ 0.5, and window recall reported.
- (d) **Better than chance abstention:** p < 0.05, where p = (1 + #{RA draws whose covered
  overrun rate ≤ S's}) / 1,001. Ties count against S.
- (e) **No attack-triggered abstention:** coverage of attack windows ≥ 0.8 × coverage of
  verified-benign windows.

**J1 failure:** any of (a)–(e) fails.

**Not evaluable** (VALIDATION_PROTOCOL.md section 5):
- If fewer than 4 confirmation networks pass the probes in total, J1 is not evaluable.
- **If only one family survives,** J1 is evaluated on that family alone and the verdict is
  labelled "single environment family". A success then cannot be claimed to generalise
  across environments.

**Claim rule:**
- No result is described as "1% FPR". The realised FPR is always shown with its interval.
- "FPR ≤ 2%" may be claimed only when the one-sided 95% Clopper-Pearson bound ≤ 2%. The bound
  is computed on effective counts: n_eff from M3's formula applied to the covered
  verified-benign windows, and x_eff = x · n_eff / n.
- At an observed 1% this needs at least about 590 effective windows (always from 719;
  METHODOLOGY section 2).

**J2:**
- **Supported** if all three hold:
  - at least one confirmation network passes M1's network checks;
  - no passing network has a covered M0 FPR above 3%;
  - the pooled M0 FPR of failing networks exceeds that of passing networks.
- **Refuted** if a passing network exceeds 3%, or if failing networks do not overrun more.
- **Not evaluable** if no network passes or none fails.

**J3:**
- **Supported** if all three hold:
  - M3 covers ≥ 50% of evaluation blocks;
  - M3 meets (a) on the networks it covers;
  - when M3 abstains on any network, the pooled M0 FPR of the abstained networks exceeds
    that of the covered networks.
- If M3 abstains on no network, the last condition is recorded as vacuous.
- **Refuted** otherwise.
- M3's recall cost against M0 on the same covered blocks is reported. (Comparing overrun on
  the same blocks would be uninformative: M3's threshold is never below T0.)

## 7. Development selection rule (applied before the freeze)

1. Run M1, M2 and M4 on development with leave-one-network-out over the 4 development network
   units. M2's and M4's models and τ come from the other three units only.
2. **τ:** the largest τ (least abstention) whose covered overrun rate on the training units'
   out-of-fold predictions, pooled with equal unit weights, is ≤ 10%. If no τ reaches 10%,
   take the τ minimising the overrun rate subject to block coverage ≥ 50%, and flag it.
3. **S** is the method meeting criteria (a) and (b) on the most held-out development units.
   Ties go to the lower pooled overrun rate, then to higher coverage.
4. **Go/no-go:** the confirmatory run happens only if S meets (a) and (b) on ≥ 2 of the 4
   development units. Otherwise Phase 8j ends with a registered negative development result,
   and no fresh data is spent.
5. The final M2/M4 model and τ for confirmation are refitted on all 4 development units with
   the same procedure, then frozen.

## 8. What would count as evidence against the whole approach

- **Benign hosts drive overruns:** if S meets (a) only by abstaining on networks whose
  verified-benign populations are large and diverse. Criterion (b)'s benign-window coverage
  limits this; per-network tables show it.
- **Degenerate abstention:** if the reliability score's AUROC against overrun is ≤ 0.6 on the
  confirmation networks, S succeeds by coverage restriction rather than prediction.

Both are reported whatever the J1 verdict.

## 9. Known limitations, stated before the data are seen

- Both fresh families are emulated or cyber-range networks with simulated users.
- F1's 7 networks share one generator, and F2's weeks share one range. **The two families are
  the independent units:** 2 is enough to falsify, not to estimate a population rate.
- Telemetry shift: nProbe in development; Tstat (F1) and Zeek (F2) in confirmation.
- P1x assumes vetted calibration-period labels. Label errors there pass straight into
  calibration.
- Development has only 4 network units, so M2 is trained on very few independent units. Its
  development performance is a weak prior.
- The simulation supporting M3 is a stylised Gaussian model. M3's development and
  confirmation results, not the simulation, decide J3.

## 10. Deviations from the Phase 8i proposal (section 10.4 of its final report)

- **Check 1:** registered as proposed (≥ 199). For i.i.d. data, the 95% FPR bound exceeds 2%
  for n of 199–235 and 299–312, and holds from 313 (METHODOLOGY section 2). This motivates M3
  rather than a changed threshold.
- **Check 4 (recency):** applied per block, not per network.
- **Calibration protocol:** P1x replaces the Phase 8i strict-benign rule, which used
  evaluation-period labels.

## 11. Amendments

**A1 (2026-11-02, development only, before any freeze or fresh data): the overrun test uses the
2α tolerance.**
- **What changes:** block overrun is now the exact one-sided binomial test of FPR ≤ **2α**
  (p < 0.05), not FPR ≤ α. Everything else in section 2 is unchanged (≥ 30 verified-benign
  windows; strictly-above alerts).
- **Why:** the first development smoke run (seed 0) showed that the α-test flags near-nominal
  blocks as overruns whenever a block is large.
  - NF-CIC blocks hold about 20,000 verified-benign windows. A realised FPR of 1.33% is then
    significantly above 1%, and 81% of NF-CIC blocks counted as overruns.
  - M2, trained on that target, abstained on all of NF-CIC.
  - The α-null contradicts the 2α tolerance used everywhere else: criterion (a) ≤ 2%, the
    simulation's "bad", and the first draft's "> 2%".
  - The 2α-null keeps the review's fix (the false-overrun rate of a perfectly calibrated block
    stays ≤ 5% at any size), and it flags blocks only when they clearly exceed the tolerance.
- **Seen before the change:** seed-0 development results of all methods under the α-null.
  No fresh data.
- **Transparency:** the complete development comparison is also reported under the original
  α-null (`reports/phase8j/dev/compare_null_alpha.json`) as a sensitivity analysis.
