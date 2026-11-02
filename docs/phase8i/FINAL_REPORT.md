# Phase 8i final report

**Status labels:**
- **[E]:** development, exploratory.
- **[C]:** the single confirmatory evaluation on NF-BoT-IoT-v3.
- Hypotheses, protocols and amendments: [PREREGISTRATION.md](PREREGISTRATION.md).
- Chronology and incidents: [AUDIT_TRAIL.md](AUDIT_TRAIL.md).

## 1. Question

Phase 8h found that supervised flow-window detectors rank attacks almost perfectly within one
network but collapse on another (recall about 1.0 vs 0.03 at a 1%-FPR threshold). Phase 8i asks
whether three remedies help on an unseen network while keeping false alerts near a 1% budget:
- a few labelled target windows (I1);
- a shift score that withdraws unsupported false-alert claims (I2);
- a representation that carries less network identity (I3).

## 2. Data

- **Development** (inspected; [DATASET_AUDIT.md](DATASET_AUDIT.md)):
  - N1 NF-CIC-IDS2018-v3: 11 days, development part.
  - N2 NF-UNSW-NB15-v3: development part.
  - N3 NF-ToN-IoT-v3: 27.5M flows, new to this project's window pipeline. Its network was
    inspected in Phase 8c.
- **Protected test:** N4 NF-BoT-IoT-v3, never opened before the freeze.
- **Windows:** the Phase 8h windows (30 s, per source, 12 features). The NF-CIC and NF-UNSW
  windows are identical to Phases 8h/8b.

## 3. Engineering fix: late records now degrade telemetry health

- **Before:** a record arriving after its window had closed was counted and dropped, but health
  stayed `ok`. In CTU-13 scenario 10, 90 such records (0.0008% of 11.6M) removed 10 alerts
  while the monitor reported healthy telemetry.
- **Now:** the first late record sets the `late_records` flag (severity 1, as
  `buffer_pressure`), and `late_windows` counts the affected windows. The flag reaches the
  assessment ("normality not supported"), the event store, the CLI and the dashboard through
  the existing health path.
- **No rate threshold:** the only measured case shows harm at 0.0008%, and clean replays at an
  adequate lateness produce zero late records.
- **Limitation:** assessments already emitted for the affected windows are not rewritten.
- **Tests:** `test_late_records_degrade_health`, `test_late_flag_ranks_below_integrity_faults`,
  the monitor CLI JSON test, and the pre-8f forgery test, where the loss is now visible.

## 4. Development results [E]

**Setup.**
- Sources are every other development network. Thresholds are split-conformal at α = 1% on
  the target's benign hold-out (T0).
- "Recall" means operational window recall at that threshold, and FPR is the realised rate on
  target benign windows.
- Every number below comes from data inspected in earlier phases, so none of it is evidence
  for a hypothesis.

### 4.1 Experiment A: label budgets (I1)

| unit | attackers | label pool (windows / entities) | n_hold | A0 recall / FPR | A1 recall / FPR | A1 ROC-AUC | A3 Ka25 | A4 Ka25 | A5 Ka25 |
|---|---|---|---|---|---|---|---|---|---|
| NF-CIC 02-14 SSH-BF | 1 | 196 / 1 | 35,221 | 1.000 / 39.7% | 0.996 / 1.33% | 0.996 | 0.995 / 1.59% | 0.995 / 1.48% | 0.989 / 0.80% |
| NF-CIC 02-16 DoS-Hulk | 1 | 107 / 1 | 25,919 | 0.975 / 36.0% | 0.963 / 1.23% | 0.981 | 1.000 / 0.91% | 0.963 / 1.20% | 0.963 / 0.32% |
| NF-CIC 02-20 DDoS-LOIC | 10 | 906 / 10 | 34,741 | 0.091 / 40.3% | 0.085 / 1.30% | 0.225 | 0.085 / 1.03% | 0.085 / 1.14% | 0.009 / 0.53% |
| NF-CIC 02-21 DDoS-HOIC | 10 | 212 / 10 | 36,144 | 0.998 / 41.7% | 0.991 / 1.57% | 0.998 | 0.999 / 0.95% | 0.998 / 1.45% | 0.968 / 0.15% |
| NF-CIC 03-02 Bot | 7 | 1,018 / 8 | 29,131 | 1.000 / 47.4% | 0.357 / 0.99% | 0.976 | 0.999 / 1.98% | 0.986 / 0.97% | 0.978 / 1.16% |
| NF-UNSW | 4 | 937 / 4 | 443 | 0.600 / 2.7% | 0.971 / 3.66% | 0.974 | 0.065 / 0.05% | 0.934 / 1.30% | 0.878 / 0.17% |
| NF-ToN-IoT | 13 | 11,083 / 24 | 4,571 | 0.677 / 19.9% | 0.363 / 14.5% | 0.815 | 0.466 / 1.38% | 0.592 / 10.8% | 0.719 / 4.23% |
| *NF-CIC 02-22 (secondary)* | 291 | 869 / 316 | 35,890 | 0.225 / 39.5% | 0.095 / 1.30% | 0.472 | 0.013 / 0.93% | 0.845 / 1.14% | 0.808 / 0.96% |

- **Column definitions:**
  - A3–A5: median over 20 draws, seed 0 (amendment A3).
  - A0/A1: mean over seeds 0–2.
  - **Network-level medians at Ka = 25:**
    - A4: 0.805 (N1 mean 0.805, N2 0.934, N3 0.592).
    - A5: 0.781.
    - A3: 0.466.
  - Ka = 100 changes little except on NF-ToN-IoT, where A5 rises to 0.83 at 7.0% FPR.

**Findings:**
1. **A target threshold is indispensable.** The source-calibrated threshold (A0) gives
   19.9–47.4% FPR on every development network except NF-UNSW (and 39–51% on N4). That network's benign scores happen to sit low.
2. **Zero-label transfer is far better than in Phase 8h, and the cause is not isolated.**
   - NF-UNSW A1: ROC-AUC 0.974, recall 0.971 (FPR 3.7%), against ROC-AUC 0.39 in Phase 8h.
   - The improvement coincides with adding NF-ToN-IoT as a source network (Phase 8h trained
     on NF-CIC alone). Three other things changed at the same time: the training cap (200k →
     50k per domain), the weighting (network-balanced), and benign calibration (attacker
     entities removed). No ablation isolates the source set.
   - Both NF-UNSW and NF-ToN-IoT were captured at UNSW Canberra, so a shared-institution
     effect cannot be excluded either.
3. **The registered I1 comparison (A4 vs A1) helps where A1 fails, and does nothing where the
   failure is in ranking.**
   - **Gains:**
     - 03-02 Bot: 0.36 → 0.99. A1 was seed-unstable: 0.86 / 0.05 / 0.16.
     - NF-ToN-IoT: 0.36 → 0.59, but still at about 11% FPR.
     - 02-22: 0.10 → 0.85. Its labels mark victims, and the labelled hosts recur in evaluation.
   - **No change for A4:** 02-20 DDoS-LOIC stays at 0.085 in all 60 draws. The source model
     scores those attacks *below* benign (ROC-AUC 0.225), and 50 extra trees on up to 100
     labels do not reverse that.
   - **The target-only model A5 can recover it, but unstably.** At Ka = 5 its median recall is
     0.906 (FPR 0.65%), with recall ≥ 0.8 in 15 of 20 draws. But this falls to 8 of 20 draws
     at Ka = 25 (median 0.009) and 4 of 20 at Ka = 100. The failure lies in correcting a
     backwards-ranking source model, not in labels as such.
4. **Label diversity matters.** With all 25 labels from one attacker, NF-ToN-IoT A4 recall
   falls from 0.59 to 0.33. Its label pool comes from different attack types (scanning,
   DoS/DDoS and injection occur only in the calibration half, per the ingest counts) than its
   evaluation period (password, XSS, backdoor, ransomware, MITM).
5. **A3 (linear correction) is unreliable.** It collapses on NF-UNSW (0.065) while A4 and A5
   stay above 0.87.
6. **FPR control is the binding problem on NF-ToN-IoT.** Its benign hold-out (n = 4,571) does
   not represent the evaluation period: A1 FPR is 14.5%. Every method that keeps its target
   ranking inherits that shift.

### 4.2 Experiment B: shift-aware abstention (I2)

- **Units:** 118 one-hour blocks in 23 domains (deployed robust detector B-rz). 22.9% of blocks
  overran 2% FPR.

| score | block ROC-AUC for overrun | domain-bootstrap 95% CI | exceedance at about 60% coverage |
|---|---|---|---|
| S_score (primary): hold-out vs block score KS | 0.717 | 0.536–0.923 | 12.9% |
| S_feat: median feature KS | 0.709 | 0.559–0.912 | 12.9% |
| S_cal: within-calibration drift | 0.801 | 0.653–0.974 | 7.1% |
| S_n: 1 / n_hold (comparator) | 0.646 | 0.489–0.969 | 21.4% |
| random abstention | 0.5 | — | 22.9% |

- **The pooled AUCs are driven by differences between domains, not by separating good blocks
  from bad ones within a domain.** NF-ToN-IoT supplies 47 of the 118 blocks and 19 of the 27
  overruns.
  - Within NF-ToN-IoT, S_score has AUC 0.40 (worse than chance), and τ covers only 2 of its
    47 blocks: in practice it abstains on that whole network.
  - Without NF-ToN-IoT (71 blocks, 8 overruns), the sample-size comparator S_n is best (0.93),
    ahead of S_cal 0.87, S_feat 0.77 and S_score 0.72.
  - S_cal is constant within each domain, yet it has the best pooled AUC.
  - The domain-bootstrap intervals overlap.
  - **No shift score demonstrably beats the sample-size comparator.** (These sensitivity
    analyses are exploratory and were added after review.)
- **Selected for the test:** τ = 0.70095 (S_score). Under the I2 policy, alerts are never
  suppressed: abstention only withdraws the false-alert budget claim.
- **The source model (A1) is different.** On the 8 cross-network units (76 blocks), S_score is
  uninformative (AUC 0.49), and the sample-size score is the best predictor (0.78).

### 4.3 Experiment C: representations (I3)

| network | raw | C1_k1 | C1_k2 | C1_k3 | C2 relative volume | no volume | B-rz |
|---|---|---|---|---|---|---|---|
| N1 NF-CIC (5 days) recall / FPR | 0.678 / 1.28% | 0.737 / 1.20% | 0.732 / 1.00% | 0.650 / 1.10% | 0.606 / 1.45% | 0.066 / 1.19% | 0.111 / 1.13% |
| N2 NF-UNSW | 0.971 / 3.66% | 0.967 / 3.67% | 0.948 / 3.40% | 0.964 / 4.01% | 0.999 / 4.18% | 0.770 / 1.81% | 0.000 / 0.26% |
| N3 NF-ToN-IoT | 0.363 / 14.5% | 0.289 / 10.7% | 0.139 / 8.2% | 0.050 / 2.0% | 0.071 / 1.68% | 0.003 / 6.15% | 0.958 / 7.35% |
| **mean change vs raw** | — | −0.006 | −0.065 | −0.116 | −0.112 | −0.391 | — |

- **No representation improved cross-network recall on average.**
- The removal ranking comes from source-network classifiers. The removed features vary by fold:
  log_up_bytes and med_log_dur (sources N2+N3), rst_frac and log_down_bytes (N1+N3),
  log_up_bytes and log_dst_ports (N1+N2).
- **Within one network** (NF-CIC leave-one-day-out), C1_k2 and C2 cost at most 0.002 recall.
  Raw recall is 0.97–1.00 on every day, so this check sits at a ceiling and says little. The
  registered rule therefore selected C1_k2 (the less negative gain), with a low prior.
- **Negative control:** a network classifier on benign windows. Its macro ROC-AUC barely
  moves: raw 0.985, C1_k2 0.984, no-volume 0.982. C2 raises it to 1.000. The mechanism was
  not investigated; per-domain centring evidently adds, rather than removes, a
  domain-specific signal.
  **Removing the tested feature subsets does not remove network identity.** That is
  consistent with C1 failing, though other subsets were not tested.
- **The deployed robust detector behaves very differently from the supervised model:** it is
  the strongest on NF-ToN-IoT (0.958 at 7.4% FPR) and weak on NF-CIC (network mean 0.11; 0.56
  on 02-16) and NF-UNSW (0).

## 5. Confirmatory evaluation on NF-BoT-IoT-v3 [C]

- **Run:** once, at the frozen commit `5db0c6f`, in the order recorded in
  [FREEZE.md](FREEZE.md). Verdicts are computed by the frozen `confirm_analyze.py`
  (`reports/phase8i/confirm/verdicts.json`).
- **N4 at a glance:**
  - **Evaluation:** 3,449 windows over 422 h (2018-06-04 to 06-19, mostly 06-04): 1,579 attack
    windows from 8 entities with attack-labelled windows (two address groups; roles not
    independently verified), and 620 label-benign windows from 8 entities that never attack.
    Recall is over the 1,579 attack windows and FPR over the 620 benign windows; the 1,250
    non-attack windows of the 8 attacking entities count in neither (strict benign rule,
    section 2 of the pre-registration).
  - **Calibration (May):** benign-train 178 windows, threshold hold-out 781, labelled attack
    pool 7,230 windows from 8 entities (mostly reconnaissance).
  - 16 entities in the evaluation period; at least 20 counting the calibration period.

| hypothesis | frozen choice | result | registered verdict |
|---|---|---|---|
| **I1** label budget | A4, Ka = 25 | median recall 0.923 (2.5th pct 0.745) at median FPR **9.8%**; zero-label A1 recall 0.839 (seed mean; seed 0, on which A4 is built: 0.847 at 21.0% FPR) | **failure** (2.5th pct ≤ A1; the 9.8% FPR would also have blocked success) |
| **I2** shift-aware abstention | B-rz, τ = 0.70095 | B-rz raised **no** alerts on N4 (recall 0, FPR 0, ROC-AUC 0.93); 5 eligible blocks, none overrunning; τ covered 20% of blocks; the abstained blocks held 67% of the attack windows inside eligible blocks (767 of 1,149; 49% of all 1,579) | **not evaluable** (no overrunning blocks, amendment A4) |
| **I3** representation | C1_k2 | recall 0.858 vs raw 0.839, at FPR **19.0%** vs 11.7% | **failure** |

**Other N4 numbers [C, descriptive]:**
- **Supervised source model (raw):** ROC-AUC 0.87. Oracle recall at 1% FPR is 0.42, within the
  development range of 0.008 (NF-ToN-IoT) to 0.995 (NF-CIC 02-14). Entity recall 0.875–1.0.
- **Realised FPR at the benign-calibrated threshold:** 7.1–21.0% across seeds.
- **No-volume:** recall 0.47–0.51 at 6.9% FPR. **C2:** unstable across seeds (0.44–0.85).
- **Not the registered choices [E, exploratory on N4]:**
  - A3 (logistic correction) at Ka = 5 reached median recall 0.944 at median FPR **1.29%**
    (14 of 20 draws ≤ 2%). Its draw spread is wide: the 2.5th percentile of recall is 0.36.
  - A3 single-entity at Ka = 25: 0.943 at 1.6%.
  - C2, seeds 0 and 2: FPR 2.1%, at recall 0.44–0.46.
  - A3 was not selected on development data, where it collapsed on NF-UNSW. These are
    observations, not confirmations.
  - **Why A3 at Ka = 5 is not a success either.** It is one seed and 20 draws. Its 2.5th
    percentile (0.357) is below A1's recall (0.839), so it would fail the registered I1 rule's
    spread clause even at that budget. And its FPR does not hold as labels are added: median
    5.5% at Ka = 25 and 6.5% at Ka = 100. An effect that disappears with more labels is more
    likely draw noise on a two-source calibration than a reliable operating point.
  - **The verdicts do not depend on the frozen choices.** Under I1's rules, A3 and A5 at
    Ka = 25 would also fail (2.5th percentile 0.583 and 0.556 ≤ 0.839). Under I3's rules, C2
    would also fail (mean recall 0.586 against the 0.939 needed).
- **The registered choices all overran the budget, as did zero-label A1.** The deployed robust
  detector kept its budget only by alerting on nothing.

**Post-hoc diagnostic [E, after the verdicts; changes none].**
- **Every false alert of the A1 model on N4 comes from one label-benign host**
  (192.168.100.46), in all three seeds: 130 alerts in seed 0 (FPR 21.0%; 40% of its 325
  evaluation windows; 125 on 2018-06-04, the main DoS/DDoS day, and 5 on 06-18/19), and 44 in
  each of seeds 1 and 2 (FPR 7.1%; final audit, `calibration_audit.json`).
- **That host dominates calibration:** 503 of the 781 hold-out windows. The next largest
  source is 0.0.0.0 (127 windows), the unspecified IPv4 address, not an ordinary host.
  - Its alerting windows have nearly the same feature medians as its hold-out windows:
    `log_pkts` 9.41 vs 9.24, `new_dst_frac` 0 (saved in `posthoc_n4.json`).
  - A plausible reading: small shifts move its clustered scores across a threshold that its
    own windows set.
- The benign evidence is therefore essentially **two sources, one of them an ordinary host**
  (2.2 effective hosts, section 10). The realised FPR measures one host's behaviour on one
  flood day. It is not a network-wide false-alert rate.
- A host that is busy during a flood (target, relay or bystander) can carry the dataset's
  benign label. These alerts are **unverified**, not confirmed false positives.

## 6. Error analysis and failure taxonomy [E]

**Attribution** (TreeSHAP via LightGBM `pred_contrib`, seeds 0–1;
`reports/phase8i/attribution.json`). These are predictive, not causal, attributions.
- **Sources NF-UNSW + NF-ToN-IoT:** `new_dst_frac` (33% of gain), `rst_frac`, `med_log_dur`.
  The ranking is stable across seeds (Spearman 0.98). False alerts on NF-CIC are driven by
  `rst_frac` and `log_dst_ports`. The missed DDoS-LOIC windows have negative `log_pkts` and
  `udp_share` contributions: the source networks' DoS looks different.
- **Sources NF-CIC + NF-ToN-IoT** (target NF-UNSW): `log_pkts` alone carries 53% of the gain,
  a volume shortcut. It is the least seed-stable model (Spearman 0.78).
- **Target NF-ToN-IoT:** false alerts are driven by `new_dst_frac` (mean contribution +4.44).
  The feature counts destinations unseen during calibration, so it grows with calibration age
  by construction. **This is a plausible cause of the NF-ToN-IoT overrun (A1 FPR 14.5%). It
  is a hypothesis, not tested here.** It does not explain N4 (section 5).

**Failure taxonomy.** Categories are assigned only where the evidence supports them.

| failure | units | category | evidence |
|---|---|---|---|
| DDoS-LOIC missed by the source model and by A4 at every budget | NF-CIC 02-20 | 1 poor ranking | ROC-AUC 0.225 (attacks scored below benign); A4 0.085 in all draws; target-only A5 recovers it in some draws only (15/20 at Ka = 5, 4/20 at Ka = 100) |
| source threshold unusable | all except NF-UNSW | 2 threshold miscalibration | A0 FPR 19.9–51% |
| benign-calibrated threshold overruns | NF-ToN-IoT, NF-UNSW, N4 | 2 threshold miscalibration + 5 domain shift (within the target over time) | A1 FPR 14.5%, 3.7%, 7–21%; NF-ToN-IoT driven by `new_dst_frac`; N4 by one host |
| N4 FPR rests on one host | N4 | 9 insufficient independent evidence + 4 label ambiguity | 2.2 effective benign hosts, about 5 effective observations; alerts on a flood day (section 10) |
| seed-unstable zero-label detection | NF-CIC 03-02 | 6 model uncertainty | A1 recall 0.86 / 0.05 / 0.16 across seeds |
| representation changes do not remove network identity | all | 5 domain shift | identity AUC 0.98–1.00 under every variant |
| robust detector nearly silent on N4 and most NetFlow units | N4, NF-CIC (except 02-16: 0.56), NF-UNSW | 2 threshold miscalibration | ROC-AUC 0.91–0.93 but network-level recall 0–0.11 at T0 |

## 7. Interpretation

1. **Cross-network detection did not improve under the registered tests.**
   - I1 and I3 failed on the fresh network, and I2 could not be evaluated there.
   - This matches Phase 8h's four negative results: the problem is not solved by a few
     labels, by feature removal, or by an abstention rule.
2. **The binding constraint is calibration, not ranking. The two must be reported
   separately.**
   - Ranking quality (ROC-AUC, oracle recall) and operating-point reliability (realised FPR
     at a threshold fixed in advance) failed independently in this phase. NF-ToN-IoT and N4
     rank attacks moderately to well (ROC-AUC 0.82 and 0.87) yet overrun their false-alert
     budget, while NF-CIC 02-20 stays near its budget (1.3% FPR) and ranks attacks backwards.
   - Ranking on N4 was moderate, and labels raised recall to about 0.92. But none of the
     registered methods kept its false alerts near 1%, because the benign calibration did not
     represent the evaluation period.
   - A non-selected method (A3, Ka = 5) did reach 0.94 recall at 1.3% median FPR, with a wide
     spread across draws. That is a lead, not evidence.
   - On N4 the benign evidence was a single dominant host. Phases 8g and 8h saw the same
     pattern: the operating threshold, not the model, decides whether a detector is usable.
3. **What did help, on development data only [E]:**
   - **The Phase 8i source setup** (two source networks, network-balanced weights, strict
     calibration, 50k cap). NF-UNSW ROC-AUC rose from 0.39 to 0.97. The contributing change
     is not isolated, and a shared-institution effect is possible.
   - **Labels where the zero-label model was unstable or blind,** but not where it ranked
     attacks backwards.
   - Neither effect is confirmed.
4. **Abstention did not hide attacks by construction.** Alerts are never suppressed. But on N4
   the shift score abstained on 80% of blocks, which held 67% of the attack windows inside
   eligible blocks (49% of all attack windows). A policy
   that abstains on most of an attack period cannot be called reliable, even when it is
   honest about it.
5. **Network identity appears diffuse, and the models depend on network-specific features.**
   Removing the top 1–3 identifying features, or the 4 volume features, leaves identity AUC
   at 0.98 or above. Only those subsets were tested. Within the tested variants, removal (C1)
   and per-domain centring (C2) did not remove it. Which feature carries a model also changes
   with the source set (`new_dst_frac`, or `log_pkts` at 53% of gain; section 6), so a
   feature that transfers for one pair of networks need not transfer for another.

**Missing evidence:**
- more than one fresh network, ideally from a different institution;
- verified-benign traffic on the test network;
- benign populations of more than a handful of hosts;
- a calibration-age study isolating `new_dst_frac`.

## 8. Decisions

| question | decision |
|---|---|
| Phase 8i research closure | **GO.** Protocol frozen before the test, all runs complete, failures preserved. |
| Independent confirmation of any Phase 8i method | **NO-GO.** All registered confirmatory tests failed or were not evaluable. |
| Deploying any candidate method | **NO-GO.** No registered method kept false alerts within budget on the fresh network; the one exploratory exception (A3, Ka = 5) is unconfirmed. The deployed detector is unchanged. |
| Publishing the research report | **GO, after operator review** (local commits only; no push without authorization). |
| Engineering fix (late-record health) | **GO.** Tested; it changes only the health flag. |
| Window builds and ingest under the 3.4 GiB budget | **GO** after the final audit (section 10): bounded slices, identical development outputs at under 1.3 GB commit, OS-enforced cap. The NF-BoT-IoT-v3 ingest and build were not re-run, so their compliance is inferred from smaller equivalent workloads (a 10.6M-flow synthetic build; a 2.4M-row ingest), not shown on that capture. |

## 9. Independent review and deviations

- **The review.** An independent review pass checked the code, the JSON and the git ordering.
  It found **no bug that changes a registered verdict**, and confirmed that the
  pre-registration, amendments, freeze and protected test happened in the recorded order.
- **Upheld findings, corrected above:**
  1. The I2 development claim was overstated; added the within- and without-NF-ToN-IoT
     sensitivity analysis.
  2. The blanket "every method overran on N4" was wrong: the non-selected A3 reached 1.3%
     FPR.
  3. "Labels do not fix DDoS-LOIC" was wrong: target-only A5 sometimes recovers it.
  4. The NF-UNSW gain was attributed to the source set alone, though other changes coincide
     with it.
  5. The post-hoc "all on 06-04" was wrong (125 of 130), and the analysis is seed 0 only.
  6. The identity-diffusion wording claimed more than the tested subsets show.
- **Deviations from the pre-registration** (also in AUDIT_TRAIL.md):
  - The moving-block bootstrap intervals for I2/I3 on N4 were not computed. The verdict
    rules are effect-size rules, so no verdict depends on them.
  - The NF-ToN-IoT "initiator check" was a per-source attribution: 53% of attack windows come
    from 192.168.1.30–38. 192.168.1.193 contributes 36% (attack share 0.58) and is
    unexplained. N4 got no label audit.
  - The label-draw generator seed is `1_000_003·draw + Ka (+7)`, not the draw index.
  - `pool_short` is checked on draw 0 only.
  - The first evaluation hour is discarded rather than used for shift scores: the scores
    compare each block with the hold-out.

## 10. Final audit (after publication of the results)

The results above were pushed at `6cfe97f`. This audit re-checked them, resolved the memory
violations and characterised the N4 calibration. It changes no verdict.

### 10.1 Verdicts and denominators

- **Re-derived from the raw N4 outputs:** I1 **failure**, I2 **not evaluable**, I3
  **failure**. The verdict code implements the registered rules and amendment A4, which was
  committed (`559b4e2`) before the freeze (`5db0c6f`) and the protected run (`0176269`). The
  pre-registration was only appended to, and not after the freeze.
- **Denominators:** I1 FPR medians are over 20 draws of 620 benign windows (e.g. 9.76% =
  60.5 / 620, the median of an even count). The I3 raw FPR 11.7% is the mean of 130, 44 and 44
  false alerts over 620.
- **Robust to the frozen choices** (section 5): no other method or variant would have passed.
- **C selection wording:** recorded as an ambiguity in AUDIT_TRAIL.md item 8; either reading
  gives a failure.

### 10.2 Memory-budget violations

- **Root cause (window build, 4.1 GB):** full captures were read in one-hour slices by
  repeated lazy Polars scans, whose memory grew with every scan even while nothing was held
  (1.0 → 2.3 GB commit over 57 slices on NF-ToN-IoT). NF-BoT-IoT-v3's time-overlapping row
  groups (66 of 72) and its 4.05M-flow hour made each scan large.
- **Root cause (ingest, 3.69 GB):** the 64 MiB CSV block. 16 MiB halves the peak with
  identical output.
- **Fix:** slices of at most 500,000 flows on the window grid, read one row group at a time;
  ingest blocks of 16 MiB.
- **Validation without protected data:**
  - All 80 development outputs are identical to the frozen ones.
  - Peak working sets: NF-CIC 1.8 → 0.9 GB, NF-ToN-IoT 2.5 → 1.0 GB.
  - A synthetic BoT-shaped capture runs at 1.17 GB commit under a 2 GiB cap, where the frozen
    code fails.
- **Enforcement:** `scripts/run_capped.py` (OS-enforced cap on committed memory, exact peak);
  the watchdog now reads peak working sets, so a brief overrun of a process that is still
  running at the next 5 s poll is detected; one that spikes and exits between polls is not.
  Only the cap prevents overruns. None of the result-producing Phase 8i runs used it.
- **Limit:** compliance on NF-BoT-IoT-v3 itself is inferred from equivalent workloads; its
  build and ingest were not re-run.
- Evidence: `reports/phase8i/memory_audit.json` and `reports/phase8i/audit/`; details: AUDIT_TRAIL.md item 7.

### 10.3 Why the N4 benign calibration was inadequate

`scripts/phase8i/calibration_audit.py` (post-hoc; fits nothing, chooses no threshold) uses
the saved A1 scores (`reports/phase8i/calibration_audit.json`). The calibration-side columns
use no evaluation scores. **But hold-out membership is not label-free:** the registered
strict-benign rule (pre-registration section 2, amendment A1) removes every entity that
attacks in *either* period, so evaluation labels decide which hosts calibrate. On development
data this removed 912 NF-ToN-IoT and 1,085 NF-CIC 02-22 calibration windows; for N4 the
effect cannot be determined from the saved files. No deployed detector has this oracle: it
makes every Phase 8i benign calibration cleaner than an operational one would be.

| domain | hold-out windows | hosts | effective hosts | effective n (sessions) | host-grouped exceedance | i.i.d. conformal FPR 95% | realised A1 FPR | KS hold vs eval benign |
|---|---|---|---|---|---|---|---|---|
| NF-CIC (6 days) | 25,919–36,144 | 4,736–6,557 | 477–651 | 914–1,152 | 0.008–0.010 | about 0.9–1.1% | 1.0–1.6% | 0.01–0.03 |
| NF-UNSW | 443 | 17 | 12.3 | 27 | 0.007 | 0.25–1.97% | 3.7% | 0.09 |
| NF-ToN-IoT | 4,571 | 3,634 | 92.7 | 4,571 | 0.030 | 0.72–1.29% | 14.5% | 0.68 |
| **N4 NF-BoT-IoT-v3** | 781 | 7 | **2.2** | **4.8** | **0.644** | 0.36–1.66% | **7.1–21.0%** | 0.38 |

- **Definitions:**
  - Effective hosts = (Σm)² / Σm² over hold-out windows per host.
  - Effective n = n / (1 + (m_w − 1)ρ), with ρ the intra-session correlation of the A1 score
    and sessions split at 30-minute gaps.
  - Host-grouped exceedance: the T0 threshold computed from the other hosts' hold-out
    windows, applied to each held-out host (up to 10 host folds).
  - The i.i.d. interval is the conformal guarantee if windows were exchangeable.
- **N4, what the data show:**
  - **One host is 64% of the hold-out** (192.168.100.46, 503 of 781). The second is 0.0.0.0.
    The intra-host correlation of scores is 0.97, so 781 windows carry about 2–5 independent
    observations.
  - **The calibration fails its own internal check** (no evaluation scores used): a
    threshold from the other hosts is exceeded by 64% of the held-out host windows. That
    figure is 503 / 781: when 192.168.100.46 is held out, all of its windows exceed the
    threshold set by the others, and no other host's windows do.
  - **Time gap:** the hold-out covers 2 days in May. Every benign evaluation window falls on a
    day with no calibration data, starting 305 h (12.7 days) after the hold-out ends.
  - **The benign train/hold-out split is unbalanced** (178 vs 781 windows): the split is by
    time slots, and the benign windows cluster late in the calibration period.
  - **False alerts are concentrated:** all false alerts of all 3 seeds come from one host.
  - **The i.i.d. interval (0.36–1.66%) is irrelevant here:** exchangeability fails, and the
    realised 7–21% lies far outside it.
- **What can be concluded:** N4's realised FPR is not an estimate of a network-wide
  false-alert rate, and no threshold calibrated on this hold-out could have a meaningful
  1% guarantee. The I1 failure stands as registered; it shows that the method was not
  validated on N4 rather than that it would fail on a network with adequate benign data (labels
  did improve ranking: oracle recall at 1% FPR 0.42 → median 0.77). **I3 is a failure on
  ranking too:** C1_k2's oracle recall at 1% FPR is 0.20–0.36 against raw 0.41–0.42, and its
  ROC-AUC is 0.79–0.89 against 0.87. Both remain refuted, as the hypothesis ledger records.
- **What cannot be concluded:** whether the 192.168.100.46 alerts are false positives (the
  host may be a flood target or relay; its labels are unverified), and whether a larger
  benign population would have rescued any method. N4 cannot be re-used to find out.
- **Two separable failure modes on the development networks:**
  - **Small, dependent calibration** (NF-UNSW: 27 effective windows; N4). This can be seen
    in the calibration data alone.
  - **Calibration-to-evaluation drift** (NF-ToN-IoT: KS 0.68, 94% of benign evaluation
    windows on days without calibration, 35% from hosts absent from the hold-out). Its
    composition looks adequate. Only the grouped exceedance (0.030, three times the target)
    hints at it. (Its effective n of 4,571 is degenerate: 3,688 sessions for 4,571 windows,
    so the session correlation is clipped to 0.)

### 10.4 Recommended calibration eligibility checks (for a future registered test)

Proposed from development data. They are **hypotheses**: they were designed after N4's
post-hoc diagnostic, so N4 is not independent evidence for them.

1. **Effective sample size ≥ 199** session-adjusted windows: below 199 the 1% conformal
   threshold is the hold-out maximum and cannot control FPR at 1% (pre-registration section 2).
   Flag the estimate as degenerate when sessions are mostly single windows.
2. **Effective hosts ≥ 10**, and no host above 25% of the hold-out.
3. **Host-grouped exceedance ≤ 2α** (2% at α = 1%).
4. **Recency:** the hold-out ends within 24 h of the evaluation start. (An earlier draft
   also required the same hours of day; every NF-CIC domain splits one day at its midpoint
   and would fail it, so it was dropped.)

- **On development data:** all 4 checks pass all 6 NF-CIC domains (realised FPR 1.0–1.6%).
  NF-UNSW fails check 1 (3.7%) and NF-ToN-IoT fails check 3 (14.5%); both pass check 4.
- **On N4 (post-hoc):** N4 fails checks 1–4.
- **Use:** a domain that fails would report "FPR budget not supported" instead of a
  threshold, which is the honest output for N4. Their predictive value has to be tested on
  networks not used here.

### 10.5 Remaining risks

- **Scientific:**
  - One fresh network, with two benign sources; unverified benign labels.
  - The eligibility checks are untested.
  - A3's low-FPR observation is unreplicated.
  - The NF-UNSW zero-label gain is unexplained.
  - Development effects come from 3 network-level units.
- **Engineering:**
  - The N4 build and ingest were not re-run under the new code.
  - `run_capped.py` caps the total committed memory of the job, including the capping
    interpreter and `uv` (stricter than the per-process working set the budget was stated
    in). On POSIX it falls back to an address-space limit, which can fail spuriously with
    allocators that reserve large ranges, and reports the largest child's peak.
  - The bounded-memory claims rest on `reports/phase8i/audit/` (run records and output
    comparison), not on a re-run of the N4 build.
  - The strict-benign rule uses evaluation labels to choose calibration hosts (section 10.3).
  - `exp_b.py`'s confirm path skips the "≥ 60 benign evaluation windows" domain filter of the
    development path (frozen code; no effect on N4, which has 620).
  - Bounded builds are about 2× slower.
  - The frozen scripts' temp-directory leaks (`ns-h6-`, `ns-inc-`) remain as documented.
