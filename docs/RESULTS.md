# Results at a glance

Every number links to its source. **Data role:**
- **C**: confirmatory (pre-registered, untouched data, one shot);
- **E**: exploratory (development data, or data already inspected);
- **V**: validation split of the training dataset.

## Supervised detection (benchmarks)

| Setting | Data | Result | Role | Source |
|---|---|---|---|---|
| In-domain, CIC-IDS2018 (LightGBM, flow features) | CIC test, once | recall 0.983 [0.93, 1.00] at FPR 0.0009; 0.735 without 4 artefact fields | C | `reports/experiments/test_v1/` |
| In-domain, NF-UNSW / NF-IDS2018 | NF final test (both-protocol intersection), 3 seeds | recall 1.000 at FPR 0.0006–0.0010 | C | `reports/experiments/results_final_nf.md` |
| Cross-network transfer IDS <-> UNSW | NF final test | ROC 0.37–0.66; source thresholds flag 35–99% of benign flows | C | same |
| Label-free target calibration of the transferred model | NF final test | 23–183 false flows/h, recall <= 0.005 | C | same |
| Unseen attack groups with causal context (CIC) | validation, 5 seeds | e.g. DoS-HTTP 0.05 -> 0.95, SSH 0.60 -> 0.998; web 0.015 | V | `reports/experiments/results_v3.md` |

## Local behaviour baselines (Phases 6–7)

| Setting | Data | Result | Role | Source |
|---|---|---|---|---|
| Uncalibrated bundle on unfamiliar benign traffic | 13 CTU Zeek logs | about 120 false-alert windows/h (window FPR 0.54–1.00) | C | `reports/phase6/h1_ctu.json` |
| Local calibration, split thresholds (Phase 6 H1) | same | 2.3 false-alert windows/h; FPR <= 3x target in 7/12 captures: **H1 not supported** | C | same |
| Same, cross-fitted thresholds (Phase 7) | same captures, re-used | FPR <= 3x target in 12/12; median FPR 0 | E | `reports/phase7/calibration_drift.json` |
| Cross-fit vs split recall on labelled IoT-23 | 9 scenarios | lower recall in 3-1, 34-1, 44-1; higher in 8-1 | E | `reports/phase7/threshold_methods_iot23.json` |
| Contaminated (unlabelled) calibration | IoT-23, NF development | recall collapses (e.g. 0.60 -> 0.14): **H5 not supported** | E | `docs/phase6/REPORT.md` §3–4 |
| Device / service conditioning vs global | NF development | better ranking (FPR at recall 0.5: device 0.05–0.09, service 0.14–0.31, global 0.47–1.0); H2 partial, H3 not supported | E | same |
| Real PCAP end to end (CTU-26), Phase 7 defaults | inspected | unusual 99.0% -> 1.2% of flows; 0 false suspicious (102 in Phase 6) | E | `reports/phase7/ctu26_pcap_phase7.json` |

## Application protocol identification (nDPI proxy labels)

| Setting | Data | Result | Role | Source |
|---|---|---|---|---|
| ML, portable fields, NF-IDS2018 | validation | macro-F1 0.945 (port lookup 0.840) | V | `reports/phase6/appid_v2.json` |
| Without TTL/window shortcuts | validation | 0.944 vs 0.952 full: **H6 supported** | V | same |
| ML vs Zeek service on real traffic | 13 CTU logs | accuracy 0.925 vs port rule 0.999; abstains on 0.04%: **H7 not supported** | C | `reports/phase6/h7_ctu_appid.json` |
| Conservative ML + port policy (Phase 7) | NF development; CTU descriptive | see `docs/phase7/RELIABILITY.md` P3 | V / E | `reports/phase7/app_policy_selection.json` |

## Phase 8 (temporal models, incidents, streaming)

- Development (exploratory): [`docs/phase8/DEVELOPMENT_LOG.md`](phase8/DEVELOPMENT_LOG.md).
- Confirmatory (pre-registered, IoT-23 49-1, fresh):
  [`docs/phase8/CONFIRMATORY_RESULTS.md`](phase8/CONFIRMATORY_RESULTS.md).

| Question | Data | Result |
|---|---|---|
| Do temporal scorers beat robust median/MAD? | IoT-23 + NF-UNSW dev (3 eligible units) | No: mean PR-AUC 0.846 (robust) vs <= 0.723 (EWMA, GRU, TCN, lag-IForest) |
| Same, fresh capture, clean calibration (H1a) | 49-1 | Supported: 0.928 vs 0.676 (EWMA), delta CI [0.22, 0.29] |
| Does EWMA cope better with contaminated calibration (H1b)? | 49-1 | Refuted: 0.638 vs 0.723; both lose the attacker (recall < 0.02) |
| Product FPR on a fresh network (H2) | 49-1 | Supported: 1.09% (CI 0.5-2.1%) at a 1% target, recall 1.00 |
| Incidents (H3) | 49-1 | Refuted: 45x alert reduction, but purity 0.10 (9 benign single-window incidents) |
| App-ID consistency abstention | NF dev | Unknown-protocol abstention 1% -> 41%, IDS accepted accuracy 0.992 -> 0.996; the port table alone wins across datasets (UNSW 0.990 at 0.856 coverage) |
| Streaming exactness and cost (H6, H7) | 49-1, 5.4M records | Identical windows and incidents under jitter and duplicates; 24.8k records/s, 2.99 GB |
| Update gate vs a 60 s scan | 12 CTU-Normal (dev) | Rate-only gate: 0/12 flagged; v2 (strong-outlier rule): 7/12, 0 false |

## Phase 8b (independent validation; fresh IoT-23 captures, other malware families)

Hypothesis status for all phases: [`docs/HYPOTHESIS_LEDGER.md`](HYPOTHESIS_LEDGER.md).
Results: [`docs/phase8b/CONFIRMATORY_RESULTS.md`](phase8b/CONFIRMATORY_RESULTS.md).

| Question | Data | Result | Role |
|---|---|---|---|
| Cross-capture supervised window LightGBM vs local robust baseline (same 12 features) | IoT-23 1-1, 60-1, 9-1 (Hide and Seek, Gafgyt, Hajime), fresh | **replicated**: better PR-AUC in 2/3 (third inconclusive); detected 4/4 attackers at FPR 0-5.5% | C |
| GRU / TCN vs robust statistics | same | robust ahead in 3/3 (**replicated**) | C |
| Product FPR on fresh traffic | same | 0.0-1.5% at a 1% target (**replicated**; 4/4 with 49-1) | C |
| Transferred (source) threshold | same | FPR 5.5% / 1.3% / 0.0%: **mixed** | C |
| Does the deployed baseline catch the attacker? | same | **No: 0/4 attacking devices**, despite PR-AUC 0.92-0.95; incidents (B6) refuted | C (secondary) |
| Why incidents fail | 22 dev captures | 161/193 incidents single-window, 139 of them benign; persistence rules cost detection | E |

## Phase 8g (independent validation; CTU-13 scenarios 9 and 10)

- Results: [`docs/phase8g/RESULTS.md`](phase8g/RESULTS.md).
- Closure and post-hoc audit: [`docs/phase8g/FINAL_REPORT.md`](phase8g/FINAL_REPORT.md).
- **R**: retrospective (consumed data, after the result).

| Question | Data | Result | Role |
|---|---|---|---|
| Does the deployed baseline find the documented bots? (V3) | scenario 9 (Neris), fresh | **10/10** initiators; window recall 0.209; median delay 47.5 s; 0/803 verified-benign false alerts; 2,563 alerts/h on unlabelled background | C |
| Gated recalibration (V4) | same | **refuted**: absorbed 71% of attack windows | C |
| V1 / V2; scenario 10 | same; scenario 10 (Rbot) | not evaluable; scenario 10 declared failed (A2) | C |
| Frozen result vs an exact non-streaming reference | scenario 9 | 1,039 records had been dropped silently; recall 0.211, burden 2,755/h on the reference | R |
| Fixed stream vs reference | scenarios 9 and 10 | exact (scenario 10 at 3,700 s); at A2's 600 s, 90 late records, 0 forced closes (was 57) | R |
| Scenario 10, exploratory | scenario 10 at 3,700 s | 10/10; recall 0.573; 1.8 benign FA/h; 1,475 unverified/h; V4 absorbed 64% | R |
| Why V4 failed | scenario 9; synthetic | population-level gate diluted (attack = 0.47% of windows); bots gained own profiles; the product gate passed it too; per-entity review trigger added | R / E |
| Alert burden | scenario 9 | about 77% is what a 1% target gives at 197k device windows/h; 98% from pooled-fallback sources; incidents −18% only | R |

## Phase 8h (shift-robust window detection; development data)

- Report: [`docs/phase8h/FINAL_RESEARCH_REPORT.md`](phase8h/FINAL_RESEARCH_REPORT.md).
- Role **E** throughout: pre-registered decision rules, but data inspected in earlier phases.

| Question | Data | Result | Role |
|---|---|---|---|
| Does per-network standardisation or invariance screening transfer better? (H1a, H1b) | 7 attack domains, NetFlow + Zeek | No: Δ −0.256 and −0.081 recall at 1% FPR | E |
| Do block-bootstrap thresholds overrun less? (H2) | 27 benign units | No: 8/27 vs 8/27 | E |
| Does fusion beat the better single score? (H3) | 9 attack domains | No: Δ −0.093 | E |
| Within-network vs cross-network ranking of raw LightGBM | NF-CIC days vs NF-UNSW | oracle recall at 1% FPR ≈ 1.0 on 5/5 held-out days vs 0.03 across networks | E |
| Why | benign windows, ablations | network identifiable at ROC-AUC 0.9999; within NF-CIC, removing volume (−0.60) or `new_dst_frac` (−0.39) costs recall; across networks, removing volume lifts ROC-AUC 0.39 → 0.93 | E |
| Threshold rules | 27 benign units | units over twice the target: cross-fit 3/27, split-conformal 8/27 (untested, p = 0.06) | E |

## Phase 8i (cross-network adaptation; one protected confirmatory network)

- Report: [`docs/phase8i/FINAL_REPORT.md`](phase8i/FINAL_REPORT.md).
- **C** = the single NF-BoT-IoT-v3 evaluation after the freeze; **E** = development.

| Question | Data | Result | Role |
|---|---|---|---|
| Do 25 labelled target attack windows restore detection? (I1) | NF-BoT-IoT-v3 | No: recall 0.92 but FPR 9.8%; not better than zero-label (0.84) at the 2.5th percentile | C |
| Does a shift score mark blocks that overrun their false-alert budget? (I2) | NF-BoT-IoT-v3 / 118 development blocks | Not evaluable on N4 (the deployed detector raised no alerts); development pooled AUC 0.72, driven by between-domain differences; it does not beat the sample-size comparator | C / E |
| Does removing network-identifying features help? (I3) | NF-BoT-IoT-v3 / 3 development networks | No: +0.02 recall at 19% FPR; development −0.065 | C / E |
| Zero-label transfer with the Phase 8i source setup | NF-UNSW | ROC-AUC 0.97 (0.39 in Phase 8h); cause not isolated (source set, cap, weighting and calibration all changed) | E |
| Was N4's benign calibration adequate? (final audit) | NF-BoT-IoT-v3 | No: 7 hosts, 2.2 effective, about 5 effective observations; a threshold from the other hosts is exceeded by 64% of the held-out host windows; evaluation benign windows start 12.7 days after the hold-out | E (post-hoc) |
| Why thresholds overran | N4 post-hoc, attribution | N4: one benign host dominates calibration and evaluation; NF-ToN-IoT: `new_dst_frac` drives false alerts (hypothesis) | E |

## Phase 8j (calibration reliability; preparation only)

- Documents: [`docs/phase8j/`](phase8j/README.md). Development no-go: nothing confirmatory; no fresh data opened.

| Question | Data | Result | Role |
|---|---|---|---|
| Did evaluation labels choosing calibration hosts change Phase 8i results? | 9 development domains incl. N4 | No: identical thresholds, FPR and recall | E |
| Does recall survive a destination memory that keeps the calibration attackers' traffic? | same | FPR unchanged; recall lower on 3 domains (NF-CIC 03-02 0.86 → 0.00, 02-22 0.09 → 0.02, NF-UNSW 0.97 → 0.62) | E |
| Does the deployable protocol (P1x: purged memory) keep the oracle's recall? | same, 3 seeds | Yes: equal on every domain, higher on NF-ToN-IoT (0.61 vs 0.36) and N4 (0.88 vs 0.84) | E |
| Can an abstaining method keep the budget with ≥ 50% coverage on ≥ 2 of 4 development units? | 4 development units, 3 seeds | No-go: best method (M1) qualifies on NF-CIC only; the learned model (M2) is degenerate; Phase 8j stops before fresh data | E |
| Are the proposed eligibility checks statistically safe? | simulation | Not individually; together very conservative; a PAC rank at a dependence-adjusted effective n is the registered alternative (simulation-only support) | E |

## Phase 8k (calibration reliability and selective detection; preparation only)

- Documents: [`docs/phase8k/`](phase8k/README.md). Closed NOT EVALUABLE: the feasibility probes dropped F2 (no benign calibration traffic), and F1's confirmation networks were left untouched.

| Question | Data | Result | Role |
|---|---|---|---|
| Does host-balanced calibration help? | 4 development networks, 3 seeds | No: FPR rises on NF-CIC and NF-ToN-IoT; only NF-UNSW improves, with a recall loss | E |
| Why do calibrations fail? | same | small calibration (NF-UNSW), population turnover (NF-ToN-IoT), dominant-host change (N4); only the first is visible at decision time | E |
| Do calibration-only rules separate adequate from unsafe networks? | same | Fixed checks: 4/4 (circular); PAC rules: falsely accept NF-ToN-IoT; all reject ~94% of adequate small calibrations in stress tests | E |

## Phase 8l (data eligibility and statistical power; design only)

- Documents: [`docs/phase8l/`](phase8l/README.md). Decision: NO-GO for network-level accept/reject confirmation; no protected data opened.

| Question | Data | Result | Role |
|---|---|---|---|
| How many independent networks would a powered confirmation need? | simulation | at least about 15–30, each with ≥ 1,000 effective benign windows, for a good rule (a lower bound) | design |
| How many eligible independent networks does public data offer? | 15+ candidates surveyed | 0–1 confirmation-grade (DEDALE, pending verification), 3–6 development-grade | design |
| Are AIT / UWF labels fit for confirmation? | spent probe networks | AIT: flow-level labels, attack entities ambiguous, attacker benign-labelled in calibration; UWF: benign pooled and heavily reduced | E |
| Does a 1% conformal threshold calibrated on 2 benign weeks hold its budget over the next 2 weeks on an unseen network? | DEDALE green_internal, frozen pre-registration, one run | **HOLDS**: verified-benign FPR 0.55% [0.49, 0.62]% (26 hosts, 272,806 windows); attack and post-attack periods hold; sensitivity ≤ 1.2% | **confirmatory, n = 1** |
| How useful is detection at that threshold? | same | window recall 7% (43 attack windows), both entities first detected 44–49 h after their first attack window; ~200 false alerts/day; 90% of false alerts from the frozen destination memory | descriptive |

## Phase 8m (adaptive destination memory; development data)

- Documents: [`docs/phase8m/`](phase8m/FINAL_RESEARCH_REPORT.md). Registered development NO-GO; the deployed detector (B0) stays. (Phase 8l's "~200 false alerts/day" is the upper part of the daily range; the mean is 151 per working day.)

| Question | Data | Result | Role |
|---|---|---|---|
| Why do DEDALE's false alerts concentrate on new destinations? | DEDALE (consumed) | the evaluation memory is frozen, so post-calibration destinations stay "new"; 88% of false alerts are novel; setting the feature to 0 removes 88% of them and all detection | post-hoc |
| Does a guarded adaptive memory (≥ 2 sources, ≥ 1 h) improve detection (H3) or false alerts (H1)? | 4 development networks, 3 seeds | **not supported**: recall falls on 4 of 4 networks; FPR falls on NF-ToN-IoT (−89%) but doubles on NF-BoT-IoT | registered development |
| Does it resist contamination while adapting (H2)? | same, plus synthetic beacons | **not supported**: single-host beacons stay novel (by construction), but only 5.5% of benign new destinations are accepted, and destinations contacted by several attackers are accepted | registered development |
| Why did the NF-CIC recall collapse? | same | every retrained variant loses single-attacker days that the unrefitted B0 model keeps (refit fragility; investigated in Phase 8n) | exploratory |

## Phase 8n (training stability and robustness; development data)

- Documents: [`docs/phase8n/`](phase8n/FINAL_RESEARCH_REPORT.md). Replicated development GO for a 5-member seed ensemble (M2); development only; deployed detector unchanged.

| Question | Data | Result | Role |
|---|---|---|---|
| What makes the refitted detector collapse? | 4 development networks, 23 perturbation arms × 3 replicates | losing the information in `new_dst_frac` (drop or shuffle: 9/9 catastrophic focus cases; no-op arms 0/9); training-data changes flip single-attacker days as a whole (7 of 24 cases) | registered development diagnostic |
| Do seed ensembling, bagging or regularisation make it robust? | same, base and host-bootstrap stress regimes | M2 (5-seed ensemble) passes the registered rule; M3 passes once but not on fresh fits; M1 fails | registered development |
| Does M2's gain replicate with fresh randomness? | same, replicates never seen before | **yes**: unstable entities 11 → 1 (≥ 1 window) and 14 → 10 (≥ 20 % of windows), collapses 1 → 0; recall +0.09 NF-CIC, +0.05 NF-UNSW, −0.02 NF-ToN, −0.03 NF-BoT | registered development |

## Phase 8o (feature semantics, ensemble size, calibration; development data)

- Documents: [`docs/phase8o/`](phase8o/FINAL_RESEARCH_REPORT.md). Development NO-GO: no new candidate; frozen M2 and the deployed detector unchanged.

| Question | Data | Result | Role |
|---|---|---|---|
| Does aligning training rows with the deployed frozen memory help? (H1) | 4 development networks, 6 fresh K = 5 fits per arm | **no detectable effect** (macro recall −0.006); the registered matched-information control turned out degenerate (bit-identical scores) | registered development |
| Does dropping the cold-start source days help? (H1b) | same, base fits | **no**: NF-ToN recall −0.20 | registered development |
| What does training without the frozen-novelty attack association do? (F2) | same | NF-CIC AUC 0.78 → 0.48 (chance); NF-ToN ranking improves but recall collapses at T0 | registered, descriptive |
| Can a smaller ensemble keep M2's stability? (H2) | same, nested prefixes K = 1, 2, 3, 5 | **no**: K = 3 keeps stability but loses recall on 3 networks; K = 5 retained; cost linear in K (about 20k windows/s at K = 5) | registered development |
| Does an aligned (frozen-memory) hold-out fix FPR? (C1) | same | **no**: closer to α on 3 networks, NF-UNSW recall 0.84 → 0.52 | registered development |
| What happens without confirmed calibration labels? (C3) | same | recall NF-UNSW 0.05, NF-ToN 0.001; collapse via the threshold and the destination memory | registered, descriptive |

## Phase 8p (victim-side and service-aware detection, realistic calibration; development data)

- Documents: [`docs/phase8p/`](phase8p/FINAL_RESEARCH_REPORT.md). Development NO-GO: no new candidate; frozen M2 and the deployed detector unchanged.

| Question | Data | Result | Role |
|---|---|---|---|
| Which evaluation attackers are really missed? | 75 Phase 8n/8o entities, official CSE-CIC-IDS2018 attacker table | 19 of 20 never-alerted entities are undocumented sources (label artifacts); documented misses = 10 LOIC attackers (LOIC-UDP onset labelled HTTP) and one low-rate SMB host | exploratory (label audit) |
| Is the missing evidence present in flow metadata? | same, in-domain diagnostics | every documented miss is separable within its own network on source and victim windows (in-domain only; not established as transferable) | exploratory |
| Does victim context (D2) / service context (S1) / late fusion (D3) improve detection under the shared 1% budget? | 4 development networks, 6 paired K = 5 fits per arm | **no**: documented-attacker R₂₀ change −19 / −7 / −5 (entity bootstrap intervals below 0); victim context collapses NF-CIC (0.81 → 0.18); service-only control weak (0.13) | registered development |
| Does a victim-only model transfer? (D1) | same, victim windows | NF-CIC victim-window AUC 0.30–0.69 (4 of 6 days below 0.5); NF-ToN 0.77, NF-BoT 0.89 | registered, descriptive |
| Can calibration work without confirmed labels? (C1–C3) | same | unlabelled 0.37, 60-min delayed labels 0.39, host-balanced 0.61 macro recall vs 0.87 with labels; host-balanced FPR on NF-ToN 34% | registered development (C3: not supported) |

## Phase 8q (ground-truth audit and label-free calibration; development data)

- Documents: [`docs/phase8q/`](phase8q/FINAL_RESEARCH_REPORT.md). Calibration research NOT SUPPORTED; no model trained; deployment unchanged.

| Question | Data | Result | Role |
|---|---|---|---|
| What do the evaluation labels actually mark? | 9 target domains, about 710k windows, official CSE-CIC-IDS2018 table and documented attacker ranges | versioned categories (label-audit-1.0.0): 48 documented attackers / 5 attacked hosts / 22 undocumented sources; 02-20 LOIC-UDP onset labelled LOIC-HTTP; 03-02 bots mostly outside documented operator intervals; no verified benign | exploratory audit |
| How does frozen M2 score on the audited views? | saved scores | historical 0.788 vs documented-attacker 0.904 macro recall (same detector; different population) | audit |
| Where does the calibration-label dependency come from? | saved scores, counterfactual cells | threshold contamination 0.29-0.35 + evaluation-memory contamination 0.15-0.21 of the 0.50 loss; hold-out memory 0 | exploratory decomposition |
| Can a label-free threshold recover it? | same, 6 fits | **no**: host cap 0.387, block median 0.372, trim 0.376, abstention 0.126 vs 0.372 without labels (+0.10 required) | registered development |
| How do robust thresholds behave under controlled contamination? | clean hold-out + 0.5-10% attacker windows | host cap resists one persistent host but doubles clean FPR on NF-ToN; trim breaks at 5% vs 2% but trims a benign NF-BoT host (FPR 56%) | registered, descriptive |

## Telemetry

| Check | Result | Source |
|---|---|---|
| PCAP flow assembler vs Zeek on CTU-26 (199,279 packets) | TCP flow count equal; 99.8% packet/byte agreement; close-linger bug found and fixed | `reports/audit/pcap_vs_zeek.json` |
