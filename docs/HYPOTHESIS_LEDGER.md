# Hypothesis ledger (Phases 5-8)

One row per research claim, with the strongest evidence that exists for it. Status:

- **confirmed**: pre-registered, evaluated once on data not used for any choice, criterion
  met;
- **refuted**: same, criterion failed;
- **not testable**: pre-registered, but the fresh data did not meet the testability rule;
- **exploratory only**: evidence comes from development or already-inspected data;
- **open**: no evaluation yet.

"Independent replications" counts fresh captures or datasets with a confirmatory result.
One capture is n = 1.

## Supervised detection (Phase 5)

| Claim | Status | Evidence | Replications |
|---|---|---|---|
| LightGBM detects attacks in-domain at FPR about 1e-3 | **confirmed** | CIC test once (recall 0.983); NF final test, 3 seeds (1.000) | 2 datasets |
| Supervised models transfer across networks (IDS <-> UNSW) | **refuted** | NF final test: ROC 0.37-0.66 | 1 pair |
| Label-free target calibration rescues transfer | **refuted** | NF final test: recall <= 0.005 | 1 pair |

## Local behaviour baselines (Phases 6-8)

| ID | Claim | Status | Evidence | Open question |
|---|---|---|---|---|
| P6-H1 | Local calibration keeps FPR <= 3x target on unfamiliar benign traffic | **refuted** (split thresholds, 7/12); cross-fit 12/12 is *exploratory* (same captures) | CTU-Normal x13 | Cross-fit FPR on fresh benign traffic is only partly re-tested (P8-H2, 1 capture) |
| P8-H2 | Product calibration (cross-fit, vetted) FPR <= 3x target on a fresh capture | **confirmed, n = 1** | 49-1: 1.09%, CI [0.5, 2.1]% | more captures/families |
| P6-H2 | Service conditioning lowers FPR vs global | exploratory only (partial) | NF dev | — |
| P6-H3 | Device context improves detection | exploratory only (not supported as specified) | NF dev, IoT-23 inspected | — |
| P6-H4 | A learned model (IForest) beats robust statistics somewhere | exploratory only (weak) | NF dev, IoT-23 34-1 | — |
| P8-H1a | Robust median/MAD ranks windows better than the dev-selected temporal model (guarded EWMA), clean calibration | **confirmed, n = 1** | 49-1: PR-AUC 0.928 vs 0.676; 4 bootstrap blocks | GRU/TCN/lag-IForest **never tested on fresh data**; more captures |
| P8-H1b | Guarded EWMA beats robust_z under contaminated calibration | **refuted, n = 1** | 49-1: 0.638 vs 0.723 | — |
| P6-H5 | Calibration tolerates <= 5% contamination | exploratory only (not supported) | NF dev, IoT-23 | No confirmatory test at low contamination exists |
| — | Detection works under realistic (unlabelled) calibration when the attacker is present during calibration | **refuted in every exploratory setting**; 49-1 consistent (recall < 0.02) | | Fundamental limit, not a tuning issue |
| P8b-B1/B2 | Cross-capture supervised window LightGBM ranks better than local robust baselines (clean and contaminated calibration) | **replicated** (2 supported, 1 inconclusive, 0 refuted) | IoT-23 1-1, 60-1, 9-1: e.g. +0.082 / +0.018 (ns) / +0.063 | cross-network (non-IoT-23) test |
| P8b-B3 | GRU / TCN do not beat robust statistics | **replicated** (3/3) | robust ahead by 0.35-0.5 | |
| P8b-B4 | Product FPR <= 3x target on fresh traffic | **replicated** (3/3; 4/4 with 49-1) | 0.0-1.5% | |
| P8b-B5 | A transferred (source) threshold breaks the FPR target | **mixed** | 5.5% / 1.3% / 0.0% | |
| P8b-B6 | Incidents concentrate attack evidence (window-weighted purity >= 0.8, reduction >= 5) | **refuted** (2 refuted, 1 not testable) | product had no true detections | |
| — | The deployed baseline detects attacking devices on fresh captures | **contradicted (secondary metric)** | 0/4 attackers on 1-1, 60-1, 9-1 (49-1: 1/1) | root cause found (Phase 8c, below) |
| P8c | Why 0/4: the single device-level threshold is set by transient sources scored against the pooled fallback (100% of the tail on 1-1 and 9-1); 60-1: insufficient calibration | **explained retrospectively** (no coding defect; design defect in threshold pooling) | `docs/phase8c/ROOT_CAUSE.md` | does a corrected threshold policy work? Pre-registered as X2 (ToN_IoT) |
| P8c | LightGBM's advantage reflects a recurring scanning signature (a single feature matches it) | exploratory on IoT-23/UNSW; **not the whole story externally** | lgbm_audit.json; X4 | |
| P8c-X1 | Deployed FPR <= 3x target on an external network (ToN_IoT) | **refuted, n = 1** | FPR 8.9% [7.4, 10.5]; 19-day gap between calibration and evaluation | drift vs model failure not separable |
| P8c-X2 | Root-cause prediction (no tail warning, so the address-class threshold changes nothing) | **supported, n = 1** | diagnostic silent; recall 0.317 vs 0.314 | |
| P8c-X3 | Cross-network supervised LightGBM (no UNSW in training) ranks better than robust_z | **supported, n = 1** | ToN_IoT: 0.973 vs 0.695; 4 bootstrap blocks only | |
| P8c-X4 | LightGBM adds ranking beyond the scan signature | **supported, n = 1** | delta 0.147 [0.035, 0.262] | |
| P8c-X5 | Incidents: window-weighted purity >= 0.8 and reduction >= 5 | **refuted, n = 1** (0.779, 11x) | | |
| — | Detection delay on Zeek logs | exploratory only | IoT-23 20-1: up to about 12 h for long C&C | not measured confirmatorily |

## Incidents (Phase 8)

| ID | Claim | Status | Evidence | Open question |
|---|---|---|---|---|
| P8-H3 | Incidents reduce load >= 5x with mean purity >= 0.8 | **refuted, n = 1** | 49-1: 45x reduction, purity 0.10 (9 single-window benign incidents) | Why, and can a rule chosen on development data fix it on fresh data? (Phase 8b) |
| — | Each attacking entity forms one incident (no fragmentation) | exploratory only | demo 1/1; IoT-23 3-1 up to 10 per device; 49-1: 1 (not pre-registered) | |

## Application intelligence

| ID | Claim | Status | Evidence |
|---|---|---|---|
| P6-H6 | App classification works without host-stack shortcuts | exploratory only (supported) | NF dev validation |
| P6-H7 | Selective prediction improves app ID under shift | **refuted** | CTU x13, Zeek reference |
| P8-H5 | Class-consistency abstention raises unknown-protocol abstention without losing accuracy | **not testable** on 49-1 (25 reference flows); exploratory support on NF dev (1% -> 41%) | open |
| — | ML protocol ID beats the port table across networks | **contradicted** in exploratory data (UNSW: port 0.990 vs hybrid 0.779) | |

## Engineering claims (pre-registered, deterministic)

| ID | Claim | Status |
|---|---|---|
| P8-H6 | Streaming == offline under jitter and duplicates | **confirmed** (5.4M real records) |
| P8-H7 | < 3.5 GB peak and >= 20k records/s | **confirmed** (2.99 GB, 24.8k/s) |

## Summary of the evidence gaps

1. Every Phase 8 behavioural confirmation rests on **one** fresh capture, one malware family
   (Mirai) and 3.7 h of evaluation.
2. GRU, TCN and lag-IForest were rejected on development data only. Supervised window-level
   LightGBM was never compared on the same features.
3. Operational metrics (false alerts/h, detection delay, incidents/h) exist confirmatorily
   only for 49-1.
4. The incident failure (P8-H3) has not been explained or addressed.
5. Contaminated calibration remains the binding limitation, and nothing tested so far
   changes that.

Phase 8b (docs/phase8b/) addresses gaps 1-4 with fresh IoT-23 captures from other malware
families. Status: 1-1, 60-1 and 9-1 evaluated ([results](phase8b/CONFIRMATORY_RESULTS.md)). Gap 4 is explained (structural single-window false incidents), but
not solved.

## Phase 8d (operating points, drift, streaming; docs/phase8d/REPORT.md)

| Claim | Status | Evidence |
|---|---|---|
| The streaming clock bug changed the ToN_IoT evaluation windows | **refuted (post-hoc)** | identical record membership in all 5,820 windows, incl. 334 force-closed |
| Clock resync is safe against forged future timestamps | **refuted, then fixed** | 97% of genuine records dropped; probation limits loss to about 1,000 |
| A threshold policy is both within the false-alert budget and sensitive (development) | **not found** | only A + abstention is within budget: 4/10 attackers, 11/22 captures covered |
| LightGBM keeps the false-alert budget on benign development captures | **refuted** | max FPR 29% (local), 95% (source); device / hierarchical thresholds do not repair it |
| Window PR-AUC predicts attacker-level detection | **refuted (mechanism measured)** | window weighting, ranking-undetectable attackers (ToN: 26-36 of 40), threshold misplacement |
| Calibration validity decays with time since calibration | **exploratory, supported** | robust-z FPR 1.7% -> about 3% within 2-16 h; aged calibration up to 16% |
| Unlabelled drift alarms separate drift from attack | **refuted (exploratory)** | suspension removes 95% of false alerts and 93% of alerted attack windows |
| ToN_IoT labels follow the documented attacker-IP tagging | **contradicted in files 1-4** | 0 of 40 attack-labelled sources in 192.168.159.30-39 |
| X3/X4 intervals depend on the 4-block bootstrap | **direction robust (post-hoc)** | CIs exclude 0 at 60/15/5 min and iid |

## Phase 8e (evidence integrity, uncertainty, streaming security; docs/phase8e/REPORT.md)

| Claim | Status | Evidence |
|---|---|---|
| ToN_IoT attack labels identify attacking hosts | **refuted (retrospective, files 1-4)** | 3 initiators (192.168.1.30-32) are endpoints of 100% of attack flows; the other 37 labelled sources are responders; labels are flow-level, direction-agnostic and time-bounded |
| Frozen X policies detect the ToN_IoT initiators | **3/3 for every policy (retrospective)** | initiator window recall A 0.42, C2 0.43, E 0.56; frozen X verdicts unchanged |
| The Phase 8d probation resync survives adversarial timestamps | **refuted, then fixed** | before: up to 83% genuine loss, silent loss after a backward reset; quarantine state machine: 0 loss and 0 forged records in 10 scenarios; identical ToN_IoT windows |
| A per-population threshold policy meets FA/h budgets without degenerating (development) | **not found** | no policy passes the pre-declared rule; overruns are driven by shift (NF-UNSW local FPR 39% at 1%); never-alert rejected by the guard |
| Frozen 49-1 and ToN_IoT bootstrap intervals support inference | **reinterpreted as descriptive** | 4 blocks = 35 distinct resamples; verdicts unchanged (EVALUATION_METHODOLOGY.md) |

## Phase 8f (drift-aware calibration; docs/phase8f/REPORT.md; development data unless stated)

| Claim | Status | Evidence |
|---|---|---|
| Calibration shift inflates FPR through time-since-calibration drift | **not supported as the main mechanism** | 385/428 false alerts come from pooled-fallback sources; no within-capture age effect; the excess is concentrated in NF-UNSW (pooled 2.5% vs 0.35% without it) |
| A block-permutation feature-tail / composition test identifies periods where the calibration is invalid (pre-declared C1-C4) | **not adopted** | C1-C3 pass (null 0/16, 33x FPR separation); C4 fails (36% of benign-only segments valid); the full assessor also fails C3 (precedence); shadow-only diagnostic |
| The existing `baseline_state` drift rule separates reliable from unreliable periods | **supported (development)** | C2-C4 pass (valid-segment FPR 0.15%, 20.8x separation, 64% benign valid); C1 not measured |
| Periodic / drift-triggered recalibration makes detection more reliable | **refuted** | false alerts fall by learning attacks: window recall 0.27 -> 0.05 / 0.03; 95% / 20% of attack windows absorbed |
| A candidate-plus-gate refresh is safe | **refuted (absorption)** | behaves like the fixed baseline; still absorbs 5.8% of attack windows (a sustained sub-threshold attack) |
| Vetted refresh improves reliability without hiding attacks | **supported only with oracle vetting** | false alerts 3.81 -> 1.88/h, 9/10 attackers kept, recall 0.27 -> 0.29; not deployable without operator vetting |
| The stream clock resists in-skew forged timestamps | **refuted, then fixed** | 1 forged record dropped 82% of genuine traffic silently; median-of-101 clock: 0 loss, 244k records/s |

## Phase 8g (independent validation: CTU-13 scenarios 9 and 10; docs/phase8g/RESULTS.md)

Pre-registered in docs/phase8f/PREREG_CTU13.md (amendments A1, A2); frozen code 121acbf.
CTU-13 scenarios 9 and 10 are now **consumed**. Scenario 10 was opened by the frozen build but
declared failed under A2: 6,030 late records and 57 forced closes.

| Claim | Status | Evidence |
|---|---|---|
| V3: the deployed detector finds confirmed initiators at its operating point | **10/10 detected (scenario 9), descriptive** | Wilson [0.72, 1.00]; attack-window recall 0.21 [0.15, 0.27]; median delay 47.5 s; 0/803 verified-benign false alerts; 2,563 alerts/h on unlabelled background |
| V1: `baseline_state` is reliable on independent data | **not evaluable** | no monitoring segment (bots active throughout) |
| V2: the shift test earns adoption | **not evaluable** | no benign-only segments |
| V4: gated recalibration does not absorb attacks | **refuted** | S5 absorbed 71% of attack windows (1 activation) |
| CTU-13 flow labels mark attack traffic only after infection | **refuted (provenance audit)** | From-Botnet labels start at VM start, about 2 h before documented infection; IP-based |

**Post-hoc finalization** ([FINAL_REPORT.md](phase8g/FINAL_REPORT.md)). These rows are [R]
(consumed data) or [E] (synthetic or development data). None of them is confirmatory, and
none changes a verdict above.

| Claim | Status | Evidence |
|---|---|---|
| The frozen scenario 9 result survives the 1,039 silently dropped records | **confirmed [R]** | exact non-streaming reference: recall 0.209 → 0.211, unverified 2,563 → 2,755/h; V3 and V4 otherwise unchanged |
| Current streaming code equals the non-streaming reference on real data | **confirmed [R] (scenario 9; scenario 10 at 3,700 s)**, **refuted at scenario 10's A2 lateness (600 s)** | every record, window, feature, score and alert; at 600 s, 90 late records (counted) cost 10 alerts; 0 forced closes (was 57) |
| Scenario 10 becomes evaluable under A2 with the fixes | **refuted [R]** | A2 still fails (late 90). Exploratory at 3,700 s: 10/10, recall 0.573, 1.8 benign FA/h, 1,475 unverified/h |
| V4 root cause: a population-level gate is diluted by a few persistent attackers, and the refit grants them own profiles | **confirmed [R]** | attack 0.47% of candidate windows; even full detection could not exceed the 2× rate limit; 10/10 bots gain own profiles; per-entity test flags all 10 |
| The product update gate (`update_check`) would have caught it | **refuted [R]** | 4/241 global windows, p = 0.22, no outlier → no review |
| A per-entity review trigger adds no false reviews | **supported [E]** | 0/12 clean CTU-Normal periods, 8/12 scans (was 7/12); adopted as review-only |
| Entity quarantine or delayed activation makes data-driven refresh safe | **refuted [E]** | gradual-ramp attackers absorbed 67–100% (QC/QKC/QKCD at δ 1.5); only vetted-only refresh and refusal absorbed nothing |
| Incident grouping makes the CTU-13 background burden practical | **refuted [R]** | 6,887 → 5,655 incidents (−18%); 81% of sources alert once |

## Phase 8h (shift-robust window detection; development data; docs/phase8h/FINAL_RESEARCH_REPORT.md)

Pre-registered in docs/phase8h/PREREGISTRATION.md (amendments A1–A3). Every dataset was
inspected before, so the status is **exploratory** even where the decision rule was
pre-registered.

| Claim | Status | Evidence |
|---|---|---|
| H1a: per-network robust standardisation transfers attack ranking better than raw features | **refuted (exploratory)** | Δ recall at FPR 1% = −0.256 [−0.57, +0.04] over 7 domains, p 0.875; collapses on DDoS-LOIC and Bot |
| H1b: domain-invariance feature screening transfers better | **refuted (exploratory)** | Δ −0.081 [−0.42, +0.16]; harmful on DDoS-HOIC (−0.999); the registered strict screening changed the kept set in 5 of 10 folds compared with the as-run variant |
| H2: block-bootstrap thresholds exceed twice the 1% target less often than split-conformal | **refuted (exploratory)** | 8/27 units vs 8/27. T0 is the hold-out maximum for n ≤ 198 (17 of 27 units, all 8 overruns), so the bound cannot exceed it there |
| H3: conservative score fusion beats the better single score | **refuted (exploratory)** | Δ −0.093 [−0.23, 0.00]; median FPR 1.54% |
| Raw-feature LightGBM ranks new attack days within one network | **supported (exploratory)** | oracle recall ≈ 1.0 at 1% FPR on 5 of 5 NF-CIC held-out days (4 families, 29 attacking sources); realised FPR at the calibrated threshold 1.8–3.5% |
| It transfers across networks | **refuted (exploratory)** | NF-UNSW 0.03; benign windows identify the network at ROC-AUC 0.9999; without volume features NF-UNSW ROC-AUC rises from 0.39 to 0.93 but recall at 1% FPR does not |
| Cross-fitted thresholds exceed twice the target less often than split-conformal | **suggestive (exploratory, untested)** | 3/27 vs 8/27 units over 2% (exact one-sided McNemar p = 0.0625); worse than split-conformal at 15 minutes |

## Phase 8i (cross-network adaptation, abstention, representations; docs/phase8i/FINAL_REPORT.md)

- **Pre-registration:** docs/phase8i/PREREGISTRATION.md (amendments A1–A4, all made before the
  protected test). Frozen at `5db0c6f` (docs/phase8i/FREEZE.md).
- **Confirmatory [C]:** a single evaluation on NF-BoT-IoT-v3, never opened before the freeze.
- **Development [E]:** NF-CIC, NF-UNSW and NF-ToN-IoT, all inspected before.

| Claim | Status | Evidence |
|---|---|---|
| I1: 25 labelled target attack windows (A4 continued boosting) restore detection on an unseen network | **refuted (confirmatory, n = 1 network)** | N4: median recall 0.923 but FPR 9.8%; 2.5th percentile 0.745 ≤ zero-label recall 0.839 |
| I2: a score-shift statistic marks blocks whose false-alert rate overruns | **not evaluable (confirmatory)** | the deployed detector raised no alerts on N4, so no block overran. Development pooled block AUC 0.72 [0.54, 0.92] [E] is driven by between-domain differences: within NF-ToN-IoT 0.40; without it, the sample-size comparator is best (0.93) |
| I3: removing the top-2 network-identifying features improves cross-network recall | **refuted (confirmatory and development)** | N4: +0.02 recall at FPR 19.0% vs 11.7%; development mean change −0.065; network identity AUC unchanged (0.985 → 0.984) |
| The Phase 8i source setup improves zero-label transfer | **suggestive (exploratory, cause not isolated)** | NF-UNSW ROC-AUC 0.97 vs 0.39 in Phase 8h; the source set, cap, weighting and strict calibration all changed at once; shared institution not excluded |
| Benign-calibrated thresholds keep about 1% FPR on a new network | **refuted (confirmatory, descriptive)** | N4 A1 FPR 7.1–21.0%; development NF-ToN-IoT 14.5%, NF-UNSW 3.7%. Exploratory exception: non-selected A3 at Ka = 5 reached 1.3% median FPR on N4 (wide spread) |
| N4 false alerts reflect a network-wide rate | **refuted (post-hoc, 3 seeds)** | all A1 false alerts of all 3 seeds come from one label-benign host (seed 0: 130, 125 on the main flood day); the benign hold-out has 2.2 effective hosts and about 5 effective observations, and its host-grouped exceedance is 64% (final audit) |
| Calibration eligibility checks (effective n ≥ 199, effective hosts ≥ 10 with no host above 25%, host-grouped exceedance ≤ 2α, hold-out within 24 h) predict whether a 1% threshold holds | **hypothesis (post-hoc); registered as Phase 8j J2** | separates the 6 NF-CIC domains (FPR 1.0–1.6%) from NF-UNSW and NF-ToN-IoT on development data; designed after the N4 diagnostic, so N4 is not evidence. Phase 8j simulation [E]: no check is safe on its own (worst P(FPR > 2% given pass) 0.67–1.00); checks 1–3 together are safe but pass 17% of good calibrations; 199 lies on a bad stretch of the exact conformal risk |
| The Phase 8i evaluation-label host exclusion inflated its results | **refuted in these data (Phase 8j audit [E])** | P1 (past labels only) equals P0 in threshold, FPR and recall on all 9 domains, N4 included (all N4 evaluation attackers also attacked during calibration); score ties at T0 (up to 1.2% of hold-out scores; 58% on N4) make T0 insensitive to small changes |
| A destination memory that absorbs attackers' calibration traffic costs recall | **supported (Phase 8j audit [E])** | with all-flow windows whose memory keeps the calibration attackers' destinations (P1u), FPR is unchanged but recall falls on NF-CIC 03-02 (0.86 → 0.00), 02-22 (0.09 → 0.02) and NF-UNSW (0.97 → 0.62); N4 unchanged. Purging known calibration attackers from the memory (P1x, the registered protocol) restores the oracle recall on every domain (3 seeds), so the Phase 8i recall was not overstated |
| Phase 8j development: an abstaining method keeps the budget with ≥ 50% coverage on ≥ 2 of 4 development units (registered go/no-go) | **no-go (development [E])** | M1 and M4 meet (a) and (b) on NF-CIC only; M2 (learned reliability) is degenerate (all-or-nothing abstention). Network-level abstention by M1 was right on 4/4 networks, but its checks were designed on these networks, and criterion (b) cannot be met on units whose calibration is inadequate. No fresh data spent |
| Source-aware (host-balanced) calibration reduces false alerts on networks dominated by few hosts | **refuted (Phase 8k development [E])** | equal host weights raise FPR on every NF-CIC day (to 2.0–2.8%) and on NF-ToN-IoT (33.7%); only NF-UNSW improves (3.7% → 2.3%) at a recall cost (0.97 → 0.42). The operational FPR is window-weighted, so host balancing targets the wrong quantity |
| An adequately powered network-level confirmation of calibration-reliability decisions is possible with public data | **refuted at design stage (Phase 8l): NO-GO** | power analysis: at least about 15–30 independent networks with ≥ 1,000 effective verified-benign windows each are needed, even for a good rule (a lower bound); public data offers 0–1 strictly eligible network (DEDALE, pending verification), possibly 2. AIT labels are flow-level with ambiguous attack entities; UWF's benign traffic is pooled and heavily reduced |
| Within-calibration host turnover foreshadows post-calibration turnover failures | **hypothesis (post-hoc, n = 1) [E]** | 0.79 on NF-ToN-IoT vs 0.15–0.19 on NF-CIC; N4's host drift was not foreshadowed |
| On DEDALE (one emulated enterprise, green_internal tap), a 1% conformal threshold calibrated on the two benign weeks holds its budget over the next two weeks (registered HOLDS: point verified-benign FPR ≤ 2% and 95% upper bound ≤ 3%) | **open: draft pre-registration (Phase 8l), not frozen; frozen (ff4da57); Stage A gate and N8 PASS; evaluation not yet downloaded** | feasibility desk audit: about 55 VMs, 30 internal clients, 26 primary candidates (active hosts unverified; one generator), CC BY 4.0, 0.78 GB minimum download; N = 1, cannot revise the network-level NO-GO (docs/phase8l/DEDALE_PREREGISTRATION.md) |
| Phase 8k K1: fixed calibration checks (M1) separate adequate from unsafe fresh networks | **not evaluable (Phase 8k closed)** | the registered feasibility gate dropped F2 (its probe calibration holds no benign traffic); F1's probe has 7.0 effective hosts (below M1's 10), and its attacker machine emits only benign-labelled flows; the user stopped before any confirmation data, so F1's 7 networks remain untouched |
| Calibration-only statistics predict whether a network's calibration will hold its false-alert budget | **partly supported, development only [E]; registered as Phase 8k K1** | small calibrations are caught (NF-UNSW, N4); population turnover (NF-ToN-IoT: 61% of false alerts from unseen hosts) and dominant-host change (N4) happen after calibration and are invisible to PAC and temporal-consistency rules; the fixed checks (M1) separate all 4 networks but were designed on them |
| A PAC conformal rank at the dependence-adjusted effective n (M3) keeps the budget when it does not abstain | **suggestive, simulation only [E]; registered as Phase 8j J3** | see docs/phase8j/CALIBRATION_RELIABILITY_METHODOLOGY.md section 3 for the pooled violation rate with its 95% bound; it abstains whenever hosts are few or strongly heterogeneous |
| Late records degrade telemetry health | **implemented, tested** | `late_records` flag on the first late record; CTU-13 scenario 10 lost 10 alerts to 0.0008% late records |

