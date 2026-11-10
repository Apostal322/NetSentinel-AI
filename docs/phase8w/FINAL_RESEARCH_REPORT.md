# Phase 8w final report: network-relative representations

**Question.** Can a causally estimated, network-relative representation keep useful behavioural
deviations while making attack scoring less dependent on absolute, network-specific feature
scales and directions?

**Answer on development data:**
- **No.** Neither the signed nor the unsigned network-relative representation passed the
  registered two-seed screening against a matched null control. The campaign stopped at 24 of 48
  approved fits. Model development is a NO-GO.
- **The unsigned deviation changes one network a lot and pays for it elsewhere.** NF-UNSW's
  partial AUC rose from 0.008 to 0.53 in both seeds; NF-BoT fell from 0.58 to 0.09; NF-CIC lost
  0.12; NF-ToN stayed at zero. The macro mean did not improve (−0.02).
- **The signed deviation, Phase 8h's method, failed again** under the audited labels, the exact
  metric, a null control and two seeds (macro −0.08).
- **The strongest explanation supported by the evidence:** a deviation is not a common unit
  across networks. Its size depends on how spread out and how contaminated the reference
  population is, and a benign reference cannot be identified from unlabelled history on two of
  the four networks.

## Decisions

| gate | verdict | basis |
|---|---|---|
| G0 research and baseline correctness | **PASS** | the `R0` refit equals the saved frozen member exactly in 8 of 8 fits; references are causal for `Z0`–`Z3` (reviewer-verified); 19 unit tests; two wrong statements about `T` were corrected (amendment W-2) |
| G1 signed relative representation (H1) | **NOT SUPPORTED** | no arm meets the ranking criteria under `Z1` or `Z3`: `S` macro −0.08, `A` macro −0.02 |
| G2 context-conditioned representation (H2) | **NOT EVALUABLE** | registered before the fits: no context arm fitted. No-fit view: own-host references erase the volume signal on NF-UNSW and NF-ToN |
| G3 contamination robustness (H3) | **NOT SUPPORTED** | no arm passed screening; 30 % injected contamination removes the NF-UNSW gain; the reference draw changes the result more than the seed |
| G4 cross-network low-FPR improvement (H4) | **NOT SUPPORTED** | macro criterion and four of five guardrails fail for `A`; NF-BoT recall −0.49 |
| model development | **DEVELOPMENT NO-GO** | no arm selected; no replication |
| independent confirmation | **NOT READY** | no unused eligible network |
| deployment | **NO-GO** | — |

## A. Repository

- **Start:** `c026569` (= `origin/main`; CI run 42799447478 success), clean tree.
- **Commits (local, `main`):**
  - `914e76f`: registration, before any fit;
  - `608b76b`: fit ledger after the 24 screening fits;
  - `b966013`: registered screening evaluation;
  - `479a360`: no-refit analyses;
  - review corrections, write-ups and closure follow.
- **Push:** not pushed (needs authorisation). CI has not run on these commits.
- **Unchanged:** `src/`, the deployed detector and its defaults, the frozen M2, every Phase 8h–8v
  artifact. No dependency added.
- **Tests:** see § F.

## B. Historical-method audit (HISTORICAL_NORMALIZATION_AUDIT.md)

- **Earlier attempts:** Phase 8h `B-loc` (LightGBM on signed median/MAD z-scores per network),
  `B-lr` (logistic on the same), the unsupervised per-host |z| rule, Phase 8u service-relative
  columns, Phase 8v invariant-direction selection.
- **Why `B-loc` failed:** a signed z-score fixes scale and keeps direction, and direction is what
  conflicts between networks. Its target reference also needed labels.
- **What is different here:** an unsigned deviation in a supervised model; a matched 12-column
  null control; two paired seeds; a deployable (unlabelled) target reference; the audited labels
  and the exact partial AUC.
- **Unresolved assumptions:** that a network has one "normal" (false on NF-ToN); that history is
  mostly benign (false on NF-BoT); that deviations of equal size mean the same thing on
  different networks (contradicted, § E).

## C. Reference estimators (REFERENCE_ESTIMATION.md, IDENTIFIABILITY.md)

| item | value |
|---|---|
| formula | location = median; scale = max(1.4826 · MAD, floor); floor 0.15 for the five fraction features, 0.25 otherwise; z clipped to ±10 |
| source domains | their label-benign calibration windows (training labels) |
| target, `Z1` (deployable) | every unlabelled calibration window before the hold-out cut: 2,307 (NF-BoT) to 97,818 windows |
| target, diagnostic | `Z0` median of source references; `Z2` 800 simulated-review windows; `Z3` label-benign windows before the cut; `T` Phase 8h's reference (covers the hold-out and uses evaluation labels for host cleaning) |
| contamination of the `Z1` period (labels, diagnostic) | attack windows 0.2–1.1 % (NF-CIC), 5.3 % (NF-UNSW), 13.6 % (NF-ToN), 62 % (NF-BoT) |
| fallbacks | none: fewer than 200 windows is `insufficient_history` and is never substituted |
| effective sample size | reference windows come from few hosts on the small networks (NF-BoT: 8 benign hosts); no host-level effective size was computed |

**Identifiability.** The median of an unlabelled period is the centre of the observed mixture.
It equals the benign reference on NF-CIC and NF-UNSW (shift ≤ 0.09 scale units). It does not on
NF-ToN, where benign traffic is bimodal and 13.6 % attack windows move one reference by 17 scale
units, or on NF-BoT, where the history is mostly attack.

## D. Machine learning (MODEL_COMPARISON.md)

| item | value |
|---|---|
| representations | `R0` raw (null control), `S` signed z, `A` unsigned \|z\|; 12 columns each |
| fits | **24 registered** (3 arms × 4 leave-one-network-out folds × seeds 1060, 1061) + 3 small diagnostic network classifiers |
| hyper-parameters | frozen M2 member: LightGBM, 200 trees, 15 leaves, learning rate 0.05, subsample and colsample 0.8; network- and class-balanced weights; 50k cap per source domain |
| training rows | 80,085 (NF-CIC fold) to 580,618; checked row for row against the frozen recipe |
| model hashes | SHA-256 per fit in `reports/phase8w/fit_ledger.json` and the manifests; all 24 verified by the reviewer |
| fit time | 219 s in total |
| peak memory | 1.2 GiB resident; 1.55 GiB for the process tree (cap 3.4 GiB) |
| not fitted | positive/negative split (same tree hypothesis class as `S`); absolute + relative (24 columns; needs its own null control); context-conditioned |

## E. Cross-network results (unlabelled target reference `Z1`; mean of two seeds)

NF-CIC / NF-UNSW / NF-ToN / NF-BoT.

| metric | `R0` raw | `S` signed | `A` unsigned |
|---|---|---|---|
| exact partial AUC, FPR ≤ 1 % | 0.388 / 0.008 / 0.006 / 0.580 | 0.296 / 0.049 / 0.001 / 0.313 | 0.269 / 0.532 / 0.000 / 0.088 |
| macro partial AUC | 0.245 | 0.164 | 0.222 |
| recall at the retrospective 1 % FPR | 0.435 / 0.020 / 0.015 / 0.580 | 0.341 / 0.085 / 0.001 / 0.314 | 0.416 / 0.657 / 0.000 / 0.089 |
| realised FPR as calibrated (label-assisted threshold) | 1.3 / 3.7 / 15.1 / 12.8 % | 1.8 / 2.3 / 13.3 / 28.1 % | 2.1 / 0.0 / 23.7 / 46.0 % |
| recall as calibrated | 0.435 / 0.609 / 0.533 / 0.938 | 0.462 / 0.113 / 0.130 / 0.376 | 0.642 / 0.106 / 0.355 / 0.288 |
| benign false alerts per hour as calibrated | 318 / 50 / 16 / 0.2 | 448 / 32 / 14 / 0.4 | 524 / 0.3 / 24 / 0.7 |
| median detection delay as calibrated (min) | 15.6 / 0.9 / 5.5 / 0.0 | 1.0 / 1.0 / 17.9 / 0.2 | 0.9 / 3.5 / 1.0 / 0.2 |
| entities missed of 48, as calibrated (per seed) | 8, 8 | 10, 19 | 9, 9 |
| entities missed at the retrospective 1 % FPR (per seed) | 14, 13 | 30, 34 | 32, 28 |
| worst network (partial AUC) | NF-ToN 0.006 | NF-ToN 0.001 | NF-ToN 0.000 |

- **No arm reaches 1 % realised FPR** on NF-ToN or NF-BoT, as in Phases 8s–8v.
- **The NF-UNSW ranking gain does not reach the operating point:** as calibrated, `A` detects
  0.11 of its attack windows against 0.61 for `R0`; with a label-free threshold both detect
  about 0.05.
- **Other scenarios (diagnostic, never pooled):** with an oracle-clean reference `A`'s macro mean
  is 0.220, still below `R0`; zero-shot it gains nothing on NF-UNSW (0.003).

**Mechanism (exploratory).** Median |z| of attack windows on the volume features: 3.8 (NF-CIC),
3.5 (NF-UNSW), 1.35 (NF-ToN), against a benign median of 0.4–0.7. NF-ToN's reference scale is
four times wider because its history is bimodal, so its attacks sit inside what the model
learned as benign. On NF-BoT 97 % of benign windows hit the ±10 clip.

## F. Scientific validity

**Null control.** `R0` through the new driver equals the saved member bit for bit (8 of 8).
The pipeline effect is zero.

**Paired seeds.** `A` − `R0`: hard networks +0.238, +0.280; macro −0.047, +0.000. Two seeds fix
the sign per network (NF-UNSW up, NF-BoT and NF-CIC down, NF-ToN at zero in both). They do not
resolve the macro effect: the five saved members' macro SD is 0.0145 (amendment W-1).

**Contamination sensitivity (CONTAMINATION_ROBUSTNESS.md).**
- 20 % injected contamination halves the NF-UNSW gain and 30 % removes it; at ≥ 45 % nothing is
  left on any network.
- Below 20 % the stress cannot be told apart from reference-estimation noise: five clean draws
  of 800 reference windows miss 9 to 28 entities and move NF-UNSW between 0.27 and 0.57.

**Leakage.** None into the deployable references or the training rows (reviewer-verified). `T`
is not causal and is labelled so.

**Domain shortcut.** A classifier names the network of a benign window with 97.7 % accuracy on
raw features, 100 % on signed z and 99.96 % on unsigned |z|. Normalising per network did not
make networks look alike.

**Metric fragility (found by the review).** On NF-BoT and NF-ToN one benign host each decides
the partial AUC: without it, `R0` on NF-BoT is 0.94 instead of 0.67 / 0.49. Macro differences
are therefore largely single-host effects. The ordering of the arms does not change.

**Independent review (INDEPENDENT_REVIEW.md).** Every registered number, hash and decision
reproduced. Nine medium findings changed the interpretation, not the verdicts. The main ones:
the `T` reference is not causal; the "deployable" block uses a label-assisted threshold; the
low-contamination claim was withdrawn; the NF-UNSW gain is "consistent with", not "confirming".

**Amendments.** W-1 to W-5 (PREREGISTRATION § 8): corrections of text and added checks, made
with outcomes visible. No rule changed.

**Limits.** 4 networks from 2 institutions, 9 domains, 48 entities, 2 seeds. The unsigned arm was
designed after a no-fit look at these networks' evaluation labels. Other sessions' jobs ran on
the machine during the fits; this affects timing only.

**Validation.** TESTS_PLACEHOLDER

## G. Three most important unresolved problems

1. **A deviation is not a common unit.** The same |z| means different things on a unimodal, a
   bimodal and a contaminated network. Another transformation of the same 12 features is not
   recommended without a falsifiable mechanism that addresses this, for example a reference
   whose *shape* (not only centre and spread) is estimated, with the reference draw treated as a
   replication unit.
2. **The benign reference is not identifiable from unlabelled history** on NF-ToN and NF-BoT.
   Any target-adaptive method needs outside information there, and a few hundred reviewed
   windows were too noisy for this representation.
3. **The benchmark's low-FPR metric rests on single hosts** on two of four networks, and there is
   still no independent network. Before another model phase, the evaluation needs a host-robust
   statistic (leave-one-benign-host-out) and a decision on pseudo-hosts such as `0.0.0.0`.

**Phase 8x is not started.**

## Portfolio summary (verified claims only)

**ML Research Engineer:**
- "Audited a previously failed normalisation method down to its code and showed that the new
  candidate differed from it only in discarding the sign.
- Built a matched null control (identical rows, weights, seeds and column count) that reproduced
  a frozen model bit for bit, so that every reported effect is a representation effect.
- Showed with labels as a diagnostic that a benign reference is not identifiable from unlabelled
  history on two of four networks.
- Pre-registered effect sizes and guardrails; the candidate failed them; stopped at half the
  approved budget and reported the negative result, including an independent review that
  withdrew one of my own claims."

**Do not claim:** improved detection; that relative features transfer; a validated model;
robustness to contaminated baselines; generalisation; production readiness.
