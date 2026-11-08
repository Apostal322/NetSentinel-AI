# Phase 8r gap register

Written 2026-11-08 (Stage 0).

**Starting point:**
- `main` = `origin/main` = `84a3d0e`, with a clean tree and no tags;
- 38 GB of disk free and about 0.6–1.0 GB of RAM free (another project's mypy run was active);
- CI is not verifiable (`gh` is not installed).

**Artifacts reused (unchanged):**
- the Phase 8o F0 per-member scores (6 fits, base and stress × r6–8; `s_hold`, `s_ev`, `s_hold_u`,
  `s_ev_u`);
- the Phase 8i calibration frames and `cal_truth`, and the Phase 8j P1x frames;
- the Phase 8q label audit (`label-audit-1.0.0`) and its estimators;
- the Phase 8m evaluation contacts.

**Missing:** the Phase 8o F0 boosters were never saved, so any change to the target feature state
(a new memory) needs refits of the frozen M2 construction.

| ID | gap | evidence | severity | significance | assumptions | competing explanations | investigation | required data | compute | acceptance criteria | status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R0.1 | **No model of what trusted evidence a deployment could have** | Phase 8q: calibration needs the oracle attacker identities | high | without it, "label-free" vs "oracle" is a false dichotomy | — | — | trust categories T0–T4 and an information boundary (CALIBRATION_IDENTIFIABILITY § 1–2) | none | none | every input of every method is assigned a category and an availability time | **done** (Stage 1) |
| R0.2 | **Is the benign tail identifiable from unlabelled calibration data?** | Phase 8q F: four label-free estimators failed | high | decides whether any label-free method *can* work | mixture of benign and arbitrary attack windows | the estimators were weak, not the problem impossible | partial-identification bounds (Horowitz–Manski) on saved scores | saved scores | under 1 min | identified sets reported per domain at the true ε and at assumed bounds ε̄ | **done**: NOT IDENTIFIABLE without a bound or trusted data (§ 3) |
| R0.3 | **Distribution-free FPR control needs enough exchangeable benign hosts** | NF-UNSW has 17 benign hold-out hosts, NF-BoT 7 (2.2 effective) | high | window-level conformal guarantees ignore within-host dependence | host = exchangeable unit | window exchangeability is enough | host counts vs ⌈1/α⌉ − 1 = 99 | saved frames | seconds | per-domain feasibility stated | **done**: infeasible on NF-UNSW and NF-BoT |
| R0.4 | **Memory contamination is a feature-state problem, which no threshold fixes** | with the unlabelled memory, even the oracle threshold gives 02-22 recall 0.003–0.016 and 03-02 0.0004 | high | trusted thresholds cannot recover NF-CIC 02-22 and 03-02 | — | — | Experiment C (memory policies) | raw calibration flows, Phase 8m contacts | feature level about 5 min; scored part needs refits | registered gate (PREREGISTRATION § 6) | **gate failed**: no variant restores 02-22 / 03-02 novelty without +67–84 pt benign novelty (MEMORY_CONTAMINATION) |
| R0.5 | **Can a small, realistic trusted-benign sample replace the oracle threshold?** | — | high | the primary research question | representativeness of the vetted hosts | vetting simply recovers the oracle | Experiment A | saved scores | about 10 min | H-A1 (PREREGISTRATION § 4) | **NOT SUPPORTED**: +0.337 recall, but NF-ToN FPR 68.9 % and NF-BoT 25.7 %; host-sampled vetting is not window-representative (TRUSTED_CALIBRATION) |
| R0.6 | **How much contamination of the trusted set can each estimator tolerate?** | Phase 8q G: bounded (≤ 10 %) robustness of label-free estimators | medium | annotation errors are realistic | injected windows are real attacker windows | — | Experiment B (6 mechanisms × 4 fractions) | saved scores | about 10 min | H-B1 (PREREGISTRATION § 5) | **NOT SUPPORTED**: A3 breaks at 5 % under 5 of 6 mechanisms; A2/A4 at 2 % (CONTAMINATION_ROBUSTNESS) |
| R0.7 | **Vetting is simulated from dataset labels** | no verified-benign data exist (Q0.4) | medium | T3 is approximated by T1; real vetting may differ | dataset labels ≈ vetting outcome | dataset labels are noisy (Phase 8q audit) | labelled ORACLE-SIMULATED everywhere; annotation-error cells | — | — | never reported as real vetting | **documented limit** |
| R0.8 | **Weakly supervised training (Experiment D)** | — | low | trusted positives (T4) from a realistic budget are a handful of hosts | — | — | justification check | — | — | run only if the registered condition holds (PREREGISTRATION § 7) | **NOT RUN** (condition false) |
| R0.9 | **No independent confirmation data** | Phase 8o INDEPENDENT_DATA; DEDALE consumed | high | every result is development evidence | — | — | — | a new, unconsumed network with host-level ground truth | — | — | **NOT READY** (carried) |
| R0.10 | **The Phase 8o boosters were not saved** | listing of `data/derived` | medium | a memory change cannot be scored without refits | refits reproduce the saved scores (Phase 8o R1) | — | the scored Experiment C saves its boosters | — | about 15–20 min per regime set | reproduction check before any scoring | **not needed**: the scored part did not pass its gate |
