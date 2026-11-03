# Phase 8o H4: calibration and false-alert control

**Status:**
- C1 is REGISTERED DEVELOPMENT; C2 and C3 are registered and descriptive; C4 is EXPLORATORY
  (its threshold was chosen with the audit's novelty rates in view).

**Fits:** F0, K = 5, 6 fits.

**Sources:**
- `reports/phase8o/experiment_d.json` (`H4`);
- the false-alert decomposition of the Phase 8n fits in `reports/phase8o/semantics_audit.json`.

**What no figure here is:** a distribution-free FPR guarantee under domain shift. T0's conformal
guarantee holds only for exchangeable hold-out and evaluation windows, and they are not.

## 1. Why FPR exceeds α: no single mechanism (Stage A, EXPLORATORY)

| network | FPR at T0 | supported dominant causes | evidence |
|---|---|---|---|
| NF-CIC | 1.2 % | none material; mild rise with memory age | FPR by evaluation quarter 1.0 → 1.6 %; novel windows alert at 8–14 % vs 0.9 % |
| NF-UNSW | 3.7 % | **too little independent calibration evidence**; host-population shift | hold-out 443 windows in 17 host-hour blocks, so T0 is the 4th-highest of 443 hold-out scores (k = ⌈444 × 0.99⌉ = 440); hold-out q99 0.06 vs evaluation benign q99 0.68–0.71; false alerts not novel (1 %) |
| NF-ToN | 16.5 % | **stale frozen memory plus host turnover** | 99 % of false alerts are novel windows; FPR 28–31 % on hosts first seen after the freeze vs 8–9 % on known hosts; 5 hosts carry 93 % of false alerts |
| NF-BoT | 8.0 % | **host concentration and too little evidence** | every false alert comes from 2 benign hosts; hold-out 80 host-hour blocks |

**Workload per active host-hour** (Phase 8n M2 fits): NF-CIC 0.07–0.09, NF-UNSW 2.0, NF-ToN 1.6,
NF-BoT 1.6.

**Not supported as dominant anywhere:**
- dataset-specific telemetry semantics, which are shared across networks (NetFlow v3);
- baseline contamination: P1x purges calibration attackers. Without that purge, see C3.

## 2. Methods compared (F0, K = 5)

| method | NF-CIC recall / FPR / FA | NF-UNSW | NF-ToN | NF-BoT | R₂₀ / U₂₀ |
|---|---|---|---|---|---|
| T0 (registered) | 0.680 / 1.17 % / 1,216 | 0.835 / 3.65 % / 436 | 0.659 / 16.4 % / 1,225 | 0.873 / 7.96 % / 49 | 40 / 5 |
| **C1** aligned hold-out | 0.673 / **0.99 %** / 1,035 | **0.518** / 2.49 % / 297 | 0.654 / 16.3 % / 1,211 | 0.873 / 7.96 % / 49 | 35 / 10 |
| C2 minimum evidence | as T0 | **unassessed** (17 blocks) | as T0 | **unassessed** (80 blocks) | 30 / 3 |
| C3 no calibration labels | 0.504 / 1.16 % / 1,214 | **0.054** / 1.80 % / 215 | **0.001** / 0.39 % / 29 | 0.810 / 9.6 % / 60 | 16 / 3 |
| C4 shift abstention (exploratory) | as T0 (100 % assessed) | 0.1 % assessed | 0.1 % assessed | 2.1 % assessed | 21 / 2 |

**Single members (K = 1) behave the same way:**
- T0: NF-CIC 0.515 / 1.16 %, NF-UNSW 0.542 / 3.08 %, NF-ToN 0.584 / 15.4 %, NF-BoT
  0.754 / 11.9 %.
- C1: NF-CIC 0.494 / 1.03 %, NF-UNSW 0.310 / 2.10 %, NF-ToN 0.570 / 14.7 %, NF-BoT unchanged.

## 3. Decisions and readings

**C1, the aligned hold-out: NOT SUPPORTED.**
- FPR moves toward α on NF-CIC, NF-UNSW and NF-ToN; NF-BoT is unchanged.
- NF-CIC recall is kept: −0.007, with false alerts −15 %.
- But R₂₀ falls by 5 (limit 2), because NF-UNSW recall drops from 0.835 to 0.518.
- **NF-UNSW's hold-out is too small to set a 1 % threshold.** Raising the novelty of a handful
  of its 443 windows moves T0 sharply. That is the evidence problem, not a semantic fix.
- **NF-ToN barely moves** (16.4 → 16.3 %), as predicted before results. Its staleness builds up
  over 72 h, far beyond the hold-out's age.
- **NF-CIC shows −15 % false alerts for −0.007 recall.** This is a post-hoc subgroup of a test
  that was NOT SUPPORTED: EXPLORATORY, one network.
- **Weaknesses of the C1 rule itself** (found in review; the rule is applied as registered):
  - "closer to α" has no margin: NF-ToN 16.45 % → 16.27 % counts;
  - the recall guardrail covers only networks with T0 FPR ≤ 2α (NF-CIC alone), so NF-UNSW's −0.32
    was caught only by R₂₀.
- **NF-BoT shows the same evidence problem.** T0 is the 7th-highest of 781 hold-out scores. C1
  changes ensemble hold-out scores by up to 0.38, yet leaves T0 identical.

**C2, minimum evidence (registered, descriptive).**
- It correctly marks NF-UNSW and NF-BoT as "calibration invalid: insufficient evidence". These are
  2 of 9 domains, 19,477 of 710,321 evaluation windows (2.7 %), including all their attack windows.
- That is honest but not useful: those networks then produce no alerts at all.
- It does **not** catch NF-ToN, whose hold-out has 3,706 blocks and still sits at 16 % FPR.
  Evidence size is necessary, not sufficient.

**C3, no calibration-period labels (deployment-realistic, registered, descriptive).**
- **This is the most consequential operational result of H4.** Without P1x's confirmed
  calibration-attacker labels, recall collapses: NF-UNSW 0.054, NF-ToN 0.001, NF-CIC 0.504.
- **There are two mechanisms, and their weight differs by network.** The decomposition below
  swaps one at a time (F0, K = 5, 6 fits; corrected after review; the first draft named only the
  threshold mechanism):

  | domain | T0 | unlabelled threshold only | unlabelled features only | both (C3) |
  |---|---|---|---|---|
  | NF-CIC 03-02 | 0.978 | 0.978 | **0.000** | 0.000 |
  | NF-CIC 02-14 | 1.000 | 1.000 | 0.990 | 0.990 |
  | NF-UNSW | 0.835 | 0.288 | 0.549 | 0.054 |
  | NF-ToN | 0.659 | **0.022** | 0.489 | 0.001 |

  - **Threshold:** calibration-period attackers stay in the hold-out and raise T0. This dominates
    on NF-ToN.
  - **Features:** their destinations enter the frozen memory, so their later traffic is no
    longer novel. This is entirely responsible on NF-CIC 03-02, where the same bots are active in
    calibration (interpretation of the mechanism; the numbers are measured).
- **So the detector as evaluated requires verified calibration-period labels for both the
  threshold and the destination memory,** i.e. human review or a trusted clean baseline, to
  operate.
- Every P1x result since Phase 8j carries this assumption (Phase 8n G0.5).

**C4, shift abstention (EXPLORATORY): fails the guardrails.**
- It abstains on 99.9 % of NF-UNSW and NF-ToN and 97.9 % of NF-BoT windows. Those include
  almost every attack window of those networks.
- On NF-UNSW the attack traffic itself raises the trailing novelty rate (99.9 % of its attack
  windows are novel): the shift gate is triggered by the attacks it should detect.
- A label-free novelty-rate gate therefore cannot tell benign drift from an attack campaign
  (Phase 8f made the same point about shift tests).

**Workload transfer.** Attack prevalence in evaluation windows is 25.5 % on NF-UNSW and 45.8 % on
NF-BoT. Precision and alert workloads from these networks will not transfer to real networks,
where attacks are rare.

## 4. What is established

- **Excess FPR has different causes on different networks:**
  - stale memory and host turnover (NF-ToN);
  - insufficient calibration evidence (NF-UNSW, NF-BoT);
  - host concentration (NF-BoT).
- **None of the four simple methods controls FPR without removing detection** on at least one
  network.
- **The detector's operation depends on confirmed calibration labels.**
- **What remains open** is a calibration that is valid under host turnover and memory ageing,
  with evidence requirements tied to independent host-hour blocks. It needs data with many more
  independent calibration units than these networks provide.
