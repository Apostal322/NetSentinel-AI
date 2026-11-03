# Phase 8o Experiment D: feature-semantics arms and domain robustness (H1, H1b, F2, H5)

**Status:** REGISTERED DEVELOPMENT, on consumed development networks. Nothing here is an
independent confirmation.

**Source:** `reports/phase8o/experiment_d.json` (scripts/phase8o/analyze_d.py).

**Fits:**
- the M2 construction, K = 5 members, fresh replicates r = 6–8;
- base and stress regimes, giving 6 fits per arm; F2 and F5 run in the base regime only (3 fits);
- T0 at α = 1 %, P1x calibration.

**Run:** 89 min, peak 1.95 GiB under the 3.4 GiB cap.

**Reproduction:** R1 (M2 r0) and R2 (B0 r0) reproduced the Phase 8n scores exactly on all 9
targets (max |Δ| = 0.0). R3 (no-op rebuild) was bit-exact on all 14 domains.

## 1. Results by arm (K = 5)

| arm | fits | NF-CIC recall / FA | NF-UNSW | NF-ToN | NF-BoT | macro recall | R₂₀ / U₂₀ | U₁ | collapses |
|---|---|---|---|---|---|---|---|---|---|
| **F0** historical | 6 | 0.680 / 1,216 | 0.835 / 436 | 0.659 / 1,225 | 0.873 / 49 | 0.762 | 40 / 5 | 9 | 0 |
| **F1** aligned memory | 6 | 0.670 / 1,251 | 0.836 / 424 | 0.642 / 1,192 | 0.873 / 50 | 0.755 | 40 / 5 | 11 | 0 |
| F4 x² control | 6 | **identical to F0** (max \|Δ score\| = 0) | | | | 0.762 | 40 / 5 | 9 | 0 |
| F0, base fits only | 3 | 0.683 / 1,191 | 0.976 / 461 | 0.604 / 1,127 | 0.870 / 48 | 0.783 | 42 / 3 | 0 | 0 |
| **F5** cold-start sources dropped | 3 | 0.683 / 1,191 | 0.985 / 443 | **0.400** / 861 | 0.865 / 47 | 0.733 | 40 / 2 | 0 | 0 |
| **F2** expanding replay | 3 | **0.004** / 1,174 | 0.781 / 478 | **0.122** / 0 | **0.433** / 14 | 0.335 | 9 / 0 | 6 | **12** |

FA = mean false alerts per domain and fit. R/U = entities detected in all / some of the arm's
fits, at ≥ 20 % of their windows (subscript ₂₀) or at ≥ 1 window (₁). The full measures (FPR, AUC,
ranking recall, per-domain ranges) are in the JSON.

## 2. Registered decisions

**H1, training–inference alignment (F1 vs F0): NOT SUPPORTED.**
- Every guardrail holds, but neither path does:
  - macro recall changes by −0.006 (path R needs ≥ +0.02);
  - no network's false alerts fall by ≥ 20 % (path F).
- NF-ToN recall −0.017, and U₁ 9 → 11.
- **What is permitted: a partial alignment of under 1 % of training rows had no *detectable*
  effect.** It is not shown that alignment "does not matter".
  - F1 leaves the main confound in place: pre-q benign rows stay expanding, and every attack row
    stays frozen.
  - **Paired per-fit F1 − F0 macro differences** (exploratory, post-review): −0.0005, −0.0091,
    −0.0239, −0.0032, −0.0096, +0.0079. SD 0.011; naive 95 % interval about [−0.018, +0.005].
  - The 6 fits are not independent (base and stress share member seeds), and F0's per-fit macro
    recall itself ranges 0.62–0.83. Path R's 0.02 lies within fit-to-fit noise.

**H1b, cold-start exclusion (F5 vs F0, base fits): NOT SUPPORTED.**
- NF-ToN recall falls by 0.204 (guardrail −0.05), although its false alerts fall by 24 %.
- NF-UNSW +0.009.
- **NF-CIC is identical by construction** (max |Δ| = 0): its sources (NF-UNSW + NF-ToN) contain no
  NF-CIC day. H1b therefore effectively covers 3 networks.
- **F5 is not a pure exclusion.** Dropping two days also re-splits NF-CIC's network weight over 9
  domains instead of 11.
- **The Stage A reading of G0.2 as a harmful "construction artifact" is not supported.** Removing
  those days *lowered* NF-ToN recall. The cold-start rows are a semantic oddity whose effect on
  detection is mixed, not shown to be harmful.

**The F4 control is degenerate, a pre-registration design error.**
- Squaring `new_dst_frac` left every LightGBM split, and so every score, unchanged:
  LightGBM bins a feature by its sorted distinct values, so a strictly increasing transform of
  values in [0, 1] gives the same partition. Phase 8n's sqrt arm differed by at most 0.0015.
- So the registered noise floor (δ = 0, ε = 0) does **not** measure refit noise. The rule fell
  back to its fixed minima (+0.02 recall; −20 % false alerts).
- **Neither verdict depends on this.** F1's change is negative, and F5 fails a guardrail.
- The pre-registered expectation "F1 within the F4 noise floor" cannot be called confirmed: that
  floor was zero by construction.
- A meaningful control would perturb the refit itself, for example by fresh subsample seeds.
  Phase 8n's no-op refits moved NF-CIC recall by up to 0.09.

## 3. What F2 shows (dose contrast; descriptive)

**What changed:** training on evaluation rows whose novelty uses an *expanding* memory, while
the targets are still scored with the deployed *frozen* memory.

**What happened:** operational detection collapses on three networks.
- NF-CIC 0.004, NF-ToN 0.122, NF-BoT 0.433;
- 12 collapses on strong domains.

**Ranking and threshold behave differently by network:**

| network | AUC F0 → F2 | ranking recall at the benign q99 (oracle diagnostic) | reading |
|---|---|---|---|
| NF-CIC | 0.78 → **0.48** | 0.68 → 0.004 | a real ranking collapse |
| NF-ToN | 0.86 → **0.94** | 0.06 → **0.31** | ranking *improves*; recall collapses at T0 (FPR 0 %, 0 false alerts): a threshold effect |
| NF-BoT | 0.90 → 0.69 | 0.45 → 0.42 | — |

**Reading (interpretation):**
- In the expanding replay, attack windows are almost never novel (NF-UNSW attack mean
  0.90 → 0.001; FEATURE_SEMANTICS.md § 5). The F2 model learns no novelty-attack association.
- **What F2 establishes is that F0's NF-CIC detection rests on the frozen-novelty attack
  association,** i.e. on the label confound of G0.1. Without it, NF-CIC ranking falls to chance.
  This is a shortcut dependence, not a demonstration that F0's semantics are right.
- **F2 is not the aligned counterpart of F0.** It trains on expanding semantics and scores on
  frozen ones.
- **Whether "train and score on the same semantics" is what matters is not tested.** That would
  need an arm that trains *and* scores with an expanding memory (Phase 8m's B1u is the closest,
  with different columns).
- **On NF-ToN,** removing the frozen-novelty association improves ranking, consistent with Phase
  8m's finding that NF-ToN's frozen novelty mostly marks stale benign traffic. The T0 hold-out
  then sits above most attack scores.

## 4. Domain robustness (H5; F0, K = 5, 6 fits)

| domain | family | recall mean (min–max) | FPR |
|---|---|---|---|
| NF-CIC 02-14 | SSH brute force | 1.000 (1.000–1.000) | 1.1 % |
| NF-CIC 02-16 | DoS Hulk | 0.963 (0.963–0.963) | 1.2 % |
| NF-CIC 02-20 | DDoS LOIC-HTTP | **0.064** (0.019–0.085) | 1.2 % |
| NF-CIC 02-21 | DDoS HOIC | 0.994 (0.980–0.998) | 1.4 % |
| NF-CIC 02-22 | web brute force / XSS / SQL injection | **0.081** (0.058–0.095) | 1.1 % |
| NF-CIC 03-02 | bot | 0.978 (0.890–0.999) | 1.1 % |
| NF-UNSW | 9 families | 0.835 (**0.276**–0.989) | 3.7 % |
| NF-ToN | password, XSS, backdoor, ransomware, MITM | 0.659 (0.575–0.739) | **16.5 %** |
| NF-BoT | DoS, DDoS, theft | 0.873 (0.852–0.891) | **8.0 %** |

**Network-level summary:**
- macro recall 0.762; worst network NF-ToN at 0.659;
- median detection delay (first alerted window − first attack window): NF-CIC 15 s, NF-UNSW 5 s,
  NF-ToN 40 s, NF-BoT 0 s;
- false alerts per hour of evaluation: NF-CIC 295, NF-UNSW 49, NF-ToN 17, NF-BoT 0.1.

**FPR meets α on NF-CIC only.** On NF-ToN and NF-BoT it is 8–16 times α.

**NF-UNSW's 0.28 minimum is a stress fit.** The base fits average 0.976, and that domain's stress
fits are its main source of variability.

**Correlated units:**
- the six NF-CIC days are one network, not six institutions;
- 52 of the 75 entities are on NF-CIC;
- results are counts over correlated fits, without intervals.

**Comparison with Phase 8n's M2 replication** (reps 3–5, other seeds):
- NF-CIC 0.656 vs 0.680 here; NF-UNSW 0.919 vs 0.835; NF-ToN 0.593 vs 0.659; NF-BoT 0.869 vs
  0.873.
- Fresh randomness moves network recall by up to ±0.08. That is the scale of refit noise any
  future comparison has to clear.
