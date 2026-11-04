# Phase 8q Experiment B: where the calibration-label dependency comes from

**Status:** EXPLORATORY decomposition from saved scores.
- Scores: Phase 8o F0 = Phase 8p S0, 6 fits, K = 5. No model is fitted.
- The oracle calibration-attacker identities are used only to build the counterfactual cells.

**Source:** `reports/phase8q/calibration_decomposition.json`
(`scripts/phase8q/calibration_decomposition.py`). Figure: `figures/decomposition.png`.

## 1. How P1x uses labels (traced in code)

| mechanism | where | effect |
|---|---|---|
| **threshold population** | `build_p1x.P1xBuilder.add`: calibration windows of calibration-period attacker hosts are dropped | T0 is computed without attacker windows |
| **shared feature state** | the same builder keeps attackers' destinations out of the memory (`self.seen`). That memory is (a) the expanding memory of the calibration windows, and (b) frozen at the midpoint for **every** evaluation window's `new_dst_frac` | attack windows to destinations the attackers contacted during calibration stay novel |

**Not used:**
- score normalisation (none);
- the training of the scoring model, which learns only from the other networks' labels.

## 2. Cells (documented-attacker recall / FPR; 6 fits)

| cell | threshold | evaluation scores | macro | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|---|---|---|
| **U** (no labels) | unlabelled hold-out | unlabelled memory | **0.372** | 0.503 / 1.16 % | 0.054 / 1.80 % | 0.001 / 0.39 % | 0.930 / 9.60 % |
| **T** (threshold-only exclusion) | unlabelled hold-out minus attacker windows | unlabelled memory | 0.656 | 0.503 / 1.17 % | 0.549 / 3.63 % | 0.640 / 16.0 % | 0.933 / 7.80 % |
| UE (memory-only exclusion at evaluation) | unlabelled hold-out | P1x memory | 0.518 | 0.807 / 1.16 % | 0.288 / 1.80 % | 0.034 / 0.54 % | 0.943 / 9.76 % |
| TE | unlabelled hold-out minus attacker windows | P1x memory | 0.869 | 0.807 | 0.835 | 0.884 | 0.950 |
| **P** (P1x, oracle) | P1x hold-out | P1x memory | **0.869** | 0.807 / 1.17 % | 0.835 / 3.65 % | 0.884 / 16.5 % | 0.950 / 7.96 % |

TE equals P on every network. The hold-out memory has **no** effect on the threshold.

## 3. Attribution of the 0.497 macro-recall loss

| path | threshold contamination | evaluation-memory contamination | hold-out memory |
|---|---|---|---|
| U → T → TE → P | 0.285 | 0.213 | 0.000 |
| U → UE → TE → P | 0.351 | 0.146 | 0.000 |

The two orders differ because the effects interact. Roughly two thirds of the loss is the
threshold and one third the memory. **Per network** (path 1):

| network | threshold | evaluation memory | reading |
|---|---|---|---|
| NF-CIC | 0.000 | 0.304 | the loss is entirely the memory (02-22 and 03-02) |
| NF-UNSW | 0.495 | 0.286 | both |
| NF-ToN | 0.639 | 0.244 | mostly the threshold |
| NF-BoT | 0.003 | 0.017 | almost none |

**Why:**
- **The threshold.** The unlabelled hold-out is **attack-dominated on NF-BoT and NF-ToN**, and
  29 % contaminated on NF-UNSW. Calibration
  attackers hold 92 % of NF-BoT's hold-out windows (8,886 of 9,667), 76 % of NF-ToN's (14,726 of
  19,298) and 29 % of NF-UNSW's (180 of 623). On NF-CIC they hold 0–10 %, and their windows
  rarely score above T0.
  - NF-ToN's T0 moves from 0.436 to 0.993, and NF-UNSW's from 0.036 to 0.460 (base r6).
- **The memory** (corrected after the independent review). The NF-CIC memory effect (0.304)
  comes **entirely from two days.**

  | domain | U | UE | P |
  |---|---|---|---|
  | 02-22 | 0.003 | 0.843 | 0.843 |
  | 03-02 | 0.000 | 0.978 | 0.978 |
  | 02-14 | 0.990 | 1.000 | 1.000 |
  | 02-16, 02-20, 02-21 | unchanged | | |

  - On 02-22 and 03-02 the calibration-period sources that P1x purges are the 316 labelled
    02-22 sources and the 8 calibration bots. Their destinations (24 and 9) enter the unlabelled
    memory, and the documented attack windows stop being novel.
  - **On 02-14 the memories differ by exactly one destination,** the victim 172.31.69.25. Its
    only calibration-period source was the FTP attacker 18.221.219.4. That flips the *novelty
    feature* of the SSH attack windows from 1.0 to 0, but **not detection**: recall 0.99 vs 1.00.
    The other features carry it.
- **Why the hold-out memory has no effect, and what that hides.**
  - The expanding calibration memory saturates: only 0.1–2 % of hold-out windows have
    `new_dst_frac` > 0, against 2–38 % of benign evaluation windows.
  - That calibration-to-evaluation shift, not any label use, is why even P runs at 16.5 % FPR on
    NF-ToN at α = 1 % (Phase 8o G0.3).

## 4. What is identified, and what is not

- **Identified, as a path-dependent attribution:**
  - the two mechanisms;
  - their sizes along both path orders (threshold 0.285 or 0.351; the 0.066 difference is the
    interaction);
  - the absence of a hold-out-memory effect;
  - the per-domain location of the memory effect.
- **Not identified:**
  - an interaction term beyond the difference between the two orders;
  - effects under a model trained differently.
- **Mixed semantics.** TE and UE combine a threshold from unlabelled-memory hold-out scores with
  P1x-memory evaluation scores. That combination *is* the counterfactual, and is stated.
- **Delayed labels (Phase 8p C2: 0.387)** fit this picture. Attackers active until near the
  calibration end stay in both the hold-out and the memory.
