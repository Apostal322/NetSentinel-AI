# Phase 8t deployable conditional calibration: registered comparison

**Status:** REGISTERED.
- Amendment A-1 registered the candidates before any deployable outcome (code `ebe8596`).
- Amendment A-2 fixed a matched-budget defect after the first run (`9bf9611`).
- Amendment A-3 fixed an inexact-saturation defect found by the independent review (`ec091fe`).
- **Final results:** `reports/phase8t/deployable_r3.json`.
- The earlier `deployable.json` and `deployable_r2.json` are kept; their D2 matched-budget values
  are artefacts.
- All scores are S_U (deployable memory).

**Calibration sources:**
- **CAL_T:** benign hold-out windows via calibration labels, the best case of trusted review
  (Phase 8s: reachable only at about 100 reviews under perfect review);
- **CAL_U:** the whole unlabelled hold-out.

## Decisions (CAL_T)

| hypothesis | verdict | basis |
|---|---|---|
| **H1** conditional calibration helps at a shared 1 % budget | **NOT SUPPORTED** | matched budget: D2 0.270 vs D0 0.275 (−0.005); R₂₀ +0. **Informative on NF-CIC only** (§ matched budget) |
| H2 pooling improves group reliability | **SUPPORTED** | group transfer error D2 < D1 on NF-CIC, NF-UNSW, NF-BoT (not NF-ToN) |
| H3 less concentration without detection loss | **NOT SUPPORTED** | holds on NF-ToN only |
| H4 temporal | **NOT SUPPORTED** | second-half macro gain +0.004; NF-ToN FPR 5.2 % vs D0 3.1 % |
| **Operational detection gate** | **DEVELOPMENT NO-GO** | as calibrated: macro −0.003, R₂₀ +0.7; H1 failed |

## Matched 1 % budget (the shared-budget comparison)

| method | macro recall | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | R₂₀ | missed |
|---|---|---|---|---|---|---|---|
| D0 global (= O0) | 0.275 | 0.500 | 0.023 | 0.007 | 0.571 | 16.0 | 16.8 |
| D1 service groups | 0.270 | 0.481 | 0.023 | 0.007 | 0.571 | 16.0 | 16.5 |
| **D2 hierarchical (κ = 500)** | **0.270** | 0.481 | 0.023 | 0.007 | 0.571 | 16.0 | 16.2 |
| D3 reliability-aware | 0.270 | 0.481 | 0.023 | 0.007 | 0.571 | 16.0 | 16.2 |
| D_host per-host | 0.241 | 0.362 | 0.023 | 0.007 | 0.571 | 15.2 | 18.5 |
| oracle O3g (retrospective) | 0.491 | 0.503 | 0.202 | 0.364 | 0.896 | 24.0 | 11.0 |

**κ sensitivity (EXPLORATORY):** κ ∈ {100, 2000} gives the same 0.270.

**On NF-UNSW, NF-ToN and NF-BoT this comparison cannot separate the methods.**
- More benign evaluation windows than the budget allows score above every calibration maximum:
  NF-UNSW 151–318 against B = 119; NF-BoT 9–12 against B = 6.
- Every calibration-CDF method therefore reduces to raw-score ranking there, and equals D0 by
  construction. **The result on those networks is uninformative, not evidence against.**

**On NF-CIC, the one informative network, service-group thresholds are slightly worse than global**
(0.481 vs 0.500).

**Benign calibration alone cannot reproduce the oracle's gain.**
- That gain needs knowledge of *which* groups hold attacks.
- Under drift, the evaluation benign tail lies beyond anything the calibration data show.

**Per-host thresholds are worse than global** at the matched budget (NF-CIC 0.36 vs 0.50). The
cause was not isolated.

**The reported pre-fix values were artefacts:** D2 0.299 (r2) and 0.179 (first run).

## As calibrated (thresholds as estimated; FPR against the 1 % target)

| method | macro | NF-CIC rec / FPR | NF-UNSW | NF-ToN | NF-BoT | R₂₀ |
|---|---|---|---|---|---|---|
| D0 global | 0.661 | 0.503 / 1.2 % | 0.562 / 3.8 % | 0.645 / **16.0 %** | 0.934 / 9.0 % | 27.3 |
| D2 hierarchical | 0.658 | 0.502 / 1.1 % | 0.563 / 3.9 % | 0.657 / 14.8 % | 0.909 / 4.7 % | 28.0 |
| D1 service groups | 0.685 | 0.502 / 1.2 % | 0.576 / 4.0 % | 0.730 / 13.3 % | 0.934 / 9.9 % | 28.5 |
| D_host | 0.661 | 0.503 / 1.8 % | 0.562 / 3.8 % | 0.645 / 19.5 % | 0.934 / 7.5 % | 27.3 |

**No hold-out-calibrated method reaches 1 % FPR on NF-UNSW, NF-ToN or NF-BoT.**
- Their recall above 0.5 there exists only because their FPR is 4–20× the target.
- **False alerts per hour (D0 → D2):** NF-CIC 297 → 276; NF-UNSW 51 → 52; NF-ToN 16.5 → 15.2;
  NF-BoT 0.1 → 0.1.
- **Top host's share of false alerts:** NF-BoT 1.00 under every method; NF-ToN 0.37 → 0.31.

**CAL_U** (fully label-free): D0 0.374, D2 0.375 as calibrated. At matched budget D1/D2/D3 reach
0.32–0.35, mostly on NF-BoT (0.77–0.89; integer-weight D1 too, so this is not the A-3 artefact).
- This is not a calibration success. The unlabelled hold-out contains the same attacker hosts, so
  their windows shape the group CDFs. That acts as a prior on where attacks are, which a clean
  deployment would not have.

## Stress cases (EXPLORATORY; development data)

**Removing the noisiest benign calibration host:**
- as calibrated, D0's NF-BoT FPR jumps 9.0 % → 55.4 %, because NF-BoT's tail is one host
  (Phase 8s);
- D2 gives no protection (55.4 %).

**Calibrating on the older half of the hold-out:** recall falls (NF-ToN 0.65 → 0.55 as calibrated)
with no D2 advantage.

**New hosts and changed IDs:** service-group methods carry no host state, so new hosts are handled
by construction. The per-host baseline sends them to the global threshold.

## Reading

- **Conditional thresholds rearrange where false alerts fall; they do not create separation the
  scores lack.**
- **The one deployable gain (pooling makes group thresholds transfer more reliably) does not turn
  into detection.**
- **The calibration/evaluation boundary overlaps by one 30 s slot** (14 windows on NF-UNSW, 5 on
  NF-ToN). This is inherited from the Phase 8i split, and its effect is negligible; disclosed.
