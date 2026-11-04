# Phase 8q pre-registration: Experiment F (label-free threshold calibration) and Experiment G (controlled contamination)

**Chronology.** Written 2026-11-04 after:
- the ground-truth audit (LABEL_AUDIT.md; `reports/phase8q/label_audit.json`);
- the benchmark recomputation (`benchmark_metrics.json`);
- the calibration decomposition (`calibration_decomposition.json`).

It is written before any candidate below has been computed. No candidate score, threshold or
metric exists when this file is committed.

**What was seen.** The decomposition cells:

| cell | macro recall_doc |
|---|---|
| U | 0.372 |
| T | 0.656 |
| TE | 0.869 |
| P | 0.869 |
| UE | 0.518 |

Their per-network values and the hold-out composition (attacker windows per domain) were seen as
well.

**Revision before commit.** The first draft set c = 0.02 and compared each host with the pooled quantile.
Unit tests on *synthetic* data showed two defects:
- a 2 % cap still lets one host hold twice the 1 % budget;
- a large host masks itself in a pooled quantile.

Both were fixed (c = α/2; leave-one-host-out) before this file was committed and before any real
candidate result existed.

**What shaped the design:**
- The candidate family (threshold-only, label-free) and the margins below were chosen with those
  cells in view.
- The thresholds' tuning parameters are fixed here, with reasons, and are not searched.

**Data.** Saved Phase 8o F0 scores: 6 fits, K = 5, consumed development networks. No model is
fitted. Every result is REGISTERED DEVELOPMENT. DEDALE is not used.

## 1. Setting (deployment-realistic, label-free)

| item | value |
|---|---|
| hold-out | the *unlabelled* calibration hold-out (last 30 % of calibration slots; every host; memory from all calibration flows) and its scores `s_hold_u`, with each window's host and end time |
| evaluation | the unlabelled evaluation scores `s_ev_u` (memory from all calibration flows); no label of any period is used by a candidate |
| metric population | V2 documented-attacker windows (positives) vs the historical benign set (negatives); label audit `label-audit-1.0.0` |
| α | 1 % |

## 2. References

| reference | role |
|---|---|
| **U** = T0 on `s_hold_u` (Phase 8p C1) | the deployment-realistic baseline every candidate must beat |
| **T** = T0 on `s_hold_u` without the oracle calibration-attacker windows | the ceiling of any threshold-only fix at the unlabelled memory (oracle, not deployable) |
| **P** = P1x (Phase 8p C0) | the oracle-assisted reference |

## 3. Candidates (label-free; parameters fixed now)

| candidate | threshold | why this parameter |
|---|---|---|
| **L1 host-capped** | the weighted (1 − α) quantile of `s_hold_u`, weight per window min(1, c · N / n_h) / normalised, where n_h is the host's hold-out windows, N the total and **c = α/2 = 0.005** | no single host can hold the alert budget alone. Unlike Phase 8p's equal host weights, small hosts keep weight 1, so transient hosts do not take over the tail. Known limit: k ≥ 2 contaminating hosts can still hold k · c ≥ α |
| **L2 block-median** | the median over 1-hour time blocks of each block's (1 − α) quantile (blocks with ≥ 100 windows; at least 5 such blocks, otherwise L2 = U) | a contaminating episode that covers under half the hold-out hours cannot move the median. 1 h is the existing block unit (Phase 8f/8o) |
| **L4 persistent-host trim** | T0 after removing hosts whose *median* hold-out score exceeds the (1 − α) quantile of the *other* hosts' windows (leave-one-host-out for hosts with ≥ α/2 of the windows) | a host whose typical window is in the top 1 % of everyone else's behaves unlike the population; fixed at the same α |
| **L5 = L4 + abstention** | L4, but the domain is *unassessed* if the hold-out has fewer than 100 distinct host-hour blocks (1/α; Phase 8o C2) or fewer than 20 effective hosts (1 / Σ host share²) | insufficient evidence is reported, not hidden; unassessed windows count as not detected |

## 4. Decision rule (candidate X vs U; 6 fits; network means)

**X is SUPPORTED if all four hold:**

| # | condition |
|---|---|
| (i) | macro recall_doc(X) − macro recall_doc(U) ≥ 0.10 (attainable: T − U = 0.285) |
| (ii) | on every network, recall_doc(X) ≥ recall_doc(U) − 0.05 |
| (iii) | on every network, FPR(X) ≤ FPR(P) + 0.01: no worse than the oracle reference's own false-alert rate plus 1 pp. α itself is not attainable; P exceeds it on 2 networks |
| (iv) | abstaining candidates (L5): at least 50 % of evaluation windows assessed on every network; recall over all windows |

**Calibration research verdict:** SUPPORTED if any candidate is SUPPORTED; NOT SUPPORTED otherwise;
NOT EVALUABLE if a score set is missing.

**Also reported:**
- the share of the T − U gap each candidate recovers;
- per-network recall, FPR and false alerts per hour;
- documented-entity R₂₀;
- the domain-cluster bootstrap interval of the R₂₀ difference vs U (B = 2,000, seed 8);
- paired per-fit differences.

## 5. Experiment G: controlled contamination of a clean hold-out (descriptive, registered)

**Clean base:** the P1x hold-out scores (`s_hold`), with evaluation on `s_ev` (P1x memory), so
that **only the threshold** is contaminated.

**Injection:** the domain's own calibration-attacker hold-out windows (their `s_hold_u` scores,
with their hosts).
- Amounts: f ∈ {0.5, 1, 2, 5, 10} % of the clean hold-out size, capped by what exists.
- Two modes:
  - **(a) persistent single host:** the calibration attacker with the most hold-out windows;
  - **(b) spread:** a random draw over every attacker window, seed 8.

**Thresholds compared:** T0, L1, L2 and L4 on the contaminated hold-out.

**Measured:**
- the threshold shift;
- recall_doc and FPR on evaluation;
- the contamination level at which each method's recall falls by more than 0.10.

**Sparse calibration:** keep a random 25 % and 10 % of hold-out *hosts* (seed 8; no injection).
- Measured: the variability of T0 and L1–L4 over 20 draws.

**Mixed semantics.** The injected windows are scored under the unlabelled memory, the base under
P1x. Stated; this is a stress test of the threshold estimators, not of the memory.

## 6. Exploratory, after the registered parts: label-free memory guard (feature level only)

- **The guard:** the frozen destination memory admits only destinations contacted by ≥ 2 distinct
  calibration sources.
- **Measured:** whether it restores the novelty of documented attack windows relative to the
  unlabelled memory, without rescoring (no models are saved; rescoring would need refits, which
  are not authorized here).
- **This is a feasibility diagnostic, not a detector result.**

## 7. Budget

Saved scores and lazy flow scans only. Each script runs in minutes under `run_capped`
(3.4 GiB). No training, no download.
