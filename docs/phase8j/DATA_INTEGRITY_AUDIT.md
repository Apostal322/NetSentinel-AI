# Phase 8j data-integrity audit: labels in the Phase 8i calibration

**Date:** 2026-11-02. **Status:** development-only [E]. It changes no Phase 8h or 8i verdict.
**Code:** `scripts/phase8j/leakage_audit.py` (one seed-0 source model per target network, as in
Phase 8i), then `scripts/phase8j/leakage_p1u.py` (no model; derived from the saved scores).
**Output:** `reports/phase8j/leakage_audit.json`. Run under `scripts/run_capped.py`: peak
1,514 MiB of the 3,482 MiB cap, 262 s (`reports/phase8j/logs/capped.jsonl`).

## 1. Where labels enter the Phase 8i calibration (code reading)

| id | where | what it uses | available to a deployed detector? |
|---|---|---|---|
| **L1** | `phase8b/harness.py` builds the "clean" calibration variant from benign-labelled flows only | flow labels of the **calibration** period | only if an analyst vetted every calibration flow |
| **L2a** | `phase8i/common.py::load_domain`: `every = attackers ∪ cal_attackers`; hosts in `every` are removed from the calibration | entity labels of the **calibration** period | yes, if the calibration period was vetted |
| **L2b** | the same line: hosts that attack only in the **evaluation** period are removed too | **future** evaluation labels | **no**: this is the leakage named in the Phase 8i final audit |
| **L3** | `new_dst_frac` of evaluation windows is computed against a destination memory: ONE global set of every destination seen in the calibration variant (`harness.py`, `seen`). Phase 8i scores `eval_clean`, whose memory comes from the L1-cleaned calibration | flow labels of the calibration period, carried into the **evaluation features** | no. Not identified in the Phase 8i audit. |

The verified-benign evaluation mask (hosts that never attack) and the attack labels are used for
metrics only; that is legitimate and identical across all protocols below.

## 2. Five calibration protocols on the same windows and model

| protocol | calibration windows | hosts removed | evaluation windows | labels used |
|---|---|---|---|---|
| P0_oracle | clean (L1) | attackers of either period (L2a + L2b) | clean (L3) | L1, L2a, L2b, L3 (the registered Phase 8i protocol) |
| P1_past | clean (L1) | calibration-period attackers (L2a) | clean (L3) | L1, L2a, L3 |
| P1u_past_unlabelled | all flows | calibration-period attackers (L2a), from the hold-out only | all flows; the destination memory still holds **every** calibration destination, the removed attackers' included | L2a only |
| **P1x** (registered, not yet measured) | all flows | calibration-period attackers (L2a) | all flows; destination memory built **only from the retained hosts' flows** | L2a only: the deployable protocol (section 5) |
| P2_none | all flows | none | all flows | none |
| P3_screen | all flows | hosts whose median source score exceeds the source model's own benign 99th percentile | all flows | none (label-free screening by the source model) |

P0 reproduces the Phase 8i seed-0 T0 and A1 FPR exactly on all 9 domains (checked in code).
NF-BoT-IoT-v3 (N4) is consumed. It appears here as a development network only and can never
again be confirmation.

## 3. Results: realised FPR on verified-benign windows / window recall at T0 (seed 0)

| domain | P0_oracle | P1_past | P1u_past_unlabelled | P2_none | P3_screen |
|---|---|---|---|---|---|
| NF-CIC 02-14 | 1.3% / 1.00 | 1.3% / 1.00 | 1.3% / 0.99 | 1.3% / 0.99 | 3.2% / 0.99 |
| NF-CIC 02-16 | 1.3% / 0.96 | 1.3% / 0.96 | 1.3% / 0.96 | 1.3% / 0.96 | 1.4% / 0.96 |
| NF-CIC 02-20 | 1.4% / 0.08 | 1.4% / 0.08 | 1.4% / 0.08 | 1.4% / 0.08 | 1.2% / 0.08 |
| NF-CIC 02-21 | 1.6% / 1.00 | 1.6% / 1.00 | 1.6% / 1.00 | 1.6% / 1.00 | 2.5% / 1.00 |
| NF-CIC 02-22 | 1.3% / 0.09 | 1.3% / 0.09 | 1.3% / **0.02** | 1.3% / 0.02 | 2.8% / 0.02 |
| NF-CIC 03-02 | 1.0% / 0.86 | 1.0% / 0.86 | 1.0% / **0.00** | 1.0% / 0.00 | 1.1% / 0.00 |
| NF-UNSW | 3.7% / 0.97 | 3.7% / 0.97 | 3.7% / **0.62** | 2.2% / 0.08 | 2.2% / 0.08 |
| NF-ToN-IoT | 13.1% / 0.28 | 13.1% / 0.28 | 13.1% / 0.28 | 0.0% / 0.00 | 3.9% / 0.10 |
| N4 (consumed) | 21.0% / 0.85 | 21.0% / 0.85 | 21.0% / 0.85 | 6.6% / 0.80 | 6.6% / 0.80 |

| domain | future-only attacker windows in the P1 hold-out | attack windows in the P2 hold-out | T0: P2 vs P0 | hosts removed by P3 (attackers) | ROC-AUC P0 / P1u |
|---|---|---|---|---|---|
| NF-CIC 02-14 | 0 | 52 (0.1%) | 0.803 vs 0.803 | 6,006 (1) | 0.993 / 0.994 |
| NF-CIC 02-16 | 0 | 0 | 0.812 vs 0.812 | 4,580 (1) | 0.982 / 0.982 |
| NF-CIC 02-20 | 0 | 1 | 0.815 vs 0.815 | 5,707 (10) | 0.235 / 0.235 |
| NF-CIC 02-21 | 0 | 0 | 0.803 vs 0.803 | 5,760 (0) | 0.999 / 0.999 |
| NF-CIC 02-22 | 413 (67 hosts) | 244 (0.6%) | 0.803 vs 0.803 | 5,751 (75) | 0.479 / 0.271 |
| NF-CIC 03-02 | 0 | 822 (2.7%) | 0.816 vs 0.817 | 4,614 (1) | 0.989 / 0.427 |
| NF-UNSW | 0 | 180 (28.9%) | 0.465 vs 0.040 | 1 (0) | 0.975 / 0.935 |
| NF-ToN-IoT | 1 | 4,304 (22.3%) | 0.998 vs 0.550 | 10 (9) | 0.813 / 0.813 |
| N4 | 0 | 5,799 (60.0%) | 0.693 vs 0.498 | 1 (0) | 0.866 / 0.866 |

## 4. Findings

1. **The future-label leak (L2b) changed nothing measurable in these data.** P1 equals P0 in
   threshold, FPR and recall on all 9 domains.
   - Only NF-CIC 02-22 (413 hold-out windows of 67 hosts that attack only later) and
     NF-ToN-IoT (1 window) had future-only attackers in the hold-out.
   - **Part of the reason is score ties:** the source model gives many windows identical
     scores. On 02-22, 1.2% of hold-out scores tie exactly at T0, which is more than α, so T0
     barely moves when a few hundred windows are added. Tie mass at T0 is 0–1.2% on the other
     development domains and **58% on N4**, where the dominant host's windows score
     identically.
   - **N4:** all 8 of its evaluation attackers also attacked during calibration, so P0 and P1
     coincide there. The Phase 8i final audit said this "cannot be determined from the saved
     files". It can, and the answer is: no effect.
   - The Phase 8i verdicts (I1 failure, I2 not evaluable, I3 failure) stand.
2. **Recall depends on what the destination memory contains.**
   - With all-flow windows whose memory includes the calibration attackers' traffic (P1u, as
     measured), FPR is unchanged but recall falls on 3 domains:
     - NF-CIC 03-02: 0.86 → 0.00 (ROC-AUC 0.99 → 0.43);
     - NF-CIC 02-22: 0.09 → 0.02;
     - NF-UNSW: 0.97 → 0.62.
   - Attackers active during calibration put their destinations into the memory, so their
     later attack windows no longer look new. On 03-02 all 7 evaluation attackers were also
     calibration attackers.
   - P1u's own premise is that the operator knows those hosts, and an operator who knows them
     can keep their traffic out of the memory (P1x). P1x is close to the clean memory of P0,
     so it may recover most of the recall. **That is untested:** it needs a window rebuild,
     registered as a development run.
   - **What is established:** a detector whose memory absorbs attackers' calibration traffic
     (P1u, P2) loses recall on these domains.
   - **What is not:** that the Phase 8i development recall overstates what a deployable
     detector (P1x) would reach.
   - N4 is unaffected (recall 0.85 under every protocol with attacker exclusion).
3. **With no labels at all (P2), contamination dominates.** Attack windows make up 22–60% of
   the hold-out on NF-UNSW, NF-ToN-IoT and N4. T0 rises (NF-ToN-IoT 0.55 → 0.998), FPR falls
   and recall collapses (NF-ToN-IoT 0.28 → 0.00; NF-UNSW 0.97 → 0.08). Lower FPR here is a
   symptom, not an improvement.
4. **Label-free screening by the source model (P3) does not work.** It removes 39–47% of the
   NF-CIC hold-out hosts: the source model, trained on other networks, scores many NF-CIC
   benign hosts above its own benign 99th percentile. That raises FPR to 2.5–3.2% on three
   days. It also removes only 9 of 24 NF-ToN-IoT calibration attackers.

## 5. The deployment-realistic protocol for Phase 8j

**P1x is the registered calibration protocol for every Phase 8j method:**
- Calibration windows are built from all flows (no flow-level cleaning).
- Hosts with an attack **during the calibration period** are removed, both from the hold-out
  and from the destination memory used for evaluation features. On fresh data, this list
  comes only from labels or published schedule entries whose time is before the calibration
  end. The function that reads them must refuse later rows; it is written and unit-tested
  before the freeze (VALIDATION_PROTOCOL.md section 3).
- Evaluation windows are built from all flows, against that purged memory.
- No evaluation-period label touches calibration, features, thresholds or method choice.

P1x needs the window builder to take the excluded host list before it builds the memory: a
small code change, plus one rebuild per network.

It assumes the operator can vet the calibration period (for example an incident review of a
quiet week). Two secondary rows are reported on every network so the cost of that assumption
stays visible: the fully label-free P2, and the measured P1u (memory not purged). P3 is
dropped.

## 6. Other integrity checks

- `git status`: clean at 102882f before Phase 8j. Phase 8i frozen artefacts unchanged.
- Development data: every file under `data/derived/phase8i` was produced by the Phase 8i
  `build_windows.py`, from hash-checked inputs (Phase 8i DATASET_AUDIT section 3). The
  memory-bounded audit version reproduces them exactly.
- All results above use one seed (0). Seeds 1–2 are registered development runs.
- **Process deviation:** the leakage audit was estimated at about 1 minute but ran 262 s. That
  exceeds the project's 2-minute approval threshold, and it ran without prior approval. It
  stayed within its memory cap (1,514 MiB) and read no protected or fresh data.
- No Phase 8j code reads any dataset not already consumed or development-permitted.
- Remaining limitation: L2a still requires the calibration-period labels to be correct. On
  NF-ToN-IoT and N4 they are known to be imperfect (Phase 8c; Phase 8i label audit).
