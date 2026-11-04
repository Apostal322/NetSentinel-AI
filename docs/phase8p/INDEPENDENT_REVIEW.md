# Phase 8p: independent review and actions

**The review.** A separate agent did a read-only audit as five reviewers (ML, data integrity,
statistics, operational detection, research claims). It was given the code, the
pre-registration and the saved results, but not the author's conclusions.
- It recomputed the D2 and S1 decisions with its own implementation.
- It recomputed the D3 behaviour on NF-UNSW and NF-BoT, the C3 threshold and the victim history
  directly from the saved files.

Every finding used below was re-checked by the author against the data or the official
source before any change. Where the re-check differed, the re-checked value is used (noted).

## Confirmed

- **Chronology.**
  - Registration commit `5cdbe8d` at 19:34:42.
  - All Experiment E score files are dated 19:47–21:40, and both run provenances record
    `git_head` = `5cdbe8d`.
  - `analyze_e.py` ran as registered.
- **R1 is genuine.** All 27 S0 base refits equal Phase 8o F0 (max |Δ| = 0.0) through the
  SX-joined frames, so the join changes no training row, order or capped draw. The arms are
  paired.
- **The victim history is causal.** Recomputed from the per-host order: maximum error 4.5e-14.
  There are no duplicate victim-window or source-context rows.
- **The decisions recompute exactly:**
  - D2: macro_doc 0.701 vs 0.869; R₂₀ 18 vs 37; 16 collapses.
  - S1: 0.785; R₂₀ 30.
  - Both fail the guardrails as reported.
- **The roles are assigned by IP rule, not by outcome,** and identically for every arm (48 / 5 /
  22).
- **UTC−4 is correct** (Atlantic standard time; DST began 11 March 2018).
- **C2 and C3 are implemented as registered.** An independent weighted quantile matches C3.

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| 1 | high | **The 02-20 "post-attack LOIC residue" claim is wrong.** The official table has a second 02-20 row, DDoS-LOIC-UDP 13:13–13:32. All 106 evaluation attack windows fall inside it | yes: re-fetched the table; 2,153 flows at 13:14–13:29 local, 1,363 TCP and 790 UDP, all labelled `ddos_loic_http` | intervals fixed in `observability.py` (now per attack and host); ATTACK_OBSERVABILITY, FAILURE_ANALYSIS, GAP_REGISTER and MODEL_COMPARISON corrected to "onset of the documented LOIC-UDP attack under the HTTP label". Roles and every Experiment E number are unchanged |
| 2 | medium | 02-14 and 02-16 intervals pooled across attackers | yes | per-host intervals; SSH 98 %, Hulk 100 % inside (unchanged); undocumented sources 0 % inside any interval of an attack naming them, 21 % by time alone |
| 3 | high | **D3 on NF-UNSW is degenerate:** ties give T0 = 1.0, so no window can alert | yes (10 of 443 hold-out windows share the top victim score) | NF-UNSW reported as "not operable"; 3-network macro 0.861 vs S0 0.880 added; verdict unchanged (NF-BoT guardrail) |
| 4 | high | **D3 on NF-BoT is guilt by association:** benign clients of attacked hosts inherit victim scores beyond the hold-out range | yes; 6-fit FPR 45.9 % (the reviewer's 46.6 % is base r6) | stated in MODEL_COMPARISON § 3 |
| 5 | medium | **The paired differences were reported in a different unit from rule (b)** (pooled domains, NF-CIC 6/9 of the weight). The registered SD-based margin does not describe this phase (S0 per-fit range 0.19) | yes | network-macro paired differences, split base/stress, now reported; the margin's justification flagged |
| 6 | medium | **The entity bootstrap is too optimistic;** entities cluster by network-day | yes: domain-cluster intervals S1 [−22, +2], D2 [−43, −2], D3 [−13, 0] | cluster intervals reported; losses described as specific clusters (03-02 bots, 02-21 HOIC) |
| 7 | medium | **C3 works opposite to its rationale on NF-ToN.** Transient low-score hosts take the weight: T0 0.0055 vs C1 0.993; 55 % of hold-out windows lie above it | yes (re-run) | CALIBRATION_STUDY rewritten: host balancing hands the tail to transient hosts |
| 8 | low | C2 ≈ C1 by construction except on NF-BoT | — | stated |
| 9 | medium | **D1 attributed coverage is nearly uninformative** (1.00 at victim-window recall 0.01–0.13); no carry-over of the in-domain victim-side separation | yes; mixed share on 02-20 is 50 % in the saved output (the reviewer's 0.63 used another definition) | MODEL_COMPARISON § 3: never cited as detection |
| 10 | low | the straddle window's SX and VW rows mix pre- and post-midpoint flows (one window per domain) | — | documented here and in `build_victim.py` |
| 11 | low | the history join relied on row order without `maintain_order` | yes | `maintain_order="left"` added; a rebuild of NF-UNSW is identical (max \|Δ\| 0.0, 37,302 rows) |
| 12 | low | the documented-attacker primary set was chosen after seeing that S0's misses were undocumented sources | disclosed in the pre-registration; symmetric across arms | all-75 figures reported beside the documented ones |
| — | claim | "Remaining misses are a transfer problem, not an evidence problem" overstates in-domain ceilings that can leak host identity | yes | reworded to "separable in-domain"; D1 shows no cross-network victim-side transfer |

## Not changed

- **No registered verdict.** H1–H4 are NOT SUPPORTED; DEVELOPMENT NO-GO.
- **No saved score.**
- **The frozen M2.**
- **The pre-registration text.** Its two design errors, D3's tie-unsafe fusion and the SD
  justification of the 0.03 margin, are recorded in this file and in MODEL_COMPARISON rather
  than repaired after the fact.
