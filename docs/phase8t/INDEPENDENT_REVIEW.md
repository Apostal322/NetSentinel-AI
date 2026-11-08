# Phase 8t: independent review and actions

**The review.** A separate agent did a read-only audit as six reviewers:
- A: calibration methodology;
- B: ML methodology;
- C: data integrity;
- D: statistics;
- E: operational relevance;
- F: research integrity.

It had the protocol, amendments, code and saved results, but not the author's conclusions. It
recomputed the key numbers with its own code, including a brute-force group allocation that did
not reuse the repository's dynamic programme. Every finding used below was re-checked against
the saved data.

## Recomputed and matched

| quantity | result |
|---|---|
| O0 and O3g recall per network (NF-UNSW, NF-BoT; 6 fits) | exact match |
| D0 / D2 as calibrated, CAL_T (recall, FPR) | match |
| D0 matched budget = O0 in every fit (NF-UNSW, NF-BoT, NF-ToN, NF-CIC 02-21) | confirmed (the A-2 property) |
| G1 arithmetic (macro gain 0.216, R₂₀ +8, retention ratios) | match |
| no host has both documented-attack and benign evaluation windows | confirmed; true by construction |
| thresholds use hold-out data only; service groups come from each window's own features | confirmed |
| chronology: registration `05b8dc3` → oracle results `caaa602` (clean tree) → A-1 before deployable code `ebe8596` → runs on clean trees, all kept | confirmed |

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| A1 | **high** | **D2's matched-budget values were a floating-point artefact.** The CDF saturated at 1 ± 1e-14, so saturated windows were ordered by group | yes: after the fix D2 equals D0 on NF-UNSW, NF-ToN and NF-BoT; macro 0.299 → 0.270 | **amendment A-3**; `deployable_r3.json`; H1 restated (−0.005). Verdicts unchanged |
| A2 | **high** | **Under drift the matched-budget estimand degenerates:** more than B benign windows exceed every calibration maximum, so CDF methods reduce to raw-score ranking | yes (NF-UNSW 151–318 > 119; NF-BoT 9–12 > 6) | H1 described as **informative on NF-CIC only** |
| E1 | **high** | **As calibrated, recall about 0.66 is bought with FPR 4–16× the 1 % target** (NF-ToN 16 %, NF-BoT 9 %, NF-UNSW 3.8 %); 10–17 of 48 entities missed entirely | yes | put first in the final report |
| B4 | medium | **The O3g gain is mostly budget reallocation into attack-rich groups.** Only NF-UNSW's multi-port group looks stable | yes | ORACLE_FEASIBILITY § 4 |
| D8 | medium | **G1 criterion 3 depends on interpretation** (≥ 3 of 4 networks retaining: 2 of 4) | yes | all four readings reported; the registered PASS kept and qualified |
| D9 | medium | **The R₂₀ interval treats 48 entities as independent;** domain clusters give [0, 21.3] | yes (recomputed) | reported |
| A3 | low | D2's global component includes the group's own windows (double counting). Groups without calibration windows fall back to global; one such NF-UNSW group holds 2,174 positives | yes | disclosed |
| C7 | low | **The calibration/evaluation boundary shares one 30 s slot** (NF-UNSW 14 windows, NF-ToN 5), inherited from Phase 8i | yes | disclosed; negligible; historical split not changed |
| F12 | medium | A-2 exposed A1, so both earlier files' D2 matched values on 3 networks are invalid | yes | A-3 note; earlier files kept and marked |

## Not changed

- Registered rules and the verdicts: **H1 NOT SUPPORTED, H2 SUPPORTED, H3/H4 NOT SUPPORTED,
  operational gate DEVELOPMENT NO-GO.**
- The as-calibrated results. They are identical across the three runs.
- The frozen M2 and all historical artifacts.
