# Phase 8s: independent review and actions

**The review.** A separate agent did a read-only audit as six reviewers:
- A: sampling;
- B: machine learning;
- C: statistics;
- D: data integrity;
- E: operational relevance;
- F: claims.

It received the protocol, code and saved results, but not the author's conclusions. It
recomputed the decision inputs with its own scripts. Every high-severity finding below was
re-checked by the author against the saved rows before any change.

## Recomputed and matched

| quantity | result |
|---|---|
| H1 per-network medians (primary and baseline, 8 values) | exact match |
| Calibration gate: per-network mean FPR, NF-ToN p90, abstention, macro recall 0.6741 | match |
| H3 medians, H4 contamination, H5 deviations | match |
| Σπ = min(k, H) for every design; random-window π_h against its draw mechanism (Monte Carlo, max error 0.014) | correct |
| Frozen score hashes | 54 / 54 present and matching Phase 8o |
| Information boundary | designs see only `Pool`; labels live only in `Reviewer` and the metrics; Experiment E's halves do not overlap, and the 1 h review delay is applied |
| Chronology | registration `16f564b` 01:25:46 → results 01:36–01:38 → `a5161d9` 01:38:05; `provenance.git_sha` = `16f564b`, clean tree; code unchanged between the two commits |

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| C1 | high | **The H1 "3 of 4" count depends on a census artefact.** NF-UNSW (21 hosts) and NF-BoT (15) are reviewed in full by every design at k = 30, so the NF-UNSW "win" is only the quantile definition (C1 inverted-CDF vs C0 conformal rank) | yes (identical host sets; random-host + C1 gives the same 0.0021) | amendment S-3; documents state "2 of 2 non-census networks"; the verdict stands as registered |
| C2 | high | **H3 has the same flaw** | yes (NF-UNSW: 50 % of pairs exactly 0; NF-BoT median 0) | S-3; ACTIVE_CALIBRATION qualified |
| E1 | high | **H5 "SUPPORTED" comes from thresholds that collapse recall** (NF-ToN E2 recall 0.002; NF-UNSW R₂₀ 0). Abstention also scores \|FPR − α\| = α | yes | TEMPORAL_STABILITY relabelled: "FPR fidelity only; detection collapses". The corollary is stated: at a calibrated 1 % FPR, the frozen M2 detects almost nothing on NF-ToN/NF-UNSW in that period |
| E2 | high | **Gate C compares against T, which is itself far from α** (NF-ToN 16 %). Passing networks still carry 1.5–2.1 false alerts per benign host-hour | yes | stated in the final report; burden reported beside every calibration claim |
| B1 | medium | **No active or tail design beats the window-proportional controls; budget matters more than design.** The primary comparison matches expected attempts, not SIMULATED cost (NF-ToN about 183 vs 32) | yes | stated (ACTIVE_CALIBRATION §§ 1, 4) |
| A2 | medium | census networks make the 20 draws identical copies, so their p10/p90 are degenerate | yes | stated |
| C5 | medium | `summarise` kept NaN recall, so temporal NF-CIC and macro recall are NaN | yes | fixed for future runs (amendment S-1); corrected table in `posthoc.json` (EXPLORATORY); the registered JSON is kept |
| C3 | medium | \|cal_error\| is symmetric and in-sample (trusted windows belong to the scored hold-out) | yes | disclosed |
| E3 | medium | C3 abstains 100 % on NF-ToN/NF-BoT and 67 % on NF-UNSW | yes | reported; it is C3's registered purpose (fewer than 5 tail hosts) |
| F3 | medium | 7 primary decisions on 4 correlated networks, 2 of them census-limited | — | stated |
| A3 | low | the window-level Kish n_eff treats clustered windows as independent | yes | disclosed; the tail-host count is the binding safeguard |
| C6 | low | H2 pools budgets (k confounds both correlates) | yes | disclosed |
| D2 | low | the hash check silently passed files missing from the registry | yes | fixed to fail closed (amendment S-2); none were missing |
| C4 | low | `decide()` nits: null handling in H3/H4 (none occurred); nearest-rank p90 | yes | noted |

## Robust verdicts (the reviewer's assessment, confirmed)

These do not depend on any artefact above:
- calibration quality **NOT SUPPORTED** (NF-ToN);
- detection **DEVELOPMENT NO-GO**;
- reviewer-error robustness **NOT SUPPORTED**.

## Not changed

- Registered rules and verdicts.
- `reports/phase8s/experiments.json` and its hash.
- The frozen M2 and every historical artifact.
