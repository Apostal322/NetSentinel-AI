# Phase 8m results

**Development:** PREREGISTRATION.md with amendments 1–2, all written before any build or training.
**Status labels:** REGISTERED DEVELOPMENT, EXPLORATORY, POST-HOC (DEDALE) or NOT EVALUABLE.

**Saved results:**
- `reports/phase8m/novelty_audit.json`
- `reports/phase8m/model_comparison.json`
- `reports/phase8m/contamination.json`
- `reports/phase8m/dev/scores_seed{0,1,2}.json`
- the build metadata in `data/derived/phase8m/novelty/*/*/meta.json` (not tracked) and
  `reports/phase8m/build_novelty_*.json`

**Figures:** `docs/phase8m/figures/`, drawn by `scripts/phase8m/figures.py` from those files.

## Verdicts

| item | label | result |
|---|---|---|
| Stage 1: stale frozen novelty is associated with DEDALE false alerts | POST-HOC | **yes**, in correlation, model attribution and an out-of-support counterfactual (none is a causal effect): 88 % of false alerts novel; `new_dst_frac` := 0 removes 88 % of them **and** all detection |
| … and the development networks' false alerts | EXPLORATORY | NF-ToN-IoT yes (99 %); NF-CIC partly (lift ≈ 10); NF-UNSW and NF-BoT-IoT **no** |
| H3: B2 improves recall without extra workload | REGISTERED DEVELOPMENT | **NOT SUPPORTED**: recall falls on 4 of 4 networks (−0.13 to −0.47); workload ×2.2 on NF-BoT-IoT |
| H1: B2 lowers FPR on the high-FPR networks | REGISTERED DEVELOPMENT | **NOT SUPPORTED**: −89 % NF-ToN-IoT and −17 % NF-UNSW, but NF-BoT-IoT rises 11.9 % → 26.3 % (point estimate, as registered; bootstrap interval includes 0; 620 benign windows) |
| H2: the guarded memory resists contamination **and** adapts | REGISTERED DEVELOPMENT | **NOT SUPPORTED**: single-host beacons stay novel (100 %, true by construction), but only 5.5 % of benign post-freeze destinations are accepted (3 networks); attacker-contacted destinations are accepted (NF-UNSW 100 %, NF-ToN 45 %) |
| B1 vs B0 (secondary) | REGISTERED DEVELOPMENT | not supported: recall falls on 4 of 4 networks |
| selection | REGISTERED DEVELOPMENT | **no candidate → NO-GO; B0 stays** |
| ablations, B3, B1u, Q1, temporal, grid | EXPLORATORY | no variant improves recall (the grid measures promotion only). On NF-CIC the loss is mostly refit fragility: every retrained variant loses the single-attacker days that B0 and Q1 detect. On NF-UNSW and NF-ToN, the representation change alone (Q1) costs 0.33–0.34 recall |
| DEDALE application of a candidate | NOT EVALUABLE | not run: no candidate was fixed (PREREGISTRATION section 8) |
| independent confirmation | NOT EVALUABLE | no fresh eligible network exists; DEDALE is consumed |

## The central finding

On NF-ToN-IoT and DEDALE, the destinations that make benign traffic look stale-novel and the
destinations in attack windows are the same kind of signal: contacts the calibration never saw. On
NF-UNSW, attack windows rely on that signal too, though benign windows there are never novel. A
memory that adapts blurs both:
- **A1** (learn everything) erases detection.
- **A3** (≥ 2 sources, ≥ 1 h) accepts few benign destinations. Most are reached by a single host, so
  benign novelty hardly falls. Destinations contacted by several attackers, meanwhile, satisfy the
  rule within about an hour.
- **A0** (frozen, deployed) keeps detection and accumulates false alerts as time passes
  (NF-ToN-IoT 0 % → 22 % FPR at 6–24 h; DEDALE novelty 8.6 % → 27.8 % of windows over 10 days).

No registered or exploratory variant moved this trade-off in the useful direction on development
data.

**Separately,** B0's NF-CIC recall rests on fragile fits. A change of feature set and refit loses
whole single-attacker days. This is a robustness concern for the deployed model itself
(MODEL_COMPARISON.md, item 1).

Corrections from the independent review are listed in REVIEW.md.
