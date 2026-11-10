# Phase 8w gap register

Written 2026-11-10 (Stage 0).

**Starting point:**
- `main` = `origin/main` = `c026569`, clean tree; CI run 42799447478 success.
- About 1.1 GB of RAM free at the start; every heavy job runs alone under the 3.4 GiB cap.

**Reused, unchanged:**
- Phase 8i window frames and the frozen member recipe; Phase 8o F0 saved member scores;
- Phase 8q label audit; Phase 8u exact partial AUC (`lowfpr.partial_auc_exact`);
- the product's `RobustScaler` floors (0.15 for fraction features, 0.25 otherwise).

| ID | scientific issue | existing evidence | experiment in 8w | leakage risk | compute | gate | status |
|---|---|---|---|---|---|---|---|
| W0.1 | **What exactly failed in Phase 8h's normalisation?** | H1a failed (Δ recall −0.256) | code and protocol audit (HISTORICAL_NORMALIZATION_AUDIT) | none | none | G0 | **done:** signed median/MAD z per network, oracle-assisted target reference, one seed, no null control |
| W0.2 | **Feature directions invert between networks** (Phase 8v: 8 of 12 features) | univariate AUC tables | unsigned deviation \|z\| (`A`) against the signed one (`S`) and the raw null (`R0`) | development labels shaped the candidate (disclosed) | up to 48 fits (**needs approval**) | G1, G4 | open |
| W0.3 | **No null control and one seed in Phase 8v** (review finding B1) | adding columns changed every tree's column draw | every arm has the same 12 columns, rows, weights and seed; five paired seeds for any supported verdict | none | included | G0, G4 | designed; tested |
| W0.4 | **Is the benign reference identifiable from unlabelled history?** | Phases 8q–8s: calibration periods contain attacks | scenarios Z0–Z3 and `T`; contamination measured with labels as a diagnostic (IDENTIFIABILITY) | labels used for the oracle reference and diagnostics only | no fit | G3 | **done (no-fit):** identifiable on NF-CIC and NF-UNSW; not on NF-ToN (bimodal benign) or NF-BoT (62 % attack windows) |
| W0.5 | **Does a relative representation survive a contaminated reference?** | none | the same boosters scored under Z1, Z2, Z3; contamination stress by re-scoring | stress contaminants are evaluation attack windows (diagnostic, disclosed) | no refit | G3 | open |
| W0.6 | **Context-conditioned references** | Phase 8u `C1` (service-relative): no gain | no-fit own-host diagnostic only | none | no fit | G2 | **NOT EVALUABLE** (registered): persistent attackers normalise themselves on NF-UNSW and NF-ToN |
| W0.7 | **Seed noise on NF-CIC and NF-BoT** (SD 0.08–0.12 partial AUC) | Phases 8u, 8v | gates need the hard-network effect *and* the macro effect in every seed; NF-BoT's as-calibrated FPR guardrail is widened to 6 points (its baseline seeds span 7–19 %) | none | none | pre-registration | registered |
| W0.8 | **Train/deploy reference mismatch:** sources use label-benign references, the target an unlabelled one | none | reported per scenario; `T` is the train-consistent oracle reference | none | none | G3 | open; a limitation of this design |
| W0.9 | **No independent network** | Phases 8o–8v | none | — | — | independent confirmation | **NOT READY** (carried) |
