# Phase 8j: calibration reliability (research preparation)

**Status (2026-11-02):** design and data-integrity audit complete. **No Phase 8j method has been
compared yet, no fresh dataset has been downloaded, and nothing is frozen.** Everything here
is development-only [E] unless marked otherwise.

**Question.** Can a detector recognise when its target-network calibration is representative
enough to support a 1% false-alert budget, and abstain where it is not, while still covering
most traffic and most attacks?

| document | contents |
|---|---|
| [DATA_INTEGRITY_AUDIT.md](DATA_INTEGRITY_AUDIT.md) | the three ways labels entered the Phase 8i calibration, measured on 9 domains; the deployable protocol P1u |
| [CALIBRATION_RELIABILITY_METHODOLOGY.md](CALIBRATION_RELIABILITY_METHODOLOGY.md) | exact conformal risk, a simulation testing the four proposed eligibility checks, the learned reliability model and the PAC calibration |
| [DATASET_ELIGIBILITY.md](DATASET_ELIGIBILITY.md) | 15 candidate datasets; shortlist AIT Netflow v2 (F1) and UWF-ZeekData24 (F2); probes and approvals |
| [PREREGISTRATION.md](PREREGISTRATION.md) | hypotheses J1–J4, methods M0–M4 and controls, metrics, success criteria, development selection rule |
| [VALIDATION_PROTOCOL.md](VALIDATION_PROTOCOL.md) | data roles, order of work, label sealing, splits, failure handling, compute budget |

**Headline findings so far [E]:**
- **The future-label leak flagged by the Phase 8i audit made no measurable difference** on any
  of 9 domains, N4 included, so the Phase 8i verdicts stand.
- **The "new destination" memory does matter.** When it keeps the calibration attackers'
  traffic, recall falls on 3 domains:
  - NF-CIC 03-02: 0.86 → 0.00;
  - NF-CIC 02-22: 0.09 → 0.02;
  - NF-UNSW: 0.97 → 0.62.

  The registered protocol (P1x) purges known calibration attackers from that memory. Whether
  that restores the Phase 8i recall is not yet measured.
- **None of the four proposed eligibility checks is statistically safe on its own.** "n ≥ 199"
  falls on a bad stretch of the exact conformal risk curve. A PAC rank at a dependence-adjusted
  effective sample size had the best safety and utility trade-off in the simulation, so it
  becomes method M3. That support is simulation-only.
- **An independent review** found three blocking design problems, now fixed: the block-overrun
  definition, the P1u memory overstatement, and the random-abstention control. Section
  "Review" below lists all of them.

**Scripts:**
- `scripts/phase8j/leakage_audit.py` and `scripts/phase8j/leakage_p1u.py`: the integrity audit;
- `scripts/phase8j/threshold_stats.py`: the statistics.

**Outputs:** `reports/phase8j/`.

## Review

An independent read-only review checked every table against the JSON outputs and the code.
The numbers matched. Its substantiated findings and what was done:

| finding | severity | disposition |
|---|---|---|
| A "block FPR > 2%" overrun is binomial noise for small blocks (one alert in 30–49 windows) | blocking | overrun is now an exact binomial test against α; block size removed from M2's features |
| The measured P1u kept the excluded attackers' destinations in the evaluation memory, so the recall drop does not show a deployable detector's loss | blocking | P1x (memory purged of known calibration attackers) registered as the protocol; claims reworded; P1x measurement is a registered development run |
| Random-abstention control undefined for network-level abstention; pooling undefined for networks with no coverage | blocking | RA draws blocks pooled over all networks with matched total coverage; ties count against the method; pooling rules stated |
| Coverage loophole via benign-light blocks | should fix | criterion (b) now also needs ≥ 50% of verified-benign windows covered |
| Units ambiguous (NF-CIC days; UWF weeks; one surviving family) | should fix | NF-CIC is one unit; each UWF week is a calibration unit but F2 is one environment; single-family verdicts are labelled |
| J3 tautological; J2 had no separation test | should fix | both redefined (PREREGISTRATION section 6) |
| Simulation safety rested on a pass-rate filter, Monte Carlo noise and fixed φ | should fix | pooled counts with 95% bounds, worst configurations with counts, φ ∈ {0.5, 0.9}; M3's n_eff now deflates within-host autocorrelation |
| Score ties at T0 (58% on N4) violate the continuity assumption | should fix | thresholds are order statistics with strict-greater-than alerts; tie mass reported; the L2b finding qualified |
| Claim-rule arithmetic (step-10 search, non-monotone) and "effective windows" undefined | minor | exact search: 590 first, 719 always; the rule tests the bound on effective counts |
| Duplicate episode variants; unverified dataset claims not marked; P3 host share; missing file fallback | minor | fixed |
