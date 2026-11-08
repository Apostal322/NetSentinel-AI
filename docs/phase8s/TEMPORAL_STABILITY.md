# Phase 8s Experiment E: calibration age and freshness

**Status:** REGISTERED (PREREGISTRATION §§ 5, 7). PPS + C1, k = 30, R0, 20 draws. Every cell is
evaluated on the **second half of the evaluation period**, strictly after any review it uses.

**Cells:**
- **E0:** hold-out review (the oldest evidence).
- **E1:** review limited to the most recent half of the hold-out.
- **E2 refresh:** the same budget spent on the evaluation period's first half, on windows ending
  ≥ 1 h before the switch (review delay). The simulated reviewer there uses the audited
  categories of those first-half windows only.
- **E3:** E0, abstaining when the label-free KS distance between the hold-out and first-half
  unlabelled scores exceeds 0.10.

**Decision H5** (median |FPR − α| on the second half; E2 < E0 on ≥ 3 of 4 networks):
**SUPPORTED** (4 of 4).

**But the registered metric rewards any threshold that lowers FPR towards α.** Recall shows the
cost.

## Second half of the evaluation period

Recall excludes domains without documented attacks in the second half (amendment S-1, reporting
only):

| cell | macro recall | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|---|
| T reference (hold-out oracle threshold) | 0.438 | 0.278 / 1.3 % | 0.546 / 4.0 % | 0.036 / 3.1 % | 0.892 / 6.5 % |
| E0 historical | 0.448 | 0.273 / 1.9 % | 0.558 / 4.2 % | 0.069 / 6.4 % | 0.892 / 7.7 % |
| E1 recent half | 0.467 | 0.278 / 2.0 % | 0.573 / 5.1 % | 0.138 / 13.7 % | 0.878 / 6.0 % |
| **E2 refresh** | **0.201** | 0.278 / 1.8 % | **0.025 / 1.1 %** | **0.002 / 0.3 %** | **0.502 / 0.2 %** |
| E3 abstain if stale | 0.181 | 0.273 / 1.9 % | 0.451 / 3.0 % (abstains 33 %) | abstains 100 % | abstains 100 % |

Label-free KS drift (hold-out vs evaluation first half): NF-CIC 0.01–0.04; NF-UNSW 0.08;
NF-ToN 0.17; NF-BoT 0.61.

## Reading

**Fresh review brings FPR to about α on every network, but with a threshold that misses most
attacks.**
- **Median thresholds** (scores, from `temporal_rows.parquet`):

  | network | T reference | E0 | E2 refresh |
  |---|---|---|---|
  | NF-CIC | 0.83 | 0.81 | 0.81 |
  | NF-UNSW | 0.04 | 0.04 | **0.67** |
  | NF-ToN | 0.31 | 0.21 | **0.99** |
  | NF-BoT | 0.58 | 0.58 | **0.94** |

- In the evaluation period, **the benign 1 % tail on NF-UNSW, NF-ToN and NF-BoT lies at attack
  level.** A threshold calibrated on fresh benign evidence therefore sits there and alerts on
  almost nothing:
  - NF-UNSW recall 0.56 → 0.03;
  - NF-ToN 0.07 → 0.002;
  - NF-BoT 0.89 → 0.50.
- **The corollary matters more than H5.** On those networks, the "useful" recall of the hold-out
  thresholds, the oracle reference T included, exists only because their evaluation FPR is far
  above α (T: 16 % on NF-ToN over the whole evaluation).
  - **At a correctly calibrated 1 % FPR**, the frozen M2 with its frozen memory detects almost
    nothing on NF-UNSW and NF-ToN in this period.
  - This agrees with Phase 8o: benign novelty grows with memory age.
- **A fresher threshold cannot separate classes that drift has made overlap.** It can only choose
  where on the overlap to sit.

**The registered H5 metric was FPR-only.** H5 is SUPPORTED as written, but **freshness is not
shown to improve detection**: macro recall falls 0.448 → 0.201.

**Abstention when stale (E3)** abstains wherever drift is large (NF-ToN, NF-BoT). Its |FPR − α| of
α there is an artefact of predicting nothing.

**The second half is short and attack-sparse** on several domains. NF-ToN's T reference recall
there is 0.036. Precision is limited accordingly.
