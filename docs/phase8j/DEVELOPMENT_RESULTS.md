# Phase 8j development results [E]: NO-GO

**Date:** 2026-11-02. All results are development-only. No fresh data was downloaded or opened.
**Registered outcome (PREREGISTRATION.md section 7):**
- No candidate abstaining method meets criteria (a) and (b) on ≥ 2 of the 4 development
  units. The selected method S = M1 meets them on 1 (NF-CIC).
- **The go/no-go rule therefore says no-go.** The confirmatory run is not done, and the fresh
  families F1/F2 are not spent.
- The result holds under amendment A1 (overrun tested against 2α) and under the original
  α-null (sensitivity analysis). With the α-null the rule selects S = M4, again on 1 unit.

**Runs:**
- **P1x rebuild of the 4 development networks.**
  - Peaks: NF-UNSW 1,094 MiB, NF-ToN-IoT 1,087 MiB, NF-CIC 1,254 MiB, N4 2,664 MiB.
  - All finished under the 3.4 GiB cap (`reports/phase8j/logs/capped.jsonl`).
- **Leakage audit seeds 1–2 and scoring seeds 0–2:** ≤ 1,551 MiB.
- **Comparison:** 218 s, 1,304 MiB; the sensitivity run took 168 s.
- **Code:**
  - `scripts/phase8j/build_p1x.py`, `dev_scores.py`, `dev_compare.py`, `protocol_summary.py`;
  - outputs in `reports/phase8j/dev/` (`compare.json`, `compare_null_alpha.json`,
    `final_models.json`) and `reports/phase8j/protocol_summary.json`.

## 1. Held-out development units (mean over seeds 0–2; covered blocks)

| unit | method | FPR [95% bound] | block coverage | attack coverage | benign coverage | recall (covered) | entity recall | overrun rate | (a) | (b) |
|---|---|---|---|---|---|---|---|---|---|---|
| NF-CIC (6 days) | M0 | 1.3% [1.4%] | 1.00 | 1.00 | 1.00 | 0.58 | 0.85 | 0.00 | yes | yes |
| | M0x | 1.1% [1.1%] | 1.00 | 1.00 | 1.00 | 0.56 | 0.84 | 0.00 | yes | yes |
| | **M1** | 1.3% [1.4%] | 1.00 | 1.00 | 1.00 | 0.58 | 0.85 | 0.00 | yes | yes |
| | M2 | – | **0.00** | 0.00 | 0.00 | – | 0.00 | – | no | no |
| | M3 | 1.3% [1.4%] | 1.00 | 1.00 | 1.00 | 0.58 | 0.85 | 0.00 | yes | yes |
| | M4 | 1.3% [1.4%] | 1.00 | 1.00 | 1.00 | 0.58 | 0.85 | 0.00 | yes | yes |
| NF-UNSW | M0 | 3.7% [4.5%] | 1.00 | 1.00 | 1.00 | 0.97 | 1.00 | 0.89 | no | yes |
| | M0x | 0.9% [1.1%] | 1.00 | 1.00 | 1.00 | **0.18** | 1.00 | 0.00 | yes | yes |
| | M1, M3, M4 | – (abstain) | 0.00 | 0.00 | 0.00 | – | 0.00 | – | no | no |
| | M2 | 3.7% [4.6%] | 1.00 | 1.00 | 1.00 | 0.97 | 1.00 | 0.89 | no | yes |
| NF-ToN-IoT | M0 | 14.8% [32.8%] | 1.00 | 1.00 | 1.00 | 0.61 | 1.00 | 0.31 | no | yes |
| | M0x | 15.9% [34.1%] | 1.00 | 1.00 | 1.00 | 0.63 | 1.00 | 0.31 | no | yes |
| | M1, M2 | – (abstain) | 0.00 | 0.00 | 0.00 | – | 0.00 | – | no | no |
| | M3, M4 | 14.8% [~33%] | 1.00 | 1.00 | 1.00 | 0.61 | 1.00 | 0.31 | no | yes |
| N4 (consumed) | M0 | 11.9% [21.5%] | 1.00 | 1.00 | 1.00 | 0.88 | 1.00 | 0.72 | no | yes |
| | M0x | 8.0% [14.4%] | 1.00 | 1.00 | 1.00 | 0.87 | 1.00 | 0.67 | no | yes |
| | M1, M2, M3, M4 | – (abstain) | 0.00 | 0.00 | 0.00 | – | 0.00 | – | no | no |

The random-abstention p-value is 1.0 everywhere. Within a unit, every method covered either
every block or none, so random abstention at matched coverage is identical to the method.

## 2. What the development data show

1. **Network-level abstention behaves as designed, but the registered rule cannot reward it
   here.**
   - **M1** covers NF-CIC (FPR 1.0–1.6% per day) and abstains on all three networks whose
     budget fails (NF-UNSW 3.7%, NF-ToN-IoT 14.8%, N4 11.9%): 4 of 4 correct network decisions.
   - **M3/M4** make 3 of 4 correct decisions. They abstain on NF-UNSW and N4, but not on
     NF-ToN-IoT, whose failure is drift, not sample size.
   - **But** criterion (b) needs ≥ 50% coverage on each unit, and only 1 of the 4
     development units has an adequate calibration. A method that abstains correctly
     therefore *must* fail (b) on the other three.
   - **[R] post-hoc:** the go/no-go rule was mis-specified for development data that are
     mostly inadequate. This is recorded, not fixed. Changing the rule after seeing it fail
     would be a post-hoc rescue. M1's checks were also designed in the Phase 8i audit from
     these same networks, so its 4/4 is circular and not evidence.
2. **The learned reliability model (M2) is degenerate.**
   - It abstains on every block of NF-CIC, NF-ToN-IoT and N4, and covers every block of
     NF-UNSW, where FPR is 3.7%.
   - Trained on three units, it does not transfer to the fourth. A likely reason: the units
     differ in scale by orders of magnitude (7 to 6,500 hosts), so a held-out unit's features
     fall outside the training range.
   - For M2, τ was flagged in 2 of 4 folds: no τ reached ≤ 10% out-of-fold overrun.
   - For M4, τ was 1 in every fold (3 flagged), so M4 never abstained beyond M3 and equalled
     it.
   - With 4 development networks, a learned reliability model has nothing to learn from.
     This confirms the limitation stated before the run (PREREGISTRATION section 9).
3. **M0x (threshold over all calibration windows) meets (a) on NF-UNSW but at a recall of
   0.18**, against 0.97 for M0. More calibration data from the same few hosts buys a stricter
   threshold, not a representative one.
4. **The deployable protocol P1x costs no recall** (3-seed means, `protocol_summary.json`):

   | domain | P0 oracle (FPR / recall) | P1u, memory not purged | **P1x** | P2, no labels |
   |---|---|---|---|---|
   | NF-CIC 02-22 | 1.3% / 0.095 | 1.3% / 0.026 | 1.3% / 0.095 | 1.4% / 0.026 |
   | NF-CIC 03-02 | 1.0% / 0.357 | 1.0% / 0.000 | 1.0% / 0.358 | 1.0% / 0.000 |
   | NF-UNSW | 3.7% / 0.971 | 3.6% / 0.590 | 3.7% / 0.971 | 2.1% / 0.065 |
   | NF-ToN-IoT | 14.5% / 0.363 | 14.5% / 0.363 | 14.8% / **0.609** | 0.2% / 0.000 |
   | N4 | 11.7% / 0.839 | 11.7% / 0.839 | 11.9% / 0.883 | 6.7% / 0.803 |

   - The other NF-CIC days are identical across protocols.
   - Purging known calibration attackers from the destination memory restores the oracle
     recall, and exceeds it on NF-ToN-IoT and N4. The oracle's memory kept those attackers'
     benign-labelled flows; P1x drops their whole traffic.
   - **The Phase 8i development recall was therefore not overstated relative to a deployable
     detector.** Only a detector whose memory absorbs attackers' calibration traffic (P1u,
     P2) loses recall.
   - Seed variation is large: NF-CIC 03-02 oracle recall is 0.86 at seed 0 and 0.36 averaged
     over 3 seeds.
5. **J4 (descriptive):** without vetted calibration (P2), the damage shows as lost recall and
   a *lower* FPR (NF-ToN-IoT 0.2%, recall 0.00), as expected.
6. **The Phase 8i eligibility checks (J2) on development (seed 0):**
   - All 6 NF-CIC days pass; NF-UNSW, NF-ToN-IoT and N4 fail.
   - This matches their M0 FPRs, but those checks were designed on these networks, so it is
     not a test.

## 3. Consequences

- **Phase 8j stops here.** No fresh data is spent. F1/F2 remain untouched and can still serve
  a future, separately registered test.
- **Final models are saved** for the record, not for use: `reports/phase8j/dev/final_models.json`
  holds the M2/M4 coefficients and τ refitted on all 4 units. No method is promoted, and the
  deployed default is unchanged.
- **The integrity findings stand on their own:**
  - the future-label leak had no effect;
  - the deployable P1x keeps the oracle recall;
  - none of the proposed eligibility thresholds is statistically safe alone;
  - a dependence-adjusted PAC rank is the best calibration-only rule in simulation.
- **What a next phase would need** (proposal only, not registered):
  - development units where calibration adequacy varies *within* networks, so that coverage
    can be scored on the networks that deserve it;
  - a discrimination-based success criterion: correct cover/abstain decisions per network,
    plus (a) on the covered networks;
  - many more independent networks than 4 before any learned reliability model.
