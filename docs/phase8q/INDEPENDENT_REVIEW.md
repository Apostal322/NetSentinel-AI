# Phase 8q: independent review and actions

**The review.** A separate agent did a read-only audit as five reviewers (ground truth, ML
methodology, statistics, leakage, claims). It was given the code, the pre-registration and the
saved results, but not the author's conclusions.
- It fetched the official CSE-CIC-IDS2018 table.
- It recomputed the decomposition cells, the L1/L4 decisions and per-domain recall with its own
  code.

Every finding used below was re-checked against the saved data before any change.

## Confirmed

- **Chronology.**
  - Registration `50bcc4b` (18:17:49) precedes `experiment_f.json` (18:21) and
    `experiment_g.json` (18:35); results `cfb0c67` at 18:38.
  - The only post-registration code change before the results was the vectorised
    `persistent_trim_t0`. Independently re-implemented as the registered loop, it reproduces L4
    on the real data.
- **Ground truth.**
  - All 14 Table 2 rows match the official page.
  - The category counts in LABEL_AUDIT.md match `label_audit.json`.
  - No raw label is modified.
- **UTC−4 is inferred, not documented,** and the data support it:
  - documented attackers' windows fall at local 14:01–15:33 on 02-14 (table 14:01–15:31) and
    14:11–15:06 on 02-21 (table 14:05–15:05);
  - the few "outside interval" windows are end-of-attack spillover.
- **Decomposition alignment.** The P1x hold-out equals the non-attacker rows of the unlabelled
  hold-out on all 9 domains. TE = P is real.
  - An equality assertion now enforces this in the code.
- **Every reported number recomputes:** the U, T and P cells; L1 and L4 decisions; all verdicts
  NOT SUPPORTED.
- **No leakage.**
  - The candidates use only unlabelled hold-out scores, hosts and times.
  - The oracle labels enter only the counterfactual cells and G's injection.
  - The guard memory uses calibration flows only.
- **02-14's single differing destination** is 172.31.69.25, the victim. Its only
  calibration-period source was the FTP attacker.

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| 1 | high | **"One destination flips 02-14" is false at recall level.** 02-14 recall: U 0.990, P 1.000. The NF-CIC memory effect (0.304) is all 02-22 (0.003 → 0.843) and 03-02 (0.000 → 0.978) | yes (per-domain cells added to the decomposition) | CALIBRATION_DECOMPOSITION § 3 rewritten; the guard's 02-14 "success" is described as a day that needed nothing |
| 2 | medium | **"No label-free threshold can work" overstates four tested estimators.** L2 fell back to U on NF-UNSW (1 block) and NF-CIC (2–3 blocks) | yes (block counts now in `experiment_f.json`) | reworded to "the registered candidates did not recover the gap"; fallback reported |
| 3 | medium | NF-UNSW at 29 % is contaminated, not "attack-dominated" | yes | corrected in both documents |
| 4 | medium | criterion (iii) on NF-BoT is failed by U itself; NF-BoT FPR rests on about 2 benign hosts; the decision unit was not stated | yes | stated; criterion (i) decides every verdict |
| 5 | medium | **registered outputs were missing:** the domain-cluster bootstrap, false alerts per hour, G's breakdown fraction | yes | added to `experiment_fg.py` and rerun; every registered number identical; reported |
| 6 | medium | G's ≤ 10 % range is far below the real contamination (11.4 ×, 3.2 ×, 41 %); "every estimator buys robustness with false alerts" is false on NF-UNSW (L1 lowers FPR and halves recall); L4 trims one NF-BoT host in base r6 | yes | LABEL_FREE_CALIBRATION § 2 corrected |
| 7 | low | 03-02 "documented attackers" are Table 2's Bot *victims* (infected hosts) | yes | role text: "documented infected host" |
| 8 | low | the NF-ToN role rule matched any address with last octet 30–39; NF-BoT roles likely match the BoT-IoT paper (recalled, not checked) | yes (rule) | anchored to 192.168.1.0/24 (categories identical); paper note added as unverified |
| 9 | low | "hold-out memory = 0" hides the saturation of the expanding memory, which drives P's own excess FPR | yes | stated in CALIBRATION_DECOMPOSITION § 3 |
| 10 | low | docs were untracked when the gap register cited them; the decomposition checked sizes only | yes | committed; equality assertion added |

## Not changed

- No registered verdict, and no saved score.
- The registered parameters (c = α/2, 1-h blocks, the leave-one-host-out trim, the abstention
  thresholds).
- Historical Phase 8h–8p results.
