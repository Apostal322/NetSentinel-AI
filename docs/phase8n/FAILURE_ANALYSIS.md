# Phase 8n: catastrophic failures, attack families and feature stability

**Sources:**
- `reports/phase8n/candidate_comparison.json` (`per_domain`, `RUN_by_network`);
- `reports/phase8n/fragility_analysis.json`;
- the Phase 8m B0r boosters (`data/derived/phase8m/models/B0r`) for importance stability.

**Labels:**
- recall values from the Experiment C fits: REGISTERED DEVELOPMENT;
- the attack-family reading and the importance analysis: EXPLORATORY.

**Attack families** are the dataset labels (`reports/phase8i/windows_<network>.json`). On NF-CIC,
each day carries one family.

## Recall per domain and family

Mean and [min, max] over the 6 fits (3 base, 3 stress):

| domain (family; attack entities) | M0 | M2 | M3 |
|---|---|---|---|
| CIC 02-14 (SSH brute force; 1) | 0.998 [0.99, 1.00] | 1.000 [1.00, 1.00] | 0.836 [**0.02**, 1.00] |
| CIC 02-16 (DoS Hulk; 1) | 0.525 [**0.00**, 0.96] | 0.963 [0.96, 0.96] | 0.821 [0.11, 0.96] |
| CIC 02-20 (DDoS LOIC-HTTP; 10) | 0.079 [0.05, 0.08] | 0.085 [0.08, 0.08] | 0.085 [0.08, 0.08] |
| CIC 02-21 (DDoS HOIC; 10) | 0.951 [0.74, 1.00] | 0.997 [0.99, 1.00] | 0.911 [0.52, 1.00] |
| CIC 02-22 (web brute force, XSS, SQL injection; 23) | 0.074 [0.02, 0.10] | 0.088 [0.07, 0.10] | 0.071 [0.06, 0.09] |
| CIC 03-02 (bot; 7) | 0.641 [**0.06**, 1.00] | 0.974 [0.86, 1.00] | 0.872 [0.76, 1.00] |
| NF-UNSW (9 families; 4) | 0.833 [0.17, 0.98] | 0.901 [0.55, 0.98] | 0.875 [0.42, 0.98] |
| NF-ToN-IoT (5 families; 11) | 0.568 [0.39, 0.67] | 0.634 [0.58, 0.81] | 0.521 [0.36, 0.69] |
| NF-BoT-IoT (DoS, DDoS, theft; 8) | 0.798 [0.63, 0.89] | 0.883 [0.86, 0.90] | 0.875 [0.85, 0.91] |

**Catastrophic failures.**
- **M0** has three domains whose worst fit is near zero: 02-16, 03-02 and, under stress, NF-UNSW
  (0.17).
- **M2** has none. Outside the two days no model detects (02-20 and 02-22, recall < 0.1 for every
  model), its worst fit on any domain is 0.55 (NF-UNSW, stress).
- **M3 introduces new window-level collapses** (02-14 at 0.02, 02-16 at 0.11).
  - The entity rule does not see them: both entities keep at least one alerted window (REVIEW).
  - M3's lower R comes from 2 entities on 02-22 and 1 on NF-ToN, all barely detected.

**Regressions to flag.**
- No family loses recall under M2 by more than 0.01 on any domain mean.
- On NF-ToN-IoT, M2's base-regime recall is 0.587 against M0's 0.609 (−0.02), with false alerts
  up 16 %. These are the only unfavourable movements.

## Attack entities never detected

**The same 20 entities are missed by every model in every fit:** 19 on 2018-02-22 and 1 on
2018-02-20. In numbers:

| network | entities | M0: all 6 fits / some / none | M2: all 6 / some / none |
|---|---|---|---|
| NF-CIC | 52 | 24 / 8 / 20 | 31 / 1 / 20 |
| NF-UNSW | 4 | 4 / 0 / 0 | 4 / 0 / 0 |
| NF-ToN-IoT | 11 | 10 / 1 / 0 | 11 / 0 / 0 |
| NF-BoT-IoT | 8 | 8 / 0 / 0 | 8 / 0 / 0 |

**The missed entities look like a coverage limit of the features, not a fragility.** This is an
interpretation, not a test.
- The 2018-02-22 attacks are application-layer (web login brute force, XSS, SQL injection) at low
  volume.
  - There are 1,241 attack flows in the evaluation half of the day's development part: 681 + 255 + 305 in
    `reports/phase8i/windows_nfcic.json`, `eval_labels`.
- No model or fit detects them, whatever its training. That fits flow-count and volume features
  that cannot separate them from browsing, but no experiment here tested it.

## Feature stability

**1. Removing one feature (Experiment A).** Only 3 of the 12 features are individually necessary,
and which ones depends on the network:

| feature | where it is necessary | network recall without it |
|---|---|---|
| `new_dst_frac` | NF-CIC, NF-ToN, NF-BoT | NF-CIC 0.004, NF-ToN 0.170, NF-BoT 0.428 |
| `log_flows` | NF-CIC, NF-BoT | NF-CIC 0.072, NF-BoT 0.183 |
| `log_dst_ports` | NF-UNSW | 0.027 (a threshold failure) |

- Of the other 9, all but `udp_share` change any network mean by ≤ 0.17. `udp_share` changes
  NF-ToN by −0.217 (to 0.392).
- **Single-domain collapses still occur.** See TRAINING_STABILITY.md: `log_dst_hosts` on 02-16,
  and several features on 03-02.

**2. Importance across seeds** (gain importance of the Phase 8m B0r boosters, 12 features):
- **Across seeds, for the same target:** the gain-importance order is stable for 3 targets. The
  Spearman correlation between seed pairs is 0.93–0.99 on NF-CIC, NF-ToN and NF-BoT, and
  0.76–0.98 on NF-UNSW.
- **Across targets, which have different source networks:** the order differs markedly (Spearman
  0.30–0.83). The top feature is `new_dst_frac` for three targets and `log_pkts` for NF-UNSW.

**3. Predictions.** In Experiment A, the evaluation scores under the randomness arms keep a
Spearman correlation of 0.90–0.98 with the reference. The *global* ranking is stable while the
*decisions* on single entities are not, because a homogeneous cluster of one attacker's windows
sits near the benign tail.

**Shortcut analysis: what this does and does not show.**
- The models depend on different features for different source combinations, and on
  `new_dst_frac` whose meaning differs between calibration and evaluation (Phase 8m). That is
  consistent with learning source-specific regularities, a shortcut risk.
- **Not done in this phase:**
  - a negative control that predicts source-network identity;
  - a provenance analysis of the capture tool.
- Feature attributions and importances are not causal evidence.
