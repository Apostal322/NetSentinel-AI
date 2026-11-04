# Phase 8q Experiments F and G: label-free threshold calibration and controlled contamination

**Status:**
- **F:** REGISTERED DEVELOPMENT.
- **G:** registered, descriptive.
- **Memory guard:** EXPLORATORY.

**Data:** saved scores only (Phase 8o F0, 6 fits, K = 5); no model is fitted.

**Sources:** `reports/phase8q/experiment_f.json`, `experiment_g.json`, `memory_guard_diag.json`.

**Figures:** `labelfree_pareto.png`, `contamination_dose.png`, `sparsity.png`, `memory_guard.png`.

## 1. Experiment F: label-free thresholds on the unlabelled hold-out (documented-attacker recall / FPR)

| method | macro | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | R₂₀ | verdict |
|---|---|---|---|---|---|---|---|
| U (baseline, no labels) | 0.372 | 0.503 / 1.16 % | 0.054 / 1.80 % | 0.001 / 0.39 % | 0.930 / 9.60 % | 16 | — |
| T (oracle threshold-only ceiling) | 0.656 | 0.503 | 0.549 | 0.640 | 0.933 | 24 | reference |
| P (P1x oracle) | 0.869 | 0.807 | 0.835 | 0.884 | 0.950 | 37 | reference |
| **L1** host cap α/2 | 0.387 | 0.503 / 1.17 % | 0.079 / 2.05 % | 0.037 / 1.55 % | 0.930 / 9.60 % | 16 | NOT SUPPORTED |
| **L2** block median | 0.372 | as U | as U | 0.001 / 0.35 % | as U | 16 | NOT SUPPORTED |
| **L4** leave-one-host-out trim | 0.376 | 0.503 / 1.31 % | 0.054 / 1.80 % | 0.015 / 1.73 % | 0.931 / **14.1 %** | 16 | NOT SUPPORTED |
| **L5** = L4 + abstention | 0.126 | 0.503 | abstains | abstains | abstains | 12 | NOT SUPPORTED |

**Calibration research verdict: NOT SUPPORTED.**
- No candidate gains the registered +0.10. The best, L1, gains +0.015 (per fit +0.002 to +0.047),
  recovering 5 % of the T − U gap.
- **Documented-entity R₂₀ change vs U:** 0 for L1, L2 and L4; −4 for L5, all on NF-BoT
  (domain-cluster bootstrap interval [−12, 0]).
- **False alerts per hour:**

  | method | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
  |---|---|---|---|---|
  | U | 295 | 24 | 0.4 | 0.1 |
  | P | 295 | 49 | 16.9 | 0.1 |
  | L1 | 297 | 28 | 1.6 | 0.1 |
  | L4 | 330 | 24 | 1.8 | 0.2 |

**Why the registered candidates did not recover the gap** (corrected after the independent
review; the first draft said no label-free threshold *can* work):
- **NF-ToN and NF-BoT are attack-dominated.** Calibration attackers hold 76 % and 92 % of their
  hold-out windows. That is above the 50 % breakdown point of L2's median, and above what a
  per-host cap of α/2 can absorb once two or more attacker hosts are present.
- **NF-UNSW is contaminated at 29 %, not dominated.** There the failure has more specific causes:
  - L2 never ran: its hold-out has 1 qualifying hour block, under the 5 required, so L2 fell back
    to U;
  - L1 caps all 21 small hosts, which turns it into equal-host weighting.
- **L2 falls back to U on every NF-CIC day as well** (2–3 blocks). It was a real test only on
  NF-ToN (15 blocks) and NF-BoT (17).
- **Criterion (iii) on NF-BoT is failed by U itself** (FPR 9.60 % > P's 7.96 % + 1 pp). Any
  candidate that leaves NF-BoT at U's threshold fails it automatically; L1 and L2 did.
  - NF-BoT's FPR rests on about 2 benign hosts (620 benign windows).
  - The verdicts do not depend on this: criterion (i) fails by a wide margin for every candidate.
- **The decision unit.** Window recall averaged over 6 correlated fits and over the domains
  (equally weighted, from 27 to 2,408 positives), then over 4 networks. No sampling interval
  enters the rule.
- **What is not shown:** that no label-free method could work. Only four threshold estimators were
  tested. A different estimator, or a deployment with sparse contamination, is untested.
- **L5 abstains** exactly on NF-UNSW, NF-ToN and NF-BoT, where evidence (host-hour blocks,
  effective hosts) is insufficient. It reports "unknown", as designed, and fails the coverage
  requirement.

## 2. Experiment G: controlled contamination of the clean P1x hold-out (threshold only)

**Setup:** the domain's own calibration-attacker windows are injected. Evaluation uses the P1x
scores, so the memory is clean. Means are over 6 fits.

**Documented-attacker recall at 0 → 5 → 10 % injected:**

| network / mode | U | L1 | L2 | L4 |
|---|---|---|---|---|
| NF-ToN persistent (one host) | 0.88 → 0.85 → 0.71 | **0.95 → 0.94 → 0.93** | 0.88 → 0.85 → 0.67 | 0.95 → 0.85 → 0.71 |
| NF-ToN spread | 0.88 → 0.55 → 0.44 | 0.95 → 0.55 → 0.50 | 0.88 → 0.55 → 0.37 | 0.95 → 0.74 → 0.54 |
| NF-UNSW persistent | 0.83 → 0.55 → 0.48 | **0.42** → 0.42 → 0.42 | as U | 0.84 → 0.65 → 0.56 |
| NF-UNSW spread | 0.83 → 0.53 → 0.45 | 0.42 → 0.32 → 0.33 | as U | 0.84 → 0.60 → 0.45 |
| NF-BoT | 0.95 throughout | 0.95 | 0.95 | 0.96–0.97 |
| NF-CIC days | unaffected (the injected windows score below T0) | | | |

**FPR without contamination:**

| network | U | L1 | L2 | L4 |
|---|---|---|---|---|
| NF-ToN | 16.5 % | **31.1 %** | 16.5 % | **30.9 %** |
| NF-UNSW | 3.7 % | 2.2 % | 3.7 % | 4.5 % |
| NF-BoT | 8.0 % | 10.1 % | 8.0 % | **55.6 %** |

**Readings:**
- **Breakdown** (registered: the smallest injected fraction at which recall falls by more than 0.10):

  | network / mode | U | L1 | L2 | L4 |
  |---|---|---|---|---|
  | NF-ToN persistent | 10 % | never | 10 % | 10 % |
  | NF-ToN spread | 2 % | 2 % | 2 % | 5 % |
  | NF-UNSW persistent | 1 % | never (already low) | 1 % | 5 % |
  | NF-UNSW spread | 2 % | never (already low) | 2 % | 5 % |

- **The host cap (L1) does what it was built for.** It holds NF-ToN recall against one persistent
  host (0.93 at 10 %). But it lowers the clean threshold: NF-ToN FPR doubles.
  - On NF-UNSW, with 17 small hosts, every host is capped. L1 becomes equal-host weighting, the
    Phase 8p C3 failure, and recall halves even without contamination.
- **The trim (L4) resists spread contamination best** (breakdown at 5 %). It also trims a genuine
  high-scoring benign host on NF-BoT (base r6: 192.168.100.46, 503 of 781 hold-out windows),
  giving FPR 56 %. That is exactly the failure the brief warned against.
- **Where robustness was gained, it was paid for in false alerts** (NF-ToN L1 and L4; NF-BoT L4).
  The opposite also occurs:
  - on NF-UNSW, L1 *lowers* FPR (2.2 % vs 3.7 %) while halving clean recall;
  - L2 changes nothing where it falls back to U.
- **Host sparsity** (SD of the threshold over 20 draws keeping 10 % of hosts):

  | domain | U | L1 | L4 |
  |---|---|---|---|
  | NF-CIC 02-21 | 0.008 | 0.011 | 0.006 |
  | NF-ToN | 0.21 | 0.008 | 0.095 |
  | NF-UNSW | 0.058 | 0.058 | 0.009 |
  | NF-BoT | 0.115 | 0.115 | 0.115 |

  Calibration reliability tracks host diversity.

**Limits:**
- **G does not reach F's regime.** G tops out at 10 % of the clean hold-out. The real unlabelled
  contamination is 11.4 × the clean size on NF-BoT (8,886 vs 781 windows), 3.2 × on NF-ToN and
  41 % on NF-UNSW. G characterises bounded contamination (≤ 10 %) only, and cannot explain F.
- **Mixed semantics:** injected windows are scored under the unlabelled memory.
- **"Gradual" contamination** cannot be distinguished from its total amount for an order-free
  quantile, so it was not run separately.
- **Benign hosts contacting malicious destinations** affect the memory, not the threshold (see
  § 3).

## 3. Exploratory: a label-free memory guard (feature level only; no model scored)

The guard admits a destination to the frozen memory only if ≥ 2 distinct calibration sources
contacted it.

**Share of documented attack windows / benign windows with novelty > 0:**

| domain | P1x (oracle) | U (unlabelled) | F (guard) |
|---|---|---|---|
| NF-CIC 02-14 | 1.00 / 3.3 % | 0.00 / 3.3 % | **1.00** / 5.3 % |
| NF-CIC 02-22 | 1.00 / 3.8 % | 0.00 / 3.8 % | 0.00 / 5.5 % |
| NF-CIC 03-02 | 1.00 / 3.8 % | 0.00 / 3.8 % | 0.005 / 6.7 % |
| NF-UNSW | 1.00 / 0.03 % | 0.00 / 0.0 % | 0.00 / 1.8 % |
| NF-ToN | 0.93 / 27.9 % | 0.36 / 25.0 % | 0.38 / 37.9 % |
| NF-BoT | 0.48 / 2.3 % | 0.01 / 2.1 % | 0.01 / 6.5 % |

- **It restores attack novelty only on 02-14,** where one attacker is the only calibration-period
  contact of its target. Recall on 02-14 needed no restoring: 0.99 even without labels.
- **It fails on 02-22 and 03-02,** the two days that carry the whole NF-CIC memory effect
  (CALIBRATION_DECOMPOSITION § 3).
- **Wherever several attackers share targets** (DDoS, bots, multi-host campaigns) it fails, as the
  Phase 8m guarded memory did.
- **It makes benign windows more novel everywhere.** A scored test is not justified.

## 4. Conclusion

- **The calibration-label dependency is attributed** (CALIBRATION_DECOMPOSITION), as a
  path-dependent decomposition.
- **On these data, none of the registered label-free candidates removed it:**
  - the threshold part fails mainly because NF-ToN and NF-BoT hold-outs are attack-dominated;
  - the memory part fails because the NF-CIC detections on 02-22 and 03-02 rest on destinations
    shared by several labelled sources being absent from memory.
- **The robust estimators help against bounded contamination** (≤ 10 %) of a clean hold-out, at a
  false-alert cost on NF-ToN and NF-BoT.
- **Operation still requires vetted calibration periods.**
