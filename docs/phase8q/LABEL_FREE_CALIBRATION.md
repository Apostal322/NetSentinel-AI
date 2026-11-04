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

**Calibration research verdict: NOT SUPPORTED.** No candidate gains the registered +0.10. The
best, L1, gains +0.015, which recovers 5 % of the T − U gap.

**Why no label-free threshold can work here.**
- On NF-ToN and NF-BoT, calibration attackers make up 76 % and 92 % of the hold-out windows; on
  NF-UNSW, 29 % (CALIBRATION_DECOMPOSITION § 3).
- A quantile estimator without labels cannot recover the benign tail of a population that is
  mostly attack, or whose contamination exceeds its breakdown point:
  - the median-based L2: 50 %;
  - the per-host cap L1 against several hosts: k · α/2 ≥ α already at k = 2.
- This is a property of these testbeds, whose attacks run through the calibration period, not
  evidence about deployments with sparse contamination.
- **L5 abstains** exactly on those three networks, where evidence (host-hour blocks, effective
  hosts) is insufficient. It correctly reports "unknown", but fails the coverage requirement.

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
- **The host cap (L1) does what it was built for.** It holds NF-ToN recall against one persistent
  host (0.93 at 10 %). But it lowers the clean threshold: NF-ToN FPR doubles.
  - On NF-UNSW, with 17 small hosts, every host is capped. L1 becomes equal-host weighting, the
    Phase 8p C3 failure, and recall halves even without contamination.
- **The trim (L4) resists spread contamination best.** It also trims NF-BoT's two genuine
  high-scoring benign hosts (FPR 56 %), exactly the failure the brief warned against.
- **Every estimator buys contamination robustness with false alerts** on networks with small or
  heterogeneous benign populations.
- **Host sparsity** (SD of the threshold over 20 draws keeping 10 % of hosts):

  | domain | U | L1 | L4 |
  |---|---|---|---|
  | NF-CIC 02-21 | 0.008 | 0.011 | 0.006 |
  | NF-ToN | 0.21 | 0.008 | 0.095 |
  | NF-UNSW | 0.058 | 0.058 | 0.009 |
  | NF-BoT | 0.115 | 0.115 | 0.115 |

  Calibration reliability tracks host diversity.

**Limits:**
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
  contact of its target.
- **Wherever several attackers share targets** (DDoS, bots, multi-host campaigns) it fails, as the
  Phase 8m guarded memory did.
- **It makes benign windows more novel everywhere.** A scored test is not justified.

## 4. Conclusion

- **The calibration-label dependency is identified** (CALIBRATION_DECOMPOSITION). On these data it
  is **not removable without labels**:
  - the threshold part, because the hold-outs are attack-dominated;
  - the memory part, because the attack signal is the absence of a shared victim from memory.
- **The robust estimators help against bounded contamination** of a clean hold-out, at a
  false-alert cost.
- **Operation still requires vetted calibration periods.**
