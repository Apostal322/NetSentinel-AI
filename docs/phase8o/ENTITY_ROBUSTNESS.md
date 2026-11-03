# Phase 8o H3: attack-entity robustness

**Status:** registered descriptive analysis (PREREGISTRATION § 7).

**Fits:**
- 30 single-member fits: F0 members 0–4 × 6 fits;
- 6 K = 5 fits.

**Entities:** sources with ≥ 5 attack windows in a target domain, 75 in all. Correlated windows
of one entity are never counted as separate units.

**Source:** `reports/phase8o/experiment_d.json` (`H3`). Figures: `entity_recall.png`,
`margin_sensitivity.png`.

## 1. Single models vs the ensemble

| | single members (30 fits) | K = 5 (6 fits) |
|---|---|---|
| entities detected at ≥ 20 % of windows in every fit (R₂₀) | 20 | 40 |
| detected in some fits only (U₂₀) | 26 | 5 |
| never at ≥ 20 % (N₂₀) | 29 | 30 |
| never at even one window (N₁) | 20 | 20 |
| collapses (strong domain with recall < 0.2) | 17 of 180 domain-fits | 0 of 36 |

**The R/U counts above are biased toward the ensemble.** R and U depend on how many fits are
pooled: 30 single-member fits against 6 ensemble fits.

**The fair comparison** uses the same 6 fits per member index (exploratory, post-review):
- single-member U₂₀ is 13–24 (mean 18), against 5 for K = 5;
- the collapse *rate*, 17 of 180 domain-fits (9 %) vs 0 of 36, is comparable across the two.

The single-member fragility is large either way.

## 2. The focus entities (NF-CIC single-attacker days, 03-02 bots)

| entity (windows) | single member: fits ≥ 20 % | single: worst recall | single: median margin | K = 5: fits ≥ 20 % | K = 5: worst recall | K = 5: median margin |
|---|---|---|---|---|---|---|
| 02-14 13.58.98.64 (184) | 23 / 30 | 0.01 | +0.063 | 6 / 6 | 1.00 | +0.099 |
| 02-16 18.219.193.20 (27) | 24 / 30 | 0.00 | +0.045 | 6 / 6 | 0.96 | +0.064 |
| 03-02 bots, 7 hosts (344 each) | 17–18 / 30 | 0.00–0.03 | −0.001 to +0.010 | 6 / 6 | 0.28–0.99 | +0.045 to +0.054 |

*Margin* = median attack-window score − T0, per fit.

**The mechanism:**
- **The attack clusters sit almost on the threshold.** With a single model the median margin is
  0.00–0.06.
- **A small change in the fit moves the whole cluster across T0.** These are the whole-entity flips
  of Phase 8n.
- **Every single-member failure here is a ranking failure** (6–13 per entity). The entity's
  windows are also below the benign 99th percentile, so they are not a threshold artefact. On
  NF-CIC, where FPR ≈ α, the two thresholds are close, so this split is weak there (Phase 8n
  G0.3).
- **Averaging five members does two things:**
  - it raises the margin (+0.045 to +0.10), by averaging away member-specific low scores;
  - it reduces its spread.

  Every focus entity is then detected in all 6 fits. One 03-02 bot still drops to 0.28 in one
  fit.

## 3. Consistently missed entities: representation, not stability

| group | entities | windows each | K = 5 median margin | detection |
|---|---|---|---|---|
| NF-CIC 02-22 web brute force / XSS / SQL injection | 19 of 23 | 5–97 | −0.42 to −0.84 | 0 windows in every fit, single or ensemble |
| NF-CIC 02-20 DDoS LOIC-HTTP | 10 | 8–16 | −0.82 | under 20 % of windows in every fit. K = 5 alerts at least one window in 50–100 % of fits for 9 entities; 1 entity is never alerted |
| NF-ToN 192.168.1.37 | 1 | 168 | −0.30 | ≈ 3 % of windows |

- **These scores lie far below T0 in every fit.** No ensemble or threshold change within the α
  budget detects them. They are ranking (representation) failures, not stability failures.
- **Interpretation, not tested:**
  - **Web attacks** send a few HTTP requests per 30 s window to one web server, which looks like
    benign browsing in the 12 volume, diversity, novelty and flag features.
  - **LOIC-HTTP** is distributed over many external sources, so each source's device window
    carries little volume.

  The sources do contain related families: NF-ToN has XSS, injection and password attacks;
  NF-UNSW has exploits. So "no training support" is not the explanation. A per-device window
  representation is.
- **What would test this:** a per-destination (victim-side) or service-level aggregation. That is
  a feature-representation change, outside this phase.

## 4. Other unstable entities (K = 5)

| entity | fits ≥ 20 % | median recall | median margin |
|---|---|---|---|
| NF-BoT 192.168.100.5 | 3 / 6 | 0.22 | −0.34 |
| NF-BoT 192.168.100.7 | 2 / 6 | 0.19 | −0.20 |
| NF-ToN 192.168.1.193 (3,185 windows) | 4 / 6 | 0.27 | −0.15 |
| NF-UNSW 175.45.176.0–3 (≈ 1,020 windows each) | 6 / 6 | 0.96–0.99 | ≈ +0.27 |

- **NF-BoT and NF-ToN:** the median attack window is below T0, so these detections come from the
  upper tail of a cluster that sits below the threshold.
- **NF-UNSW:** the margin is large, but in stress fits recall drops to 0.26–0.29. The
  host-bootstrap resampling, not the threshold, is what moves them.

**Not computed:**
- per-entity detection-delay variability (network medians: NF-CIC 15 s, NF-UNSW 5 s, NF-ToN 40 s,
  NF-BoT 0 s);
- ground-truth ambiguity beyond the Phase 8i/8j label audits.
