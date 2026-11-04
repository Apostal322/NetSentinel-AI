# Phase 8p Experiment E: victim-side, service-aware and bidirectional models (H1–H3)

**Status:** REGISTERED DEVELOPMENT, on consumed development networks. Nothing here is an
independent confirmation.

**Source:** `reports/phase8p/experiment_e.json` (scripts/phase8p/analyze_e.py).

**Fits:**
- the M2 construction, K = 5;
- replicates r = 6–8, paired with Phase 8o F0, which is the source-only baseline S0;
- base and stress regimes give 6 fits per arm (controls: 3 base fits);
- P1x calibration, T0 at α = 1 %.

**Primary entity set:** the 48 documented attackers (ATTACK_OBSERVABILITY § 2, registered
before results).

**Runs:**
- source arms 24 configurations, peak 2.2 GiB;
- victim arms 9 configurations, peak 2.1 GiB;
- 113 min from the first to the last score file (about 117 min with data loading), against the
  registered estimate of 100–120 min. A mid-run projection of about 140 min, from the slower
  early configurations, was reported to the user and turned out pessimistic.

**Reproduction:** R1, the refit S0, is identical to the Phase 8o F0 member scores on all 27
base fits (max |Δ| = 0.0).

## 1. Results (K = 5; documented-attacker recall / mean false alerts per domain and fit)

| arm | fits | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | macro recall_doc | R₂₀ / U₂₀ / N₂₀ (doc) | collapses |
|---|---|---|---|---|---|---|---|---|
| **S0** source only (= Phase 8o F0) | 6 | 0.807 / 1,216 | 0.835 / 436 | 0.884 / 1,225 | 0.950 / 49 | **0.869** | 37 / 0 / 11 | 0 |
| D2 source + victim context | 6 | **0.182** / 1,040 | 0.919 / 644 | 0.902 / 1,304 | 0.802 / 38 | 0.701 | 18 / 2 / 28 | 16 |
| S1 source + service | 6 | 0.540 / 1,195 | 0.704 / 340 | 0.961 / **2,086** | 0.933 / 48 | 0.785 | 30 / 1 / 17 | 3 |
| D2S source + context + service | 6 | 0.263 / 1,124 | 0.969 / 538 | 0.938 / 1,989 | 0.903 / 104 | 0.768 | 18 / 2 / 28 | 14 |
| D3 late fusion S0 + D1 | 6 | 0.779 / 1,248 | **not operable** (T0 = 1.0; 0 / 0) | 0.877 / 1,204 | 0.928 / **284** | 0.646 (3 networks without NF-UNSW: 0.861 vs S0 0.880) | 32 / 1 / 15 | 6 |
| Sonly control: service only | 3 | 0.000 / 1,059 | 0.253 / 160 | 0.251 / 184 | 0.013 / 0 | 0.129 | 8 / 0 / 40 | 12 |

**All 75 entities** (secondary; includes the 22 undocumented sources), R₂₀ / U₂₀ / N₂₀:
- S0 40 / 5 / 30;
- D2 20 / 9 / 46;
- S1 32 / 5 / 38;
- D2S 21 / 5 / 49;
- D3 36 / 6 / 33;
- Sonly 12 / 0 / 63.

**Macro window recall over all attack windows:** S0 0.762, D2 0.584, S1 0.724, D2S 0.671, D3 0.534, Sonly 0.199.

## 2. Registered decisions: all NOT SUPPORTED; DEVELOPMENT NO-GO

| candidate | guardrails failed | R₂₀,doc change, by network-day | 95 % interval: entity bootstrap / **domain-cluster bootstrap** | paired network-macro change, base fits / stress fits |
|---|---|---|---|---|
| D2 | false alerts NF-UNSW (1.48 ×); recall NF-CIC, NF-BoT; collapses | **−19** (02-21 −10, 03-02 −7, 02-14 −1, 02-16 −1) | [−26, −13] / **[−43, −2]** | −0.22, −0.21, −0.20 / −0.09, −0.19, −0.10 |
| S1 | false alerts NF-ToN (1.70 ×); recall NF-CIC, NF-UNSW; collapses | −7 (03-02 −7, 02-14 −1, NF-ToN +1) | [−12, −2] / **[−22, +2]** | −0.14, −0.11, −0.19 / −0.06, −0.04, **+0.03** |
| D2S | false alerts NF-UNSW, NF-ToN, NF-BoT; recall NF-CIC; collapses | −19 | [−26, −13] / — | −0.16, −0.15, −0.16 / −0.08, −0.14, **+0.08** |
| D3 | false alerts NF-BoT (5.8 ×); recall NF-UNSW; collapses | −5 (NF-UNSW −4, 03-02 −1) | [−10, −1] / **[−13, 0]** | — |

**Reading the uncertainty** (corrected after review):
- **Entities cluster by network-day.** The domain-cluster bootstrap is the defensible interval.
  - S1's and D3's intervals include 0.
  - **The losses are specific clusters, not "significantly worse" in general:** S1 loses the
    seven 03-02 bots, and D2 loses 02-21's HOIC attackers and the 03-02 bots.
- **The paired differences use the rule's own unit,** the mean of 4 network means.
  - Every base fit is negative.
  - In the stress fits, S1 and D2S are positive in r8, the one fit where S0 itself is weak
    (network macro 0.73; S0 ranges 0.73–0.92).
- **The registered 0.03 margin was justified with Phase 8o's paired SD (0.011).** That does not
  describe this phase: S0's own per-fit range is 0.19, so a +0.03 gain could not have been
  resolved with 6 fits.
- **The verdicts do not depend on this.** Every candidate fails a guardrail.

**Verdicts:**
- **H1** (victim context, D2): NOT SUPPORTED.
- **H2** (service, S1): NOT SUPPORTED. Its shortcut control passed: service mix alone carries
  0.129 macro recall, under half of S1's. The service features did not create a port shortcut;
  they also did not help.
- **H3** (fusion, D3): NOT SUPPORTED.
- **No candidate:** the frozen M2 stays the only candidate.

**What the improvements would have needed:**
- **No arm recovers any of the 10 documented 02-20 LOIC attackers** (their evaluation windows are
  the LOIC-UDP onset under the HTTP label). These were the concrete target
  identified in Stage 1.
- **S1 is the only arm that detects NF-ToN 192.168.1.37** at ≥ 20 % in every fit, and only with
  NF-ToN's FPR at 28 % (S0 16.5 %).

## 3. What the victim side does and does not carry

**Ranking vs operation** (oracle ranking recall at the benign 99th percentile; diagnostic only):

| network | S0 | D2 | S1 | D2S |
|---|---|---|---|---|
| NF-CIC | 0.677 | **0.067** | 0.418 | 0.138 |
| NF-UNSW | 0.168 | **0.341** | 0.165 | 0.398 |
| NF-ToN | 0.056 | **0.271** | 0.057 | 0.243 |
| NF-BoT | 0.445 | **0.672** | 0.679 | 0.624 |

- **Victim context does improve ranking near the benign tail on three networks.** That is
  exploratory, a diagnostic with oracle thresholds.
- **It destroys NF-CIC ranking.** NF-CIC AUC falls from 0.78 to 0.66.
- **At the calibrated threshold** the gains turn into false alerts (NF-UNSW 1.48 ×), not
  detections.

**Why NF-CIC collapses** (`reports` numbers; interpretation of mechanism):
- **The context features mostly encode shared-infrastructure fan-in.** Benign clients contact
  busy servers: the median `c_v_log_srcs_max` of benign windows is 1.79–2.40. Attack windows are
  never beyond the benign 99th percentile on any network.
  - The 02-14 SSH attacker is the only source of its victim's window (median 0.69 = ln 2).
- **The NF-CIC model learns from NF-UNSW and NF-ToN,** where the relation between fan-in and
  attack differs. The learned direction does not transfer. This is a dataset-specific
  association, the kind Phase 8p was told to avoid promoting, and the experiment rejected it.

**The victim-only model (D1) on victim windows** (cross-network; 6 fits):

| target | victim-window AUC | recall (≥ 1 attack flow) | FPR |
|---|---|---|---|
| NF-CIC days | **0.30–0.69** (4 of 6 below 0.5 in D1) | 0.00–0.13 | 1.0–1.4 % |
| NF-UNSW | 0.13 | 0.01 | 2.5 % |
| NF-ToN | 0.77 | 0.34 | 2.5 % |
| NF-BoT | 0.89 | 0.67 | 7.4 % |

- **On NF-CIC the transferred victim model ranks attacked servers *below* benign responders,**
  although Stage 1 found those windows perfectly separable *within* NF-CIC.
- **Without the history features (D1h)** the picture is the same.
- **Attributed coverage is uninformative and is never cited as detection.** It reads 1.00 on
  02-20, 02-22 and NF-UNSW, where victim-window recall is 0.13, 0.07 and 0.01. Victim windows
  are mixed (50 % of 02-20's attack victim windows also hold benign flows), and an attacker
  counts as covered if any one of its contacts lands in any alerted window. Victim-host alerts are
  *not* attacker identification.
- **No carry-over from Stage 1.** The perfect in-domain victim-side separation (AUC 1.00 on 02-20)
  does not survive transfer: D1's cross-network AUC is below 0.5 on 02-14, 02-21, 02-22, 03-02 and
  NF-UNSW.

**Complementarity of S0 and D1** (descriptive):
- **Score correlation** on documented attack windows: NF-BoT 0.57, NF-ToN 0.44, NF-UNSW 0.19;
  NF-CIC days −0.26 to +0.28.
- **False-alert overlap** (Jaccard, D3 vs S0): NF-ToN 0.90 (the fusion changes almost nothing),
  NF-CIC 0.43, NF-BoT 0.14 (the fusion adds about 1,450 new false alerts).
  - **On NF-BoT, benign hosts talking to attacked hosts inherit attack-level victim scores:** the
    shared-destination attribution problem.
    - D3's FPR there is 45.9 % (6-fit mean) against α = 1 %.
    - In base r6 (recomputed in the review), 44.5 % of benign evaluation windows alert through
      the victim branch, against 2.1 % through the source branch.
    - All of those have a victim score above every hold-out value: the evaluation-period victim
      scores lie outside what the calibration-period CDF covers.

**A registered-design defect in D3** (found after results; the verdict is unaffected):
- The fusion maps each branch to its hold-out empirical CDF. On NF-UNSW, 10 of 443 hold-out
  windows share the top victim score, so the fused hold-out reaches exactly 1.0 often enough that
  T0 = 1.0. No window can exceed it, giving recall 0 and 0 false alerts.
- The registered unit test used continuous scores and could not catch ties.
- **D3 fails its NF-BoT false-alert guardrail (5.8 ×) independently of this,** so a tie-safe
  fusion would not change the verdict.
  - On the three other networks its macro recall_doc is 0.861 against S0's 0.880.
  - NF-UNSW is reported as "not operable", not as a measured recall of 0.
- **A future fusion needs a tie-aware rank** (mid-ranks, or randomised tie-breaking) **and a
  calibration that covers evaluation-time victim scores.**

## 4. What Phase 8p establishes (and does not)

- **Established, on development data:**
  - neither victim context, service context nor late fusion improves operational detection of
    documented attackers under a shared 1 % budget;
  - victim context's learned direction is network-specific, and it destroys NF-CIC ranking;
  - the 02-20 LOIC attackers remain undetected by every arm.
- **Not established:**
  - **that victim-side information is useless.** It improves ranking near the benign tail on 3
    networks, and it is separable in-domain. What fails is cross-network transfer and
    calibration.
  - anything about web exploits: the documented one is already detected.
- **Correlated units:** the 6 fits share seeds across regimes. NF-CIC days are one network.
  Entity intervals resample entities and ignore their clustering by day.
