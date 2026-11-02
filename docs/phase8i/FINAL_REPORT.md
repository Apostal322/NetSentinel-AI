# Phase 8i final report (draft: results pending)

**Status labels:**
- **[E]:** development, exploratory.
- **[C]:** the single confirmatory evaluation on NF-BoT-IoT-v3.
- Hypotheses, protocols and amendments: [PREREGISTRATION.md](PREREGISTRATION.md).
- Chronology and incidents: [AUDIT_TRAIL.md](AUDIT_TRAIL.md).

## 1. Question

Phase 8h found that supervised flow-window detectors rank attacks almost perfectly within one
network but collapse on another (recall about 1.0 vs 0.03 at a 1%-FPR threshold). Phase 8i asks
whether three remedies help on an unseen network while keeping false alerts near a 1% budget:
- a few labelled target windows (I1);
- a shift score that withdraws unsupported false-alert claims (I2);
- a representation that carries less network identity (I3).

## 2. Data

- **Development** (inspected; [DATASET_AUDIT.md](DATASET_AUDIT.md)):
  - N1 NF-CIC-IDS2018-v3: 11 days, development part.
  - N2 NF-UNSW-NB15-v3: development part.
  - N3 NF-ToN-IoT-v3: 27.5M flows, new to this project's window pipeline. Its network was
    inspected in Phase 8c.
- **Protected test:** N4 NF-BoT-IoT-v3, never opened before the freeze.
- **Windows:** the Phase 8h windows (30 s, per source, 12 features). The NF-CIC and NF-UNSW
  windows are identical to Phases 8h/8b.

## 3. Engineering fix: late records now degrade telemetry health

- **Before:** a record arriving after its window had closed was counted and dropped, but health
  stayed `ok`. In CTU-13 scenario 10, 90 such records (0.0008% of 11.6M) removed 10 alerts
  while the monitor reported healthy telemetry.
- **Now:** the first late record sets the `late_records` flag (severity 1, as
  `buffer_pressure`), and `late_windows` counts the affected windows. The flag reaches the
  assessment ("normality not supported"), the event store, the CLI and the dashboard through
  the existing health path.
- **No rate threshold:** the only measured case shows harm at 0.0008%, and clean replays at an
  adequate lateness produce zero late records.
- **Limitation:** assessments already emitted for the affected windows are not rewritten.
- **Tests:** `test_late_records_degrade_health`, `test_late_flag_ranks_below_integrity_faults`,
  the monitor CLI JSON test, and the pre-8f forgery test, where the loss is now visible.

## 4. Development results [E]

**Setup.**
- Sources are every other development network. Thresholds are split-conformal at α = 1% on
  the target's benign hold-out (T0).
- "Recall" means operational window recall at that threshold, and FPR is the realised rate on
  target benign windows.
- Every number below comes from data inspected in earlier phases, so none of it is evidence
  for a hypothesis.

### 4.1 Experiment A: label budgets (I1)

| unit | attackers | label pool (windows / entities) | n_hold | A0 recall / FPR | A1 recall / FPR | A1 ROC-AUC | A3 Ka25 | A4 Ka25 | A5 Ka25 |
|---|---|---|---|---|---|---|---|---|---|
| NF-CIC 02-14 SSH-BF | 1 | 196 / 1 | 35,221 | 1.000 / 39.7% | 0.996 / 1.33% | 0.996 | 0.995 / 1.59% | 0.995 / 1.48% | 0.989 / 0.80% |
| NF-CIC 02-16 DoS-Hulk | 1 | 107 / 1 | 25,919 | 0.975 / 36.0% | 0.963 / 1.23% | 0.981 | 1.000 / 0.91% | 0.963 / 1.20% | 0.963 / 0.32% |
| NF-CIC 02-20 DDoS-LOIC | 10 | 906 / 10 | 34,741 | 0.091 / 40.3% | 0.085 / 1.30% | 0.225 | 0.085 / 1.03% | 0.085 / 1.14% | 0.009 / 0.53% |
| NF-CIC 02-21 DDoS-HOIC | 10 | 212 / 10 | 36,144 | 0.998 / 41.7% | 0.991 / 1.57% | 0.998 | 0.999 / 0.95% | 0.998 / 1.45% | 0.968 / 0.15% |
| NF-CIC 03-02 Bot | 7 | 1,018 / 8 | 29,131 | 1.000 / 47.4% | 0.357 / 0.99% | 0.976 | 0.999 / 1.98% | 0.986 / 0.97% | 0.978 / 1.16% |
| NF-UNSW | 4 | 937 / 4 | 443 | 0.600 / 2.7% | 0.971 / 3.66% | 0.974 | 0.065 / 0.05% | 0.934 / 1.30% | 0.878 / 0.17% |
| NF-ToN-IoT | 13 | 11,083 / 24 | 4,571 | 0.677 / 19.9% | 0.363 / 14.5% | 0.815 | 0.466 / 1.38% | 0.592 / 10.8% | 0.719 / 4.23% |
| *NF-CIC 02-22 (secondary)* | 291 | 869 / 316 | 35,890 | 0.225 / 39.5% | 0.095 / 1.30% | 0.472 | 0.013 / 0.93% | 0.845 / 1.14% | 0.808 / 0.96% |

- **Column definitions:**
  - A3–A5: median over 20 draws, seed 0 (amendment A3).
  - A0/A1: mean over seeds 0–2.
  - **Network-level medians at Ka = 25:**
    - A4: 0.805 (N1 mean 0.805, N2 0.934, N3 0.592).
    - A5: 0.781.
    - A3: 0.466.
  - Ka = 100 changes little except on NF-ToN-IoT, where A5 rises to 0.83 at 7.0% FPR.

**Findings:**
1. **A target threshold is indispensable.** The source-calibrated threshold (A0) gives 20–47%
   FPR on every network except NF-UNSW. That network's benign scores happen to sit low.
2. **Zero-label transfer is far better than in Phase 8h, for a reason that is not
   adaptation.** NF-UNSW A1: ROC-AUC 0.974, recall 0.971 (FPR 3.7%), against ROC-AUC 0.39 in
   Phase 8h. The difference is the source set: Phase 8h trained on NF-CIC alone, Phase 8i on
   NF-CIC + NF-ToN-IoT. Both NF-UNSW and NF-ToN-IoT were captured at UNSW Canberra, so a
   shared-institution effect cannot be excluded (section 6).
3. **The registered I1 comparison (A4 vs A1) helps where A1 fails, and does nothing where the
   failure is in ranking.**
   - **Gains:**
     - 03-02 Bot: 0.36 → 0.99. A1 was seed-unstable: 0.86 / 0.05 / 0.16.
     - NF-ToN-IoT: 0.36 → 0.59, but still at about 11% FPR.
     - 02-22: 0.10 → 0.85. Its labels mark victims, and the labelled hosts recur in evaluation.
   - **No change:** 02-20 DDoS-LOIC stays at 0.085 at every budget. The source model scores
     those attacks *below* benign (ROC-AUC 0.225), and 50 extra trees on up to 100 labels do
     not reverse that.
4. **Label diversity matters.** With all 25 labels from one attacker, NF-ToN-IoT A4 recall
   falls from 0.59 to 0.33. Its label pool comes from different attack types (scanning,
   DoS/DDoS and injection occur only in the calibration half, per the ingest counts) than its
   evaluation period (password, XSS, backdoor, ransomware, MITM).
5. **A3 (linear correction) is unreliable.** It collapses on NF-UNSW (0.065) while A4 and A5
   stay above 0.87.
6. **FPR control is the binding problem on NF-ToN-IoT.** Its benign hold-out (n = 4,571) does
   not represent the evaluation period: A1 FPR is 14.5%. Every method that keeps its target
   ranking inherits that shift.

### 4.2 Experiment B: shift-aware abstention (I2)

- **Units:** 118 one-hour blocks in 23 domains (deployed robust detector B-rz). 22.9% of blocks
  overran 2% FPR.

| score | block ROC-AUC for overrun | domain-bootstrap 95% CI | exceedance at about 60% coverage |
|---|---|---|---|
| S_score (primary): hold-out vs block score KS | 0.717 | 0.536–0.923 | 12.9% |
| S_feat: median feature KS | 0.709 | 0.559–0.912 | 12.9% |
| S_cal: within-calibration drift | 0.801 | 0.653–0.974 | 7.1% |
| S_n: 1 / n_hold (comparator) | 0.646 | 0.489–0.969 | 21.4% |
| random abstention | 0.5 | — | 22.9% |

- The shift scores beat the sample-size comparator and random abstention. The intervals are
  wide, because most blocks come from few domains.
- **Selected for the test:** τ = 0.70095 (S_score). Under the I2 policy, alerts are never
  suppressed: abstention only withdraws the false-alert budget claim.
- **The source model (A1) is different.** On the 8 cross-network units (76 blocks), S_score is
  uninformative (AUC 0.49), and the sample-size score is the best predictor (0.78).

### 4.3 Experiment C: representations (I3)

| network | raw | C1_k1 | C1_k2 | C1_k3 | C2 relative volume | no volume | B-rz |
|---|---|---|---|---|---|---|---|
| N1 NF-CIC (5 days) recall / FPR | 0.678 / 1.28% | 0.737 / 1.20% | 0.732 / 1.00% | 0.650 / 1.10% | 0.606 / 1.45% | 0.066 / 1.19% | 0.111 / 1.13% |
| N2 NF-UNSW | 0.971 / 3.66% | 0.967 / 3.67% | 0.948 / 3.40% | 0.964 / 4.01% | 0.999 / 4.18% | 0.770 / 1.81% | 0.000 / 0.26% |
| N3 NF-ToN-IoT | 0.363 / 14.5% | 0.289 / 10.7% | 0.139 / 8.2% | 0.050 / 2.0% | 0.071 / 1.68% | 0.003 / 6.15% | 0.958 / 7.35% |
| **mean change vs raw** | — | −0.006 | −0.065 | −0.116 | −0.112 | −0.391 | — |

- **No representation improved cross-network recall on average.**
- The removal ranking comes from source-network classifiers. The removed features vary by fold:
  log_up_bytes and med_log_dur (sources N2+N3), rst_frac and log_down_bytes (N1+N3),
  log_up_bytes and log_dst_ports (N1+N2).
- **Within one network** (NF-CIC leave-one-day-out), C1_k2 and C2 cost at most 0.002 recall.
  The registered rule therefore selected C1_k2 (the less negative gain), with a low prior.
- **Negative control:** a network classifier on benign windows. Its macro ROC-AUC barely
  moves: raw 0.985, C1_k2 0.984, no-volume 0.982. C2 raises it to 1.000. The mechanism was
  not investigated; per-domain centring evidently adds, rather than removes, a
  domain-specific signal.
  **Network identity is spread across all features.** Removing a few does not remove it,
  which explains why C1 cannot work as intended.
- **The deployed robust detector is complementary to the supervised model:** it is the best
  scorer on NF-ToN-IoT (0.958 at 7.4% FPR) and the worst on NetFlow NF-CIC and NF-UNSW.
