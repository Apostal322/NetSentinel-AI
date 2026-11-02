# Phase 8m Stage 1: why destination novelty fails

**Source:** `reports/phase8m/novelty_audit.json`, produced by `scripts/phase8m/novelty_audit.py` at 0cb0ad7.
- Runtime: 5,991 s; peak 1.0 GiB under `run_capped`.
- No model was trained or retuned. Every number below is read from that file.

**Labels:**
- **Development part:** EXPLORATORY. It is correlational, on the existing Phase 8j P1x artifacts, and
  these networks were explored in Phases 8b–8k.
- **DEDALE part:** POST-HOC RETROSPECTIVE DIAGNOSTIC on consumed data.
  - It reuses the frozen Phase 8l models and thresholds.
  - It reproduces the confirmatory FPR exactly (0.5525 %), and the script stops if it does not.
  - Nothing here changes the Phase 8l result.

"Novel" means `new_dst_frac > 0`: the window contacts at least one destination missing from the
memory.

## 1. The mechanism, in code

In `src/netsentinel/behavior/windows.py`, `new_dst_frac` uses one global memory of destination IPs.
That memory behaves differently in the two periods:
- **In calibration it expands.** A destination is new only in the first window that contacts it.
- **In evaluation it is frozen** (`known_dst`, which `monitor.py` also uses). Every destination
  first seen after calibration is "new" in every window that touches it, for as long as the
  detector runs.

The model is trained and calibrated on the first meaning and scored on the second. So the feature's
distribution shifts by construction, and the shift grows with time since calibration.

## 2. DEDALE (POST-HOC)

**The asymmetry is visible day by day.** Share of windows that are novel:

| period | first day | last day |
|---|---|---|
| calibration (expanding memory) | 10.5 % (2024-12-23) | 1.6 % (2025-01-03) |
| evaluation (frozen memory) | 8.6 % (2025-01-06) | 27.8 % (2025-01-17) |

In evaluation the share rises almost monotonically: 8.6 → 14.8 → 17.1 → 23.9 → … → 27.8 %.

**Correlation:**
- 88.0 % of the 2,188 false-alert windows (3 seeds pooled) are novel, against 21.5 % of all
  verified-benign windows. That is a lift of 4.1.
- False alerts are spread across hosts: all 26 hosts have some; the top host has 5.9 % and the top
  five have 27 %. This is not one misbehaving machine.

**Contribution (SHAP via LightGBM `pred_contrib`).** These are model attributions, not causal
effects:

| feature | false-alert windows (mean contribution) | benign sample (mean / mean abs) |
|---|---|---|
| `new_dst_frac` | **+1.80** (rank 1) | −0.06 / 0.41 (rank 3) |
| `med_log_dur` | +0.67 | +0.42 / 0.46 |
| `no_reply_frac` | +0.51 | +0.07 / 0.12 |

In false alerts, `new_dst_frac` pushes the score up about 2.7× more than the next feature. In
ordinary benign windows its mean push is slightly negative.

**Counterfactual: `new_dst_frac := 0` in evaluation.** Everything else is unchanged; the models and
T0 stay frozen.

| | as run (Phase 8l) | `new_dst_frac` = 0 |
|---|---|---|
| verified-benign FPR | 0.553 % | 0.065 % |
| false alerts (seed mean) | 1,507 | 176 |
| attack-window recall (43 windows) | 7.0 % | 0.0 % |

- Removing the stale novelty signal would remove about 88 % of the false alerts.
- It would also remove all of the little detection there was.
- 84 % of the attack windows are novel too. Recall is 8.3 % on novel attack windows and 0 % on the
  others.
- So on DEDALE the feature carries both the false alerts and the detection. Simply dropping it is
  not a fix, and this counterfactual is not a deployable feature.

**Alert-rate reconciliation.** Phase 8l's "~200 false alerts a day" was the upper part of the daily
range. The figures from the same run:

| measure | value |
|---|---|
| false alerts per working day with benign windows (10 days) | **151** mean (range 20–251) |
| false alerts per calendar day (14 days) | 108 |
| per active host-hour (2,970 host-hours) | 0.51 |
| per host per working day | 5.8 |

## 3. Development networks (EXPLORATORY)

All values are means over seeds {0, 1, 2}. NF-CIC is the mean of its 6 days.

| network | benign windows | FPR at T0 | P(novel \| false alert) | P(novel), benign | false alerts from hosts unseen in calibration | benign windows from unseen hosts |
|---|---|---|---|---|---|---|
| NF-CIC (6 days) | 79–116 k per day | 1.29 % | 0.39 | 0.043 | 7 % | 18 % |
| NF-ToN-IoT | 7,447 | 14.8 % | **0.99** | 0.28 | **59 %** | 5 % |
| NF-UNSW-NB15 | 11,937 | 3.7 % | 0.007 | 0.000 | 0 % | 0 % |
| NF-BoT-IoT | 620 | 11.9 % | 0.017 | 0.023 | 2 % | 0.1 % |

**Three different failure modes:**

1. **NF-ToN-IoT: stale novelty, as on DEDALE.**
   - Almost every false alert is novel.
   - 59 % come from hosts first seen after calibration, which make up only 5 % of benign windows.
   - FPR depends on calibration age: 0 % in the first 6 h, then 22 % at 6–24 h, where 45 % of
     benign windows are novel.
   - Adaptive memory is aimed exactly at this.
2. **NF-UNSW-NB15: not novelty.**
   - Its frozen calibration memory already covers every evaluation destination: benign novelty is
     0.0 %.
   - Its excess FPR comes from other features.
   - **Prediction recorded before any comparison:** an adaptive-novelty model cannot lower
     NF-UNSW's FPR through the novelty mechanism. The H1 clause that requires a lower FPR on both
     high-FPR networks is therefore expected to fail there (see the PREREGISTRATION amendment).
3. **NF-BoT-IoT: not novelty, and too few benign windows** (620) for a stable FPR.

**NF-CIC.**
- It sits near the α = 1 % budget.
- Novelty is concentrated in false alerts: lift ≈ 10 (5.9–11.3 by day).
- Each day is a single day with 0–6 h of calibration age, so long-horizon staleness cannot appear.

**Detection depends on novelty where attacks contact new destinations.** Attack-window recall,
novel vs not novel:

| network | novel attack windows | non-novel attack windows |
|---|---|---|
| NF-ToN-IoT | 0.79 (6,664 windows) | 0.03 (2,121) |
| NF-CIC 2018-03-02 | 0.36 (2,408) | — |
| NF-CIC 2018-02-22 | 0.10 (842) | — |
| NF-UNSW-NB15 | 0.97 (4,086) | 0.73 (5) |
| NF-BoT-IoT | 0.83 (878) | 0.95 (701) |

This is the contamination risk H2 targets:
- a memory that learns too eagerly can absorb an attacker's destinations;
- it would then lose the NF-ToN-IoT detections that rest on novelty.

## 4. Correlation vs contribution

- **On DEDALE the three views agree:** correlation (lift 4.1), attribution (rank 1, +1.80) and the
  counterfactual (−88 % of false alerts).
- **On the development networks the correlation differs by network.**
  - In NF-ToN-IoT and NF-CIC, false alerts are novelty-rich.
  - In NF-UNSW-NB15 and NF-BoT-IoT they are not.
  - So a single global "novelty causes false alerts" claim is not supported.
  - Attributions are model explanations under a fixed model, and the counterfactual changes one
    input outside its training support. Neither is a causal effect of real traffic.

## 5. What this implies for Stage 2+

1. **The useful target is the semantics of the memory, not the presence of a novelty feature.**
   - Novelty is needed for detection (DEDALE, NF-ToN-IoT).
   - The frozen evaluation memory makes it stale.
2. **The memory must adapt without learning attacker destinations.** Hence the guarded A3 policy: a
   destination is accepted only after ≥ 2 distinct sources with contacts spanning ≥ 1 h, and no
   score or label decides it.
3. **The expected benefit is limited to novelty-driven false alerts:** NF-ToN-IoT clearly, NF-CIC
   modestly, NF-UNSW-NB15 and NF-BoT-IoT not at all. H3's "≥ 3 of 4 networks" clause is therefore
   demanding, and was left unchanged.
