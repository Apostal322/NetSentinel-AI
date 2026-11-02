# Phase 8l calibration-reliability formulation, and what history can predict

**Date:** 2026-11-02. Development data only [E]. Phase 8j/8k verdicts are unchanged.

## 1. Four separate tasks

| task | question | information allowed | outcome measured (evaluation only) |
|---|---|---|---|
| **A. Representativeness at decision time** | Is the calibration a fair sample of the network as it was then? | calibration windows: size, hosts, effective hosts, sessions, host shares, within-host dependence, grouped exceedance | none needed: a property of the calibration itself (e.g. PAC feasibility at the dependence-adjusted n_eff) |
| **B. Future failure under drift** | Will the threshold still hold after calibration? | calibration-period **history** only: turnover and drift *inside* the calibration period | realised verified-benign FPR in later blocks |
| **C. Detection on accepted networks** | Where the method operates, is detection useful? | – | recall, entity recall, delay, false alerts per hour |
| **D. Abstention on unsupported networks** | Does it abstain where it should, and only there? | the decisions from A and B | false acceptance and false rejection, coverage; abstained attacks count as missed |

**A calibration-only method cannot see hosts or behaviour that appear later.** B is therefore
answerable only to the extent that history foreshadows the future. Anything else needs
**online, label-free monitoring** of the evaluation traffic, such as unseen-host share or
per-host score shift, which is a different system with its own validation.

## 2. Does history foreshadow the failures? (development check)

**Code:** `scripts/phase8l/drift_history.py`, output `reports/phase8l/drift_history.json`.
It fits nothing; values are 3-seed means.

| domain | turnover inside calibration | turnover in evaluation | seen-host p95 shift inside calibration | seen-host p95 shift in evaluation | top host share, hold-out | top host share, evaluation benign | realised FPR at T0 |
|---|---|---|---|---|---|---|---|
| NF-CIC (6 days) | 0.15–0.19 | 0.17–0.21 | −0.006 to −0.001 | 0.000–0.001 | 0.4–0.5% | 0.4–0.6% | 1.0–1.6% |
| NF-UNSW | 0.045 | 0.000 | −0.044 | −0.006 | 8.8% | 8.8% | 3.7% |
| **NF-ToN-IoT** | **0.787** | 0.304 | −0.003 | 0.000 | 9.3% | **42.5%** | **14.8%** |
| **N4** | 0.013 | 0.008 | −0.012 | **+0.068** | **64.4%** | 52.4% | **11.9%** |

- **Turnover is foreshadowed.** On NF-ToN-IoT, 79% of hold-out windows come from hosts absent
  earlier in the calibration period, against 15–19% on NF-CIC. That historical signal is
  available at decision time, and it would have flagged the network whose failure came from new
  hosts.
  - Its evaluation-period counterpart is less extreme (30%). The point is that the population
    was already unstable.
- **Dominant-host behavioural change is not foreshadowed.** N4's dominant host was stable inside
  calibration (−0.012) and drifted only afterwards (+0.068). What history *does* show is the
  dominance itself (64% of the hold-out), which task A already catches through effective hosts.
- **Small calibration** (NF-UNSW) is a task-A failure, and visible.

**Status:** these are post-hoc observations on 4 networks, the same networks that motivated the
question. They are hypotheses for a future registered test, not evidence. Historical turnover is
the one new decision-time feature with a mechanism behind it.

## 3. Methods worth testing (if the data ever exist)

| method | addresses | task | baseline it must beat |
|---|---|---|---|
| ESS-aware threshold: PAC rank at the dependence-adjusted n_eff (Phase 8j M3 / 8k M2) | small, dependent calibration | A | T0; the fixed checks |
| Source-diversity-aware calibration (host-balanced, capped) | dominant hosts | A | **already negative on development** (window-weighted FPR rises; Phase 8k): not carried |
| Calibration confidence: exact upper bound of the internal exceedance at the effective n | thin evidence | A | PAC feasibility alone |
| **Historical drift risk:** within-calibration turnover (share of the late calibration from hosts new in it) | population turnover | B | no drift check; the fixed checks |
| Temporal validity: an expiry policy (Phase 8i check 4) | ageing | B | no expiry |
| Learned reliability classifier | – | A + B | **not attempted** while independent development networks number < ~20: the Phase 8j attempt was degenerate with 4 |
