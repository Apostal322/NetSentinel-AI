# Phase 8w: audit of the earlier normalisation attempts

**Purpose.** Establish exactly what "normalising per network" meant in earlier phases, why it
failed, and what was never tested, so that Phase 8w does not rerun a failed method under a new
name.

## 1. What was tried

| phase | method | reference | sign | model | result |
|---|---|---|---|---|---|
| 8b–8h | `B-rz`: the deployed unsupervised score, top-2 mean of \|z\| per host | per host, calibration windows | **unsigned** | none (a rule) | macro oracle recall at 1 % FPR 0.153 |
| 8h | `B-loc`: LightGBM on per-network z-scores | per domain, label-benign calibration windows | **signed** | supervised, leave-one-network-out | Δ recall at 1 % FPR −0.256 [−0.571, +0.039] vs raw features (H1a failed) |
| 8h | `B-lr`: logistic regression on the same z-scores | same | signed | linear | 0.32 on NF-UNSW |
| 8u | `C1`: service-relative columns added to the raw features | per service, source calibration medians | signed | supervised | no hard-network gain |
| 8v | `INV`: drop features whose direction disagrees between source networks | none | n/a | supervised | collapse (macro partial AUC 0.254 → 0.091) |

**`B-loc` precisely** (`scripts/phase8h/lodo.py`, `scripts/phase8b/scorers.py::local_scaler`,
`netsentinel.behavior.temporal.RobustScaler`):

- z = clip((x − median) / max(1.4826 · MAD, floor), −10, 10);
- floor 0.15 for the five fraction features and 0.25 for the others;
- one reference per domain, fitted on that domain's label-benign calibration windows;
- the target domain used **its own label-benign calibration windows**. That needs labels, so it
  was an oracle-assisted reference, not a deployable one.

## 2. Why `B-loc` failed

- It collapsed on NF-CIC 02-20 (LOIC: recall 0.99 → 0.08) and 03-02 (Bot: 1.00 → 0.00), and
  moved NF-UNSW from 0.03 to 0.00.
- A signed z-score is a monotone map of the raw feature inside one network. It fixes the
  *scale* difference between networks and keeps the *direction*. The direction is what conflicts:
  attack windows have more flows than benign ones on three networks and fewer on NF-UNSW
  (Phase 8v: `log_flows` univariate AUC 0.86 / 0.13 / 0.95 / 0.97).
- Centring also removes each network's absolute level. The NF-CIC collapses suggest that level
  was a working cue there; Phase 8h did not test this directly.

## 3. What was never tested

| gap | status before 8w |
|---|---|
| an **unsigned** deviation in a supervised cross-network model | never tested (`B-rz` is unsigned but unsupervised and per host) |
| a **matched null control** (same driver, rows, seeds, column count) | never; Phase 8v's reviewer flagged this (finding B1) |
| **more than one seed** for a per-network normalised representation | never |
| a **deployable** target reference (unlabelled history) for a supervised model | never; `B-loc` used label-benign windows |
| the exact partial AUC at FPR ≤ 1 % and the Phase 8q audited labels | `B-loc` predates both |

## 4. Consequences for the Phase 8w design

- **Signed network-relative z-scores are `B-loc`.** Phase 8w's reference estimator is
  byte-compatible with it (unit test against `RobustScaler`). The signed arm `S` is therefore the
  *historical baseline run through the new driver*, not a new candidate. It is rerun for one
  specific reason: it is the only clean contrast for the unsigned arm (same reference, same rows,
  only the sign removed), and it has never been measured with a null control, several seeds, the
  audited labels or the exact metric.
- **A positive/negative split is not a new arm for a tree model.** Every axis-aligned split on z
  is a split on max(z, 0) or on max(−z, 0) and vice versa (unit test). It is the same hypothesis
  class as `S` and is not fitted.
- **The new mechanism is the unsigned deviation |z|** (`A`): "far from this network's normal, in
  either direction".
- **Risk carried over from 8h:** |z| discards the direction, which is a real cue on some attacks.
  The registered comparison `A` vs `S` measures that cost.
