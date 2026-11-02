# NetSentinel AI: ML portfolio summary (updated after Phase 8i)

NetSentinel AI is an applied machine-learning research project on network-attack detection
under distribution shift.
- **It is not a production intrusion-detection system.** The software is a local,
  detection-only analysis tool.
- The findings below concern model behaviour on public lab datasets.
- **Nothing here is a new algorithm.** The methods are established. The contribution is the
  evaluation design and the evidence.

## 1. GitHub description (short)

> Applied ML research on network-attack detection under distribution shift: LightGBM and
> robust-statistics detectors on flow windows, pre-registered cross-network evaluations with a
> protected fresh test network, label-budget adaptation, shift-aware abstention and
> representation studies, with documented negative results. Detection-only research prototype
> (Python, polars, LightGBM, scikit-learn).

## 2. Detailed portfolio entry

**Problem.** Flow-based intrusion detectors score near-perfectly inside one dataset and fail on
another network. Over two pre-registered phases (8h, 8i), the project tested seven candidate
remedies, measured against an operational criterion: recall at a threshold calibrated for 1%
false alerts, not ROC-AUC.

**Protocol (Phase 8i):**
- Hypotheses, baselines, selection rules and success/failure criteria were written and
  committed before any model ran. Four amendments were made before the protected test, each
  with its reason recorded.
- **Data separation:** three inspected development networks (NF-CIC-IDS2018, NF-UNSW-NB15,
  NF-ToN-IoT) for all method choices. One never-opened network (NF-BoT-IoT-v3) was held back,
  with a code guard that refused to read it before the freeze.
- **Methods were chosen by pre-stated rules on development data.** The confirmatory code was
  dry-run on a development stand-in. That dry run exposed two unanticipated edge cases, which
  were fixed before the test data was opened.

**What I built and trained:**
- **Label-budget adaptation:** 0, 5, 25 or 100 labelled target attack windows; 20 random draws
  plus a single-attacker variant. Methods:
  - logistic correction on the source score;
  - continued boosting from the source LightGBM (with a verified margin shortcut that avoids
    re-scoring the source trees);
  - a target-only LightGBM.
- **Shift-aware selective prediction:** unsupervised block-level shift scores (score KS,
  feature KS, calibration drift), evaluated against a sample-size baseline with
  domain-bootstrap intervals. Alerts are never suppressed by abstention.
- **Representations:** network-classifier-guided feature removal, relative volume, and a
  network-identity negative control.
- **Analysis:** TreeSHAP attribution with seed-stability checks, a failure taxonomy, and
  post-hoc diagnostics labelled as such.
- **Engineering:**
  - a streaming telemetry-health fix: dropped late records now block normality claims;
  - bounded-memory window construction over 27M flows on an 8 GB machine. Two runs
    exceeded the 3.4 GB budget; the final audit traced them to repeated lazy Parquet scans
    and a large CSV block, bounded both (identical outputs, about 1 GB peaks) and added an
    OS-enforced memory cap;
  - atomic result files and a memory watchdog.

**Results:**
- **Confirmatory, on one fresh network: all three registered remedies failed or were not
  evaluable.**
  - Twenty-five labelled target windows raised recall to 0.92, but at 9.8% false alerts, and
    were not reliably better than no labels.
  - Feature removal did not help (on development data [E], network identity also stayed
    detectable: ROC-AUC 0.98).
  - The deployed detector raised no alerts on the fresh network, so abstention could not be
    tested.
- **Diagnosis:** the binding constraint is threshold calibration, not ranking.
  - **N4 (post-hoc):** every false alert came from one benign host. The benign calibration
    had 2.2 effective hosts and failed its own host-grouped check (64% exceedance), without
    any evaluation labels.
  - **NF-ToN-IoT:** a history-dependent novelty feature drove false alerts (a hypothesis).
- **Exploratory:** with the Phase 8i source setup (a second source network, among other
  changes), zero-label cross-network ROC-AUC on NF-UNSW rose from 0.39 to 0.97. The cause is
  not isolated, and a shared-institution effect is not excluded.
- **Exploratory:** a non-selected variant (logistic correction, 5 labels) reached 0.94 recall
  at 1.3% median false alerts on the fresh network, with a wide spread across label draws.
  It is a lead, not a result: its false alerts rose to 5.5–6.5% with more labels, and its
  2.5th-percentile recall would fail the registered rule.

**What it shows:**
- Turning an open research question into falsifiable, pre-registered tests.
- Leakage-safe data handling, including a protected test set (with one disclosed oracle
  element: benign calibration excludes hosts labelled as attackers in either period).
- Operational metrics instead of ranking metrics.
- Honest reporting of negative results.
- Reproducible CPU-only experimentation under tight memory limits.

**What it does not show:**
- reliable cross-network detection;
- a false-positive guarantee;
- production readiness;
- evidence from more than one fresh network.

## 3. ML Engineer resume entry

**NetSentinel AI: ML for network-attack detection under distribution shift** (Python,
LightGBM, scikit-learn, polars)
- Built leakage-safe flow-window pipelines over about 67M NetFlow records (four datasets) on an 8 GB machine
  (streamed and memory-bounded; an OS-enforced cap added after two runs overran the
  budget). Trained LightGBM, logistic and
  robust-statistics detectors.
- Implemented label-budget domain adaptation (continued boosting, stacking, target-only
  models) and shift-aware selective prediction. Evaluated both at a 1% target
  false-alert threshold, reporting the realised rate.
- Ran a pre-registered evaluation on a protected, never-opened network (code-enforced freeze).
  The remedies failed or were not evaluable. A post-hoc audit traced the false alerts to a
  benign calibration of 2.2 effective hosts that fails a host-grouped check on its own.
- Fixed a streaming telemetry-health gap: dropped late records had left health "ok" while
  10 alerts were lost. Added regression tests.

## 4. Research Engineer summary

- **What I did:** designed and ran two pre-registered phases on cross-network intrusion
  detection, with amendments logged before the protected test, rule-based method selection
  on development data, and an audit trail of every deviation, including resource overruns.
- **Phase 8i findings:**
  - Labels, abstention and feature removal do not fix cross-network detection on the fresh
    network.
  - Calibration on a non-representative benign population is the dominant failure.
  - Removing the most network-identifying features (top 1–3, or the volume group) does not
    remove network identity (ROC-AUC ≥ 0.98).
- **Suggested next work:**
  - a calibration-age study isolating the history-dependent `new_dst_frac` feature;
  - a test network from a different institution, with verified benign hosts.
