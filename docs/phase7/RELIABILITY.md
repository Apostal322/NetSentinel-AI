# Phase 7: reliability fixes

All results here are on data **already inspected** in Phase 6 (CTU captures, NF development
data). They show that software behaviour changed as intended. They are not new confirmatory
evidence of detection quality.

## P1: safe supervised-threat defaults

**Problem (Phase 6, finding F3).** The supervised model's domain check (version 1) accepted
a calibration when the model's flag rate on asserted-benign traffic was <= max(10x its
validation FPR, 1%).
- On the unfamiliar CTU-26 PCAP the model flagged 0.54% of benign calibration flows, 5.4x
  its validation FPR of 0.1%. Version 1 still accepted it.
- Every analysis then escalated its output: 102 false `suspicious` flows in 3.26 h of benign
  traffic.
- The API's `/predict/*` endpoints went further: they returned supervised verdicts on any
  input with no domain consideration at all.

**Why version 1 was wrong.** It tested for "much worse than validation" with a generous floor.
The safe question is the reverse: is there positive evidence that the network resembles the
training data? Without that evidence the supervised output must not be authoritative.

**Fix.**
- **Default policy `unverified`** on every path: `analyze`, `serve`/API (including
  `/predict/flow` and `/predict/batch`), the dashboard and the env/compose defaults.
  - Supervised scores are still reported (`threat.probability`, `threat.is_suspicious`), but
    `threat_status = unverified_domain` and the verdict is never `suspicious` or `attack`
    because of them.
  - Anomaly reporting is unchanged.
  - With neither a baseline nor a trusted model, the verdict is `insufficient_data`, never
    `benign`.
- **Policy `auto`** escalates only if the calibration ran domain check **version 2**, for the
  same bundle, and it passed. Version 2 passes only if all of these hold:
  - vetted-benign calibration;
  - enough flows (expected flags at the validation FPR >= 10, i.e. >= 10,000 flows at FPR
    1e-3);
  - an exact one-sided binomial test does not reject "flag rate <= 2x validation FPR"
    (alpha = 0.01).
  - Version 1 checks are never trusted.
- **Policy `trust`** is an explicit operator assertion, e.g. replaying the model's own
  training dataset. Policy `unsupported` never escalates.
- **Replay** (`netsentinel replay`, `/replay/*`) still uses the engine directly. It replays
  the bundle's own recorded training-domain data, and is documented as an in-domain
  demonstration.

**Regression tests.**
- `tests/unit/test_threat_policy.py`: 14 tests. Default policy; mode resolution for every
  policy/check combination, including old version-1 checks, other bundles and insufficient
  flows; no escalation under unverified/unsupported for any behaviour state; the
  no-baseline/no-trusted-model case gives `insufficient_data`; and version 2 on the exact
  CTU-26 numbers (6,835 flows, 37 flags).
- Integration tests: `analyze` and the API now default to `unverified_domain`, with no
  `suspicious` verdicts.

**Effect on the same CTU-26 PCAP** (`reports/phase7/`; same calibration period and cut):

| Configuration | benign | unusual | suspicious | threat_status |
|---|---|---|---|---|
| Phase 6 (policy auto, check v1) | 10,214 | 117 | **102** | assessed |
| Phase 7 default (unverified) | 10,309 | 124 | **0** | unverified_domain |
| Phase 7 `--threat-policy auto` (check v2: `insufficient_flows`, p = 1.3e-7 against the 2x FPR null) | 10,309 | 124 | 0 | unverified_domain |

The 7 flows that were both `suspicious` and behaviour-anomalous are now reported as
`unusual`.

**Not addressed.** Whether the supervised model would be useful on any network other than
its training data. Phase 5 says no, and nothing here changes that.

## P2: calibration reliability

**Diagnosis** (`scripts/phase7/diagnose_calibration_drift.py` ->
`reports/phase7/calibration_drift.json`; exploratory, the same CTU captures as Phase 6 H1).
- With Phase 6 split thresholds, the **global level had a median of only 63 held-out windows**.
  At a 1% target the threshold is then the largest held-out score, and its true exceedance
  probability is Beta(1, n): 95% bound about 3/n, i.e. 4–8% for n = 36–73.
- 11 of 12 evaluation FPRs lie **within that sampling bound**, and evaluation FPR does not
  correlate with calibration-vs-evaluation score drift (r = -0.19).
- The H1 FPR misses were therefore mostly small-sample threshold noise, not traffic change.
  Phase 6's explanation ("within-capture drift") was only partly right.
- The drift monitor flagged 4 of the 5 over-target captures.

**Changes.**
1. **Threshold diagnostics** (`profile.threshold_diagnostics`), recorded per level in every
   artifact: n, the order statistic used, expected FPR, the 95% upper bound, and the number of
   windows needed for a bound <= 2x target. Unreliable thresholds raise a warning.
2. **`baseline_provisional` status**: thresholds exist but the global bound exceeds 2x target.
   Alerting stays on, and the status is shown in behaviour outputs and the dashboard.
3. **Time-blocked cross-fitted thresholds** (`--threshold-method crossfit`, new default).
   - Every calibration window is scored by statistics fit on the other 4 of 5 contiguous
     time blocks. That is about 3.3x more held-out scores, and the final profile uses all
     windows.
   - `split` remains available, and Phase 6 scripts pin it so their results reproduce.
   - Exchangeability across blocks is assumed; strong drift violates it.
4. **Drift test**: `baseline_state` now uses a one-sided binomial test of the alert count
   against the target (alert rate > 2x target and p < 0.01), alongside the score
   distribution check (KS > 0.3).
5. **Contamination warning**: more than 5% robust-outlier windows among held-out scores
   produce a warning. Unlabelled mode still warns that persistent malicious behaviour can be
   learned as normal.
6. **Safe updates and rollback** (`behavior/registry.py`; `netsentinel calibration
   list|show|activate|rollback`; `calibrate --previous active --activate`; `analyze`/`serve
   --calibration active`).
   - A new calibration period is scored under the active baseline. If it is significantly
     anomalous (binomial test), the artifact is marked `review_required` and can only be
     activated with an explicit `--reviewed`. That is the guard against silently re-learning
     attack traffic.
   - History is append-only. Rollback re-activates the previous profile.
   - There is still no online learning.

**Effect** (exploratory; same data).

| | split (Phase 6) | crossfit (Phase 7 default) |
|---|---|---|
| CTU, median held-out windows (global) | 63 | 208.5 |
| CTU, captures with global FPR <= 3x target | 7/12 | **12/12** (median FPR 0) |
| CTU, FPRs within their own sampling bound | 11/12 | 12/12 |
| IoT-23 (oracle-clean), global recall 3-1 / 34-1 / 44-1 / 8-1 | 0.97 / 0.45 / 1.0 / 0.97 | 0.52 / 0.27 / 0.5 / 0.97 |
| IoT-23 (oracle-clean), device recall 3-1 / 34-1 / 8-1 | 0.71 / 0.45 / 0.03 | 0.51 / 0.01 / 0.83 |

(`reports/phase7/threshold_methods_iot23.json`.) Cross-fitting makes the false-positive
promise of calibration hold on these captures, **at a recall cost in several IoT-23
scenarios**, with a gain in one. It is the default because calibration's job is FPR
control. This is not a detection improvement, and none is claimed. All of these numbers are
on data already inspected; an independent evaluation would need new captures.

**Tests:** `tests/unit/test_calibration_reliability.py` (5 tests):
- diagnostics maths, at the Phase 6 held-out size;
- cross-fit scores every window;
- provisional status on short history;
- contamination and trimming warnings;
- update check, activation refusal, review override, rollback and missing registry.

## P3: conservative application-protocol policy

**Failure analysis** (CTU logs, already inspected; Zeek `service` as reference). Of 27,983
Zeek-labelled HTTP flows (port 80), the portable ML model called **15,115 TLS, at a median
confidence of 0.97**. Wrong predictions were confident (median 0.97, 90th percentile 1.00),
so the validation-chosen confidence threshold almost never abstained (Phase 6 H7). The cause:
- the portable feature set sees only a coarse port class (well-known / registered /
  dynamic), so it cannot tell 80 from 443;
- long HTTP transfers (median 21 response packets) resemble TLS in flow shape.

**Policy** (`appintel/model.py::resolve_policy`, artifact schema `appintel-1.1.0`).
- A (protocol, dst port) pair is *port-supported* if NF-IDS2018 **training** flows map it to
  one label with purity >= p and support >= n. The table has 14,324 entries, stored inside
  the artifact.
- ML and port agree: label, `app_method = ml_port_agree`.
- They conflict: `port_ml_conflict`, no label. The variant `conflict=port` would output the
  port label as `port_estimate` instead.
- No port support: the ML label only if the ML did not abstain (`app_method = ml`).
- Every flow carries `app_evidence` (the ML class with its confidence, and the port
  statistics) and `app_ml_class`.
- `application_identity` stays null: this is protocol recognition, not application
  identification.

**Selection** (`scripts/phase7/select_app_policy.py` -> `reports/phase7/app_policy_selection.json`;
development data only).
- Pre-stated rule: on NF-IDS2018 validation A, coverage >= 0.95, maximise accepted accuracy.
- Grid: purity {0.90, 0.95, 0.99} x support {50, 200} x conflict {port, unknown}.
- Chosen: **purity 0.90, support 50, conflict -> unknown**. The 12 candidates differ by at
  most 0.0008 accepted accuracy on validation A.

| Policy | NF-IDS2018 val B: coverage / accepted acc. | NF-UNSW val B (shared classes): coverage / accepted acc. |
|---|---|---|
| ML only (Phase 6) | 0.997 / 0.988 | 0.991 / **0.519** |
| port lookup only | 0.939 / 0.966 | 0.856 / 0.990 |
| **chosen policy** | 0.993 / **0.992** | 0.660 / **0.779** |

On the other dataset the policy turns confident ML errors into abstentions: accepted
accuracy rises from 0.52 to 0.78, at the cost of 34% coverage. Port lookup alone is even
more accurate there (0.99), because UNSW's shared classes sit on standard ports.

**Descriptive check on CTU** (already inspected; parameters were *not* chosen on it;
`reports/phase7/ctu_app_policy_descriptive.json`): coverage 0.926, accepted accuracy 0.9987,
vs ML-only 0.925 at full coverage and the port rule 0.999. On standard-port traffic the
policy is in effect a port lookup confirmed by the ML. The ML contributes only where no port
evidence exists. Phase 6's H7 verdict (not supported) stands, and nothing here is a new
confirmatory claim.

**Product artifact:** `models/appintel/appid-portable-20261020T184500Z` (same model weights
as the Phase 6 artifact, plus the port table and policy). Phase 6 artifacts (schema 1.0.0)
still load and run ML-only.

**Tests:** `tests/unit/test_appintel.py`:
- agreement / conflict / no-support / low-confidence / unsupported cases;
- both conflict modes;
- port-table purity and support;
- backward-compatible loading of 1.0.0 artifacts.
