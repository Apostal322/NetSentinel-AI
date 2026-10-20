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
