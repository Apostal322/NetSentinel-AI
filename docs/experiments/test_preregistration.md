# Test-set pre-registration (written before any test-set access)

Date: 2026-10-19. Written after batch v1 validation results, before running
`netsentinel evaluate --final` on any run. The test split of each run below is evaluated
exactly once; no model, feature set, threshold or hyper-parameter is changed afterwards on the
basis of test results.

| Role | Run | Why this run |
|---|---|---|
| Threat, default features | `20261019-124619_baseline_binary_lightgbm` | Strongest simple model family on validation; flow-only features work for single-flow API calls |
| Threat, no shortcut fields | `20261019-124729_baseline_binary_flow_noshortcut_lightgbm` | Robustness check: performance without the four known collection-artefact fields |
| Threat, with temporal context | `20261019-125018_baseline_binary_flow_ctx_lightgbm` | Context variant used for replay |
| Attack type (label) | `20261019-125356_multiclass_label_flow_lightgbm` | Flow-only type model (avoids the day-identity artefact of context for type labels) |

Thresholds: frozen validation thresholds stored in each run (weighted benign FPR <= 1e-3).

Known limitations of the test split (from `split_coverage.csv`): DoS-Hulk, HOIC (validation),
GoldenEye and several web-attack labels have few or no test rows; per-label results are
reported only where test rows exist.
