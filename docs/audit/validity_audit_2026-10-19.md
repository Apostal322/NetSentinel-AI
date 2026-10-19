# Validity audit of batch v1/v2 (2026-10-19)

Scope: independent re-checks of temporal causality, split integrity, context-feature
construction, thresholds/calibration, dataset leakage, and the near-zero anomaly recall.
All checks use train/validation rows only; the test split was not read. Scripts:
`scripts/audit/*.py`; raw outputs: `reports/audit/*.json`. Earlier results are preserved
unchanged; corrections are new runs with new names.

## Summary of findings

| # | Severity | Finding | Evidence | Consequence |
|---|---|---|---|---|
| V1 | **Critical** | **Open-set leak through duplicate twin classes.** FTP-BruteForce (family `bruteforce`) and DoS-SlowHTTPTest (family `dos`) are byte-identical traffic (52 shared feature vectors cover >99.99 % of both). Holding out `bruteforce` leaves its twin in training under `dos`, and vice versa. FTP-BF recall is 1.000 when "unseen", SlowHTTPTest 1.000 when "unseen", in every seed and feature set | `runs/*openset*_without_{bruteforce,dos}/per_label_unseen.json` | The bruteforce and dos open-set numbers in report 3.4/3.7 and the README are **inflated**; ~half of each family's rows were effectively seen. GRU open-set (report 3.7, piece A) has the same flaw |
| V2 | High | A **single context feature with no learning** reproduces most unseen-family recall for DoS (`ctx_syn_frac_300s` low: 0.947 vs LightGBM flow+ctx 0.967) and much of DDoS (`ctx_port_flow_rate_30s` high: 0.607 vs 0.66-0.72) | `reports/audit/context.json` | The "generalisation" for these families is largely "the surrounding traffic looks unusual (few SYNs / high per-port rate)", a property tied to these attack tools and CICFlowMeter's flow splitting, not learned attack semantics |
| V3 | High | **Absolute context rates are not comparable across days**: benign flows/hour range 25 k - 616 k (02-20 is the only large untruncated file); on 02-16 / 02-21 benign rows lie mostly inside floods (truncated files), median benign `ctx_flow_rate_300s` 1,543 / 799 vs ~30 elsewhere | `reports/audit/context.json` | Rate features carry capture-specific scale; transfer of thresholds/models to another network is not supported by these results |
| V4 | High | **Context models flag benign flows that co-occur with floods**: validation benign FPR at the frozen threshold is 25 % on 02-16 and 9.5 % on 02-21 for LightGBM flow+ctx, hidden in the aggregate 0.1 % | `reports/audit/thresholds.json` | Flow-level FPR claims for context models must be qualified; incident-level evaluation is needed |
| V5 | High (fixed) | **Robust-z anomaly implementation defect**: scale = MAD with near-constant per-service features -> exploding z, cap at 50 -> 15-19 % of benign validation flows tied at the maximum; the conditioned variant had recall 0 at **every** FPR and flagged only 22 % of rows with 10 features set to 10x the benign maximum | `reports/audit/anomaly.json`, `injection.json` | Fixed (scale floor, no cap; regression test). After the fix: benign share above 99.9 = 0.28 %, injected outliers flagged 88 %. Real-attack detection did **not** improve (ROC-AUC 0.42-0.54): v1's robust-z ROC 0.62-0.63 was partly an artefact of the ties |
| V6 | Medium | **Isolation Forest is insensitive to beyond-range values** as configured (signed-log transform, 512 samples): rows with 10 features at 10x the benign maximum are flagged at 3 % (clean 0.5 %) | `reports/audit/injection_v2.json` | IForest scores here rank "unusual combinations", not range violations; documented limitation, not changed |
| V7 | Medium | "Zero anomaly recall" is mostly the operating point: at FPR 1e-3 recall ~0, but IForest with context reaches 0.41 @ 5e-2 and 0.72 @ 1e-1 (per-label ROC up to 0.96-0.99). Several floods (GoldenEye, LOIC-HTTP) look *more typical* than benign per flow (ROC < 0.5 for robust-z) | `reports/audit/anomaly.json` | Per-flow anomaly detection is not suited to volume attacks at strict FPR; report the full FPR curve |
| V8 | Medium | Operating points rest on few benign rows (57-62 of 63,693 above threshold, ~+-13 % relative uncertainty on FPR). The no-shortcut model's threshold (0.995) sits at the probability ceiling (x2 -> recall 0) | `reports/audit/thresholds.json` | Fragile; recommended: report FPR curves, not single points |
| OK1 | - | Split integrity: split recreated deterministically; no row id in two partitions; minimum gap between partitions >= 300 s on every day | `reports/audit/split_causality.json` | Confirms the protocol as implemented |
| OK2 | - | Context features on 450 **real** rows (3 days) equal a brute-force recomputation from the raw day streams (max relative error < 6e-8, float32) | same | Construction is exact w.r.t. its timing contract. The contract assumes the CIC `Timestamp` is the flow start; this cannot be verified from the CSVs |
| OK3 | - | Within-episode saturation is not only memorisation: 43 % of validation attack rows are exact copies of training rows (flow features; all FTP-BF/SlowHTTPTest), but recall on the novel rows is also 1.000. With context features no row is an exact copy | same | Saturation reflects easily separable traffic, not duplicate leakage |
| OK4 | - | Calibration: isotonic cross-fitted by day gives ECE close to in-sample (0.0000-0.0020) | `reports/audit/thresholds.json` | The bundle's in-sample calibration is not grossly optimistic on validation |

## Uncontaminated open-set evidence (from existing runs, no retraining)

Per-label recall (supervised LightGBM, FPR 1e-3) on labels **without** a twin class in training:

| Held-out | Label | flow (seed 42) | flow+ctx (seeds 42,1,2,3,4) |
|---|---|---|---|
| bruteforce | ssh_bruteforce | 0.008 | 0.997, 0.996, 1.000, 1.000, 0.993 |
| dos | dos_hulk | 0.031 | 0.984, 0.993, 0.980, 0.998, 1.000 |
| dos | dos_goldeneye | 0.440 | 0.750, 0.978, 0.592, 0.786, 0.806 |
| dos | dos_slowloris | 0.078 | 0.086, 0.154, 0.009, 0.024, 0.201 |

## Corrected re-runs (batch v3, measured; `reports/experiments/results_v3.md`)

Behaviour-defined hold-out groups (twins held out together), label cleaning v2, 5 seeds,
benign-validation FPR <= 1e-3, recall mean +- std:

| Held-out group | flow | flow + ctx | flow + scale-invariant ctx |
|---|---|---|---|
| port21_failed_conn (FTP-BF + SlowHTTPTest) | 0.32 +- 0.44 | 0.999 +- 0.002 | 0.999 +- 0.002 |
| ssh_bruteforce | 0.60 +- 0.23 | 0.998 +- 0.003 | 0.999 +- 0.002 |
| dos_http (GoldenEye, Hulk, Slowloris) | 0.05 +- 0.01 | 0.951 +- 0.017 | 0.943 +- 0.010 |
| ddos | 0.11 +- 0.14 | 0.68 +- 0.09 | 0.68 +- 0.12 |
| botnet | 0.25 +- 0.23 | 0.66 +- 0.06 | 0.705 +- 0.004 |
| web_attack | 0.09 +- 0.03 | 0.015 +- 0.008 | 0.07 +- 0.02 |

Per label (flow + ctx): Hulk 0.994, HOIC 1.000, LOIC-UDP 0.98, GoldenEye 0.73 +- 0.18,
LOIC-HTTP 0.37 +- 0.17, Slowloris 0.09 +- 0.09, web attacks <= 0.02. Anomaly-only recall
0.000 for every group and seed.

**Revised conclusions.**
* V1 is corrected: the context-feature gain on unseen groups **survives** the leak-free
  protocol; it was not produced by the twin classes.
* V3 is weakened: scale-invariant context (fractions, shares, surge ratios) performs as well
  as full context, so the effect does not hinge on capture-specific absolute rates.
* V2 stands: the effect concentrates on high-volume / failure-storm traffic (floods, brute
  force, failed connections) and is largely reproducible with single context statistics; low-
  volume application-layer attacks (Slowloris, LOIC-HTTP partly, web attacks) are not detected.
  The accurate claim is "causal context detects anomalous traffic *situations* produced by
  these tools", not "the model generalises to unseen attack semantics".
* Whether this transfers to another network is tested on NetFlow v3 data (next section).

## Corrections planned (require approval for retraining)

1. Open-set with behaviour-defined groups: `port21_failed_conn` (FTP-BF + SlowHTTPTest) held out as its own group; `bruteforce` = SSH only; `dos` = GoldenEye/Hulk/Slowloris; 5 seeds, flow and flow+ctx.
2. Context ablation: scale-invariant context only (fractions, shares, surge ratios) vs absolute rates, in-distribution and open-set.
3. Report full FPR curves (1e-3 ... 1e-1) for supervised and anomaly scores; incident-level FPR for context models.
4. Second dataset with identical features (see roadmap) to test transfer.
