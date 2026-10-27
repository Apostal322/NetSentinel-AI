# Calibration failure diagnosis (Phase 8f, Mission 1)

- Script: `scripts/phase8f/shift_diagnosis.py`.
- Result: `reports/phase8f/shift_diagnosis.json`.
- **[D]** Development captures only: 22 analysed, CTU-Normal-28 skipped (too few calibration
  windows).
- Deployed scoring (robust per-key median/MAD z, top-2 |z|, cross-fit 1% threshold), clean
  calibration as in Phases 8c–8e.
- Labels are used only to select benign evaluation windows and to measure recall.

## Summary

| factor | finding | evidence |
|---|---|---|
| where the inflation is | concentrated. Pooled device FPR is 2.51%, but **0.35% without NF-UNSW** (21 Zeek captures). NF-UNSW: device 3.4%, global 8.3%, service 5.9%. | pooled LOFO base rates |
| entity composition | **the dominant mechanism.** 385 of 428 device false alerts come from keys seen in calibration with < 30 windows, scored by the pooled fallback; 39 from keys with an own profile; 4 from never-seen keys. | `false_alerts_by_entity` |
| composition across captures | the strongest correlate of the FPR excess: share of evaluation windows from keys never seen in calibration, Spearman ρ = 0.54, p = 0.011, n = 21 (descriptive; no multiple-testing claim) | `fpr_excess_spearman` |
| feature responsible | no single feature. Dropping any one feature changes pooled false alerts by −22 (`med_log_dur`) to +67 (`log_dst_ports`) of 428. The top-|z| feature of false alerts is `log_up_bytes` (76%; NF-UNSW), else `log_down_bytes` (61%) and `med_log_dur` (28%). | LOFO, attribution |
| distribution change | **in the tails, not the medians.** NF-UNSW benign evaluation windows have median z ≈ 0 for every feature, but the \|z\| > 3 rate rises from about 6–7% (held-out) to 8–9%. | `median_z_shift`, `tail_rate_*` |
| service-specific | NF-UNSW: 107 of 118 service false alerts are `no_port` (ICMP and other portless flows). 42-1: `dns` 33, `time_mgmt` 17 (service FPR 14.8%). | `service_false_alerts` |
| traffic intensity | no association with the excess (ρ = 0.05, p = 0.84) | `flow_intensity_shift_z` |
| profile age | no age effect within the evaluation periods (median FPR 0 in both halves; the second half higher in 5 of 21 captures). This does not contradict Phase 8d's pooled hourly bins (1.7% → 2.8%); it says the effect is small next to the composition effect. | `age_first_vs_second_half` |
| calibration sample size | no rank association overall (held-out windows ρ = 0.01; fold-to-fold threshold CV ρ = −0.18). The worst short capture (CTU-Normal-21: 68 held-out windows, 0.2 h evaluation) has a device FPR of 11.1%, consistent with an unreliable threshold. | per capture |
| contamination | **costs recall, not FPR.** Unlabelled calibration raised the device threshold 3.4× on 3-1 (recall 0.51 → 0.003) and took 34-1 from 0.010 to 0; FPR did not rise in any capture. | `contamination` |
| telemetry coverage | no change observable in these data (no windows without byte counts; entities per window 11.7 → 15.1 on NF-UNSW) | `intensity` |
| temporal dependence | the median autocorrelation of global window features falls below 0.2 at lag 2 and below 0.1 at lag 3 (30 s windows) | `global_acf_median_by_lag` |

## Consequences for the design (Missions 2 and 3)

1. **A median- or score-level drift test misses the mechanism.**
   - The calibration-validity assessor needs population-conditional statistics: the share of
     windows scored by the pooled fallback, and per-feature tail rates.
   - Median shifts are not enough.
2. **The alert rate is not used as the drift statistic.** Attacks raise it too (Phase 8d).
   The feature-tail statistics are also attack-sensitive, so any detected shift is reported
   as statistical, never as "benign change".
3. **Block length for permutation tests is 10 windows (5 min).** That is more than 3× the
   lag at which the autocorrelation falls below 0.1.
4. **Recalibration must not learn from unvetted traffic.** Contamination silently removes
   recall, without any FPR symptom an operator would notice.

## Limits

- 22 captures, one of which (NF-UNSW) holds 90% of the false alerts. Every pooled figure is
  sensitive to it, which is why the tables report it separately.
- Spearman correlations are descriptive (n = 21, several candidates); none is a confirmed
  cause.
- The NF-UNSW benign evaluation windows at the global level are the quiet periods without any
  attack flow. Their intensity shift (median z of `log_flows` −17) is a selection effect, not
  evidence of lower traffic.
