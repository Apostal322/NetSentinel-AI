# Final NF-v3 evaluation (pre-registered, one-shot)

Pre-registration: `docs/experiments/final_preregistration_nf.md` (commit 47d0817). Test rows = test under both the episode and chronological protocols. Recall: mean over seeds (per-seed values, order 42,1,2); CI = 95% block bootstrap of the first listed seed; FA/h = false-alert flows per hour.

## NF-UNSW in-domain (3 seeds)

Test rows 39151, attack rows 20621, 3.25 h; labels {'exploits': 5426, 'dos': 857, 'backdoor': 1238, 'benign': 18530, 'generic': 3602, 'worms': 24, 'analysis': 269, 'fuzzers': 5738, 'reconnaissance': 3172, 'shellcode': 295}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0010 | 81 | 1.000 |
| clean_1000 | source_model_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0038 | 303 | 1.000 |
| clean_1000 | normalized_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0045 | 361 | 1.000 |
| clean_1000 | robust_subset_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0027 | 230 | 1.000 |
| clean_1000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.000) | [0.001, 0.001] | 0.0003 | 27 | 0.906 |
| clean_1000 | target_iforest_flow | 0.018 (0.035, 0.019, 0.000) | [0.014, 0.065] | 0.0009 | 78 | 0.929 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 76 | 0.558 |
| clean_1000 | target_autoencoder_flow | 0.206 (0.272, 0.302, 0.043) | [0.218, 0.328] | 0.0003 | 27 | 0.944 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.048 (0.067, 0.076, 0.000) | [0.044, 0.091] | 0.0003 | 28 | 0.799 |
| clean_1000 | target_autoencoder_all | 0.062 (0.098, 0.088, 0.000) | [0.062, 0.143] | 0.0011 | 91 | 0.938 |
| clean_10000 | source_model_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0008 | 64 | 1.000 |
| clean_10000 | normalized_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0012 | 100 | 1.000 |
| clean_10000 | robust_subset_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0014 | 119 | 1.000 |
| clean_10000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0009 | 70 | 0.885 |
| clean_10000 | target_iforest_flow | 0.017 (0.019, 0.016, 0.016) | [0.006, 0.042] | 0.0009 | 80 | 0.934 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.562 |
| clean_10000 | target_autoencoder_flow | 0.833 (1.000, 0.749, 0.749) | [1.000, 1.000] | 0.0006 | 52 | 1.000 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.152 (0.364, 0.001, 0.092) | [0.317, 0.408] | 0.0007 | 59 | 0.981 |
| clean_10000 | target_autoencoder_all | 0.749 (0.750, 0.749, 0.749) | [0.697, 0.798] | 0.0008 | 67 | 0.998 |
| clean_50000 | source_model_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0009 | 74 | 1.000 |
| clean_50000 | normalized_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0014 | 120 | 1.000 |
| clean_50000 | robust_subset_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0014 | 117 | 1.000 |
| clean_50000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0005 | 42 | 0.885 |
| clean_50000 | target_iforest_flow | 0.014 (0.024, 0.017, 0.002) | [0.009, 0.049] | 0.0007 | 61 | 0.934 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.565 |
| clean_50000 | target_autoencoder_flow | 0.917 (1.000, 1.000, 0.752) | [1.000, 1.000] | 0.0004 | 35 | 1.000 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.625 (0.916, 0.916, 0.043) | [0.904, 0.927] | 0.0003 | 27 | 0.999 |
| clean_50000 | target_autoencoder_all | 0.751 (0.755, 0.750, 0.749) | [0.701, 0.803] | 0.0005 | 46 | 1.000 |
| unlabelled_50000 | source_model_target_threshold | 0.011 (0.007, 0.011, 0.016) | [0.003, 0.013] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | normalized_target_threshold | 0.011 (0.011, 0.007, 0.014) | [0.002, 0.025] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | robust_subset_target_threshold | 0.011 (0.011, 0.013, 0.008) | [0.005, 0.017] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0005 | 42 | 0.885 |
| unlabelled_50000 | target_iforest_flow | 0.011 (0.009, 0.014, 0.008) | [0.001, 0.026] | 0.0005 | 42 | 0.941 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.546 |
| unlabelled_50000 | target_autoencoder_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.002] | 0.0006 | 51 | 0.837 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.005 (0.011, 0.003, 0.002) | [0.003, 0.026] | 0.0004 | 29 | 0.857 |
| unlabelled_50000 | target_autoencoder_all | 0.001 (0.001, 0.001, 0.000) | [0.001, 0.001] | 0.0007 | 57 | 0.742 |

## NF-IDS2018 in-domain (3 seeds)

Test rows 21408, attack rows 5910, 8.00 h; labels {'web_bruteforce': 1, 'benign': 15498, 'bot': 5890, 'web_sql_injection': 19}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0006 | 36 | 1.000 |
| clean_1000 | source_model_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0015 | 94 | 1.000 |
| clean_1000 | normalized_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0015 | 88 | 1.000 |
| clean_1000 | robust_subset_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0010 | 66 | 1.000 |
| clean_1000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.385 |
| clean_1000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0026 | 174 | 0.899 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0015 | 101 | 0.477 |
| clean_1000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0023 | 151 | 0.506 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0037 | 233 | 0.491 |
| clean_1000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0044 | 288 | 0.475 |
| clean_10000 | source_model_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0015 | 91 | 1.000 |
| clean_10000 | normalized_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0014 | 87 | 1.000 |
| clean_10000 | robust_subset_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0008 | 51 | 1.000 |
| clean_10000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0003 | 24 | 0.415 |
| clean_10000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0007 | 48 | 0.901 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0010 | 62 | 0.486 |
| clean_10000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 65 | 0.889 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0013 | 89 | 0.918 |
| clean_10000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0031 | 198 | 0.900 |
| clean_50000 | source_model_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0014 | 85 | 1.000 |
| clean_50000 | normalized_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0018 | 114 | 1.000 |
| clean_50000 | robust_subset_target_threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.0009 | 55 | 1.000 |
| clean_50000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0004 | 30 | 0.427 |
| clean_50000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0008 | 51 | 0.911 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0006 | 42 | 0.483 |
| clean_50000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0008 | 54 | 0.930 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 60 | 0.965 |
| clean_50000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0030 | 192 | 0.942 |
| unlabelled_50000 | source_model_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0004 | 30 | 0.411 |
| unlabelled_50000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0003 | 23 | 0.774 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0018 | 113 | 0.454 |
| unlabelled_50000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0032 | 195 | 0.740 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0028 | 191 | 0.942 |
| unlabelled_50000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0036 | 231 | 0.915 |

## NF-IDS2018 -> NF-UNSW, nf_flow_ctx (3 seeds)

Test rows 39151, attack rows 20621, 3.25 h; labels {'benign': 18530, 'reconnaissance': 3172, 'backdoor': 1238, 'worms': 24, 'analysis': 269, 'exploits': 5426, 'fuzzers': 5738, 'dos': 857, 'generic': 3602, 'shellcode': 295}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 0.254 (0.346, 0.272, 0.143) | [0.294, 0.390] | 0.3519 | 29076 | 0.417 |
| clean_1000 | source_model_target_threshold | 0.002 (0.004, 0.001, 0.000) | [0.003, 0.005] | 0.0014 | 122 | 0.417 |
| clean_1000 | normalized_target_threshold | 0.000 (0.000, 0.001, 0.000) | [0.000, 0.000] | 0.0230 | 1953 | 0.286 |
| clean_1000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0092 | 803 | 0.380 |
| clean_1000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.000) | [0.001, 0.001] | 0.0003 | 27 | 0.906 |
| clean_1000 | target_iforest_flow | 0.018 (0.035, 0.019, 0.000) | [0.014, 0.065] | 0.0009 | 78 | 0.929 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 76 | 0.558 |
| clean_1000 | target_autoencoder_flow | 0.206 (0.272, 0.302, 0.043) | [0.218, 0.328] | 0.0003 | 27 | 0.944 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.048 (0.067, 0.076, 0.000) | [0.044, 0.091] | 0.0003 | 28 | 0.799 |
| clean_1000 | target_autoencoder_all | 0.062 (0.098, 0.088, 0.000) | [0.062, 0.143] | 0.0011 | 91 | 0.938 |
| clean_10000 | source_model_target_threshold | 0.002 (0.004, 0.001, 0.001) | [0.003, 0.006] | 0.0018 | 154 | 0.417 |
| clean_10000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0216 | 1836 | 0.295 |
| clean_10000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0140 | 1180 | 0.385 |
| clean_10000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0009 | 70 | 0.885 |
| clean_10000 | target_iforest_flow | 0.017 (0.019, 0.016, 0.016) | [0.006, 0.042] | 0.0009 | 80 | 0.934 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.562 |
| clean_10000 | target_autoencoder_flow | 0.833 (1.000, 0.749, 0.749) | [1.000, 1.000] | 0.0006 | 52 | 1.000 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.152 (0.364, 0.001, 0.092) | [0.317, 0.408] | 0.0007 | 59 | 0.981 |
| clean_10000 | target_autoencoder_all | 0.749 (0.750, 0.749, 0.749) | [0.697, 0.798] | 0.0008 | 67 | 0.998 |
| clean_50000 | source_model_target_threshold | 0.002 (0.005, 0.001, 0.001) | [0.003, 0.006] | 0.0020 | 172 | 0.417 |
| clean_50000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0213 | 1808 | 0.297 |
| clean_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0076 | 659 | 0.393 |
| clean_50000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0005 | 42 | 0.885 |
| clean_50000 | target_iforest_flow | 0.014 (0.024, 0.017, 0.002) | [0.009, 0.049] | 0.0007 | 61 | 0.934 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.565 |
| clean_50000 | target_autoencoder_flow | 0.917 (1.000, 1.000, 0.752) | [1.000, 1.000] | 0.0004 | 35 | 1.000 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.625 (0.916, 0.916, 0.043) | [0.904, 0.927] | 0.0003 | 27 | 0.999 |
| clean_50000 | target_autoencoder_all | 0.751 (0.755, 0.750, 0.749) | [0.701, 0.803] | 0.0005 | 46 | 1.000 |
| unlabelled_50000 | source_model_target_threshold | 0.002 (0.004, 0.001, 0.001) | [0.002, 0.005] | 0.0017 | 144 | 0.417 |
| unlabelled_50000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0218 | 1849 | 0.281 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0181 | 1590 | 0.387 |
| unlabelled_50000 | target_robust_z_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0005 | 42 | 0.885 |
| unlabelled_50000 | target_iforest_flow | 0.011 (0.009, 0.014, 0.008) | [0.001, 0.026] | 0.0005 | 42 | 0.941 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.546 |
| unlabelled_50000 | target_autoencoder_flow | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.002] | 0.0006 | 51 | 0.837 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.005 (0.011, 0.003, 0.002) | [0.003, 0.026] | 0.0004 | 29 | 0.857 |
| unlabelled_50000 | target_autoencoder_all | 0.001 (0.001, 0.001, 0.000) | [0.001, 0.001] | 0.0007 | 57 | 0.742 |

## NF-IDS2018 -> NF-UNSW, nf_portable_ctx (3 seeds)

Test rows 39151, attack rows 20621, 3.25 h; labels {'benign': 18530, 'reconnaissance': 3172, 'fuzzers': 5738, 'generic': 3602, 'worms': 24, 'exploits': 5426, 'dos': 857, 'analysis': 269, 'shellcode': 295, 'backdoor': 1238}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 0.067 (0.081, 0.068, 0.052) | [0.064, 0.101] | 0.3526 | 29548 | 0.366 |
| clean_1000 | source_model_target_threshold | 0.009 (0.007, 0.006, 0.013) | [0.005, 0.010] | 0.0005 | 45 | 0.366 |
| clean_1000 | normalized_target_threshold | 0.002 (0.003, 0.002, 0.001) | [0.001, 0.005] | 0.0235 | 1977 | 0.390 |
| clean_1000 | robust_subset_target_threshold | 0.004 (0.011, 0.000, 0.000) | [0.004, 0.019] | 0.0022 | 185 | 0.378 |
| clean_1000 | target_robust_z_flow | 0.008 (0.000, 0.023, 0.000) | [0.000, 0.000] | 0.0003 | 20 | 0.706 |
| clean_1000 | target_iforest_flow | 0.049 (0.047, 0.099, 0.000) | [0.025, 0.072] | 0.0006 | 51 | 0.956 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 76 | 0.558 |
| clean_1000 | target_autoencoder_flow | 0.041 (0.053, 0.069, 0.001) | [0.032, 0.079] | 0.0006 | 48 | 0.725 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.041 (0.053, 0.069, 0.001) | [0.032, 0.079] | 0.0006 | 48 | 0.725 |
| clean_1000 | target_autoencoder_all | 0.001 (0.001, 0.000, 0.000) | [0.000, 0.001] | 0.0015 | 130 | 0.644 |
| clean_10000 | source_model_target_threshold | 0.007 (0.006, 0.007, 0.008) | [0.004, 0.009] | 0.0003 | 27 | 0.366 |
| clean_10000 | normalized_target_threshold | 0.002 (0.002, 0.002, 0.001) | [0.001, 0.004] | 0.0180 | 1503 | 0.386 |
| clean_10000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0020 | 168 | 0.393 |
| clean_10000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.571 |
| clean_10000 | target_iforest_flow | 0.064 (0.081, 0.051, 0.061) | [0.044, 0.114] | 0.0013 | 114 | 0.962 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.562 |
| clean_10000 | target_autoencoder_flow | 0.208 (0.168, 0.307, 0.148) | [0.128, 0.202] | 0.0011 | 89 | 0.975 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.208 (0.168, 0.307, 0.148) | [0.128, 0.202] | 0.0011 | 89 | 0.975 |
| clean_10000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.001] | 0.0008 | 64 | 0.738 |
| clean_50000 | source_model_target_threshold | 0.005 (0.001, 0.006, 0.008) | [0.001, 0.002] | 0.0003 | 23 | 0.366 |
| clean_50000 | normalized_target_threshold | 0.002 (0.002, 0.002, 0.001) | [0.001, 0.004] | 0.0185 | 1542 | 0.384 |
| clean_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0017 | 142 | 0.391 |
| clean_50000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.568 |
| clean_50000 | target_iforest_flow | 0.030 (0.042, 0.035, 0.013) | [0.013, 0.077] | 0.0007 | 55 | 0.961 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.565 |
| clean_50000 | target_autoencoder_flow | 0.189 (0.128, 0.372, 0.066) | [0.095, 0.159] | 0.0004 | 31 | 0.989 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.189 (0.128, 0.372, 0.066) | [0.095, 0.159] | 0.0004 | 31 | 0.989 |
| clean_50000 | target_autoencoder_all | 0.010 (0.026, 0.002, 0.003) | [0.004, 0.051] | 0.0007 | 58 | 0.810 |
| unlabelled_50000 | source_model_target_threshold | 0.005 (0.003, 0.005, 0.006) | [0.002, 0.005] | 0.0001 | 8 | 0.366 |
| unlabelled_50000 | normalized_target_threshold | 0.002 (0.002, 0.003, 0.000) | [0.001, 0.004] | 0.0115 | 967 | 0.394 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0020 | 169 | 0.387 |
| unlabelled_50000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.565 |
| unlabelled_50000 | target_iforest_flow | 0.008 (0.005, 0.013, 0.007) | [0.001, 0.013] | 0.0005 | 41 | 0.913 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.546 |
| unlabelled_50000 | target_autoencoder_flow | 0.005 (0.006, 0.005, 0.003) | [0.003, 0.011] | 0.0001 | 9 | 0.930 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.005 (0.006, 0.005, 0.003) | [0.003, 0.011] | 0.0001 | 9 | 0.930 |
| unlabelled_50000 | target_autoencoder_all | 0.001 (0.001, 0.001, 0.001) | [0.001, 0.001] | 0.0003 | 25 | 0.776 |

## NF-UNSW -> NF-IDS2018, nf_flow_ctx (3 seeds)

Test rows 21408, attack rows 5910, 8.00 h; labels {'web_bruteforce': 1, 'bot': 5890, 'benign': 15498, 'web_sql_injection': 19}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 1.000 (1.000, 1.000, 1.000) | [1.000, 1.000] | 0.9927 | 65781 | 0.663 |
| clean_1000 | source_model_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0067 | 441 | 0.663 |
| clean_1000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0044 | 306 | 0.519 |
| clean_1000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0012 | 84 | 0.073 |
| clean_1000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.385 |
| clean_1000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0026 | 174 | 0.899 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0015 | 101 | 0.477 |
| clean_1000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0023 | 151 | 0.506 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0037 | 233 | 0.491 |
| clean_1000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0044 | 288 | 0.475 |
| clean_10000 | source_model_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0024 | 161 | 0.663 |
| clean_10000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0017 | 116 | 0.553 |
| clean_10000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0006 | 38 | 0.114 |
| clean_10000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0003 | 24 | 0.415 |
| clean_10000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0007 | 48 | 0.901 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0010 | 62 | 0.486 |
| clean_10000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 65 | 0.889 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0013 | 89 | 0.918 |
| clean_10000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0031 | 198 | 0.900 |
| clean_50000 | source_model_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0028 | 183 | 0.663 |
| clean_50000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0015 | 100 | 0.556 |
| clean_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0007 | 49 | 0.112 |
| clean_50000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0004 | 30 | 0.427 |
| clean_50000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0008 | 51 | 0.911 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0006 | 42 | 0.483 |
| clean_50000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0008 | 54 | 0.930 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0009 | 60 | 0.965 |
| clean_50000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0030 | 192 | 0.942 |
| unlabelled_50000 | source_model_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0031 | 200 | 0.663 |
| unlabelled_50000 | normalized_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0018 | 124 | 0.539 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0030 | 193 | 0.007 |
| unlabelled_50000 | target_robust_z_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0004 | 30 | 0.411 |
| unlabelled_50000 | target_iforest_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0003 | 23 | 0.774 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0018 | 113 | 0.454 |
| unlabelled_50000 | target_autoencoder_flow | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0032 | 195 | 0.740 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0028 | 191 | 0.942 |
| unlabelled_50000 | target_autoencoder_all | 0.000 (0.000, 0.000, 0.000) | [0.000, 0.000] | 0.0036 | 231 | 0.915 |

## Pre-registered hypotheses

| ID | supported | values (mean over seeds) |
|---|---|---|
| H1 | **yes** | [[1.0, 0.0009501129551634947], [0.9999863819092404, 0.0005786218543653551]] |
| H2 | **yes** | [[0.4165496248137949, 0.3518557896488826], [0.3656932882117963, 0.3525850420618051], [0.6627032959768137, 0.9926874074297203]] |
| H3 | **yes** | [[0.0019944922777717, 0.002239214988206167], [0.00028744572511327227, 0.0051737402638305915], [0.002769580905952402, 0.0]] |
| H4 | **yes** | {"final_ids2ids_nf_flow_ctx:target_robust_z_flow": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_flow": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_flow": 0.0, "final_ids2ids_nf_flow_ctx:target_robust_z_ctx": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_ctx": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_ctx": 0.0005091297745045201, "final_ids2ids_nf_flow_ctx:target_robust_z_all": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_all": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_all": 0.0, "final_ids2ids_nf_flow_ctx:target_robust_z_flow_noshortcut": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_flow_noshortcut": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_flow_noshortcut": 0.0, "final_unsw2ids_nf_flow_ctx:target_robust_z_flow": 0.0, "final_unsw2ids_nf_flow_ctx:target_iforest_flow": 0.0, "final_unsw2ids_nf_flow_ctx:target_autoencoder_flow": 0.0, "final_unsw2ids_ |
| H5 | **no** | [[0.9171550164065939, 0.6251131998128784], [0.9171550164065939, 0.6251131998128784]] |
| H6 | **yes** | {"final_unsw2unsw_nf_flow_ctx:target_autoencoder_flow": [0.0010067722365576558, 0.9171550164065939], "final_unsw2unsw_nf_flow_ctx:source_model_target_threshold": [0.0112122743401804, 1.0], "final_ids2ids_nf_flow_ctx:target_autoencoder_flow": [0.0, 0.0], "final_ids2ids_nf_flow_ctx:source_model_target_threshold": [0.0, 0.9999931909546201], "final_ids2unsw_nf_flow_ctx:target_autoencoder_flow": [0.0010067722365576558, 0.9171550164065939], "final_ids2unsw_nf_flow_ctx:source_model_target_threshold": [0.001850138602901892, 0.002239214988206167], "final_ids2unsw_nf_portable_ctx:target_autoencoder_flow": [0.004803590813820852, 0.18872189154385222], "final_ids2unsw_nf_portable_ctx:source_model_target_threshold": [0.004801199284362168, 0.0051737402638305915], "final_unsw2ids_nf_flow_ctx:target_autoencoder_flow": [0.0, 0.0], "final_unsw2ids_nf_flow_ctx:source_model_target_threshold": [0.0, 0.0]} |
