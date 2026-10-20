# Final NF-v3 evaluation (pre-registered, one-shot)

Pre-registration: `docs/experiments/final_preregistration_nf.md` (commit 47d0817). Test rows = test under both the episode and chronological protocols. Recall: mean over seeds (per-seed values, order 42); CI = 95% block bootstrap of the first listed seed; FA/h = false-alert flows per hour.

## NF-UNSW in-domain (1 seeds)

Test rows 39151, attack rows 20621, 3.25 h; labels {'exploits': 5426, 'dos': 857, 'backdoor': 1238, 'benign': 18530, 'generic': 3602, 'worms': 24, 'analysis': 269, 'fuzzers': 5738, 'reconnaissance': 3172, 'shellcode': 295}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0011 | 97 | 1.000 |
| clean_1000 | source_model_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0007 | 62 | 1.000 |
| clean_1000 | normalized_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0024 | 210 | 1.000 |
| clean_1000 | robust_subset_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0021 | 183 | 1.000 |
| clean_1000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.868 |
| clean_1000 | target_iforest_flow | 0.035 (0.035) | [0.014, 0.065] | 0.0020 | 177 | 0.936 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0014 | 125 | 0.539 |
| clean_1000 | target_autoencoder_flow | 0.272 (0.272) | [0.218, 0.328] | 0.0004 | 38 | 0.912 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.067 (0.067) | [0.044, 0.091] | 0.0005 | 40 | 0.712 |
| clean_1000 | target_autoencoder_all | 0.098 (0.098) | [0.062, 0.143] | 0.0014 | 121 | 0.904 |
| clean_10000 | source_model_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0012 | 104 | 1.000 |
| clean_10000 | normalized_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0011 | 100 | 1.000 |
| clean_10000 | robust_subset_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0016 | 137 | 1.000 |
| clean_10000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.886 |
| clean_10000 | target_iforest_flow | 0.019 (0.019) | [0.006, 0.042] | 0.0008 | 74 | 0.932 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.560 |
| clean_10000 | target_autoencoder_flow | 1.000 (1.000) | [1.000, 1.000] | 0.0009 | 82 | 1.000 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.364 (0.364) | [0.317, 0.408] | 0.0009 | 81 | 0.977 |
| clean_10000 | target_autoencoder_all | 0.750 (0.750) | [0.697, 0.798] | 0.0011 | 95 | 0.998 |
| clean_50000 | source_model_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0010 | 89 | 1.000 |
| clean_50000 | normalized_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0016 | 141 | 1.000 |
| clean_50000 | robust_subset_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0012 | 107 | 1.000 |
| clean_50000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.886 |
| clean_50000 | target_iforest_flow | 0.024 (0.024) | [0.009, 0.049] | 0.0010 | 88 | 0.931 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.559 |
| clean_50000 | target_autoencoder_flow | 1.000 (1.000) | [1.000, 1.000] | 0.0005 | 46 | 1.000 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.916 (0.916) | [0.904, 0.927] | 0.0004 | 38 | 0.999 |
| clean_50000 | target_autoencoder_all | 0.755 (0.755) | [0.701, 0.803] | 0.0006 | 55 | 1.000 |
| unlabelled_50000 | source_model_target_threshold | 0.007 (0.007) | [0.003, 0.013] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | normalized_target_threshold | 0.011 (0.011) | [0.002, 0.025] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | robust_subset_target_threshold | 0.011 (0.011) | [0.005, 0.017] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.886 |
| unlabelled_50000 | target_iforest_flow | 0.009 (0.009) | [0.001, 0.026] | 0.0004 | 38 | 0.945 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.545 |
| unlabelled_50000 | target_autoencoder_flow | 0.001 (0.001) | [0.001, 0.002] | 0.0006 | 51 | 0.885 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.011 (0.011) | [0.003, 0.026] | 0.0002 | 21 | 0.879 |
| unlabelled_50000 | target_autoencoder_all | 0.001 (0.001) | [0.001, 0.001] | 0.0006 | 50 | 0.751 |

## NF-IDS2018 in-domain (1 seeds)

Test rows 21408, attack rows 5910, 8.00 h; labels {'web_bruteforce': 1, 'benign': 15498, 'bot': 5890, 'web_sql_injection': 19}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0006 | 42 | 1.000 |
| clean_1000 | source_model_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0005 | 38 | 1.000 |
| clean_1000 | normalized_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0006 | 38 | 1.000 |
| clean_1000 | robust_subset_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0007 | 48 | 1.000 |
| clean_1000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.391 |
| clean_1000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0069 | 476 | 0.886 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0040 | 279 | 0.415 |
| clean_1000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0032 | 219 | 0.397 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0035 | 239 | 0.397 |
| clean_1000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0074 | 508 | 0.387 |
| clean_10000 | source_model_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0006 | 42 | 1.000 |
| clean_10000 | normalized_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0007 | 46 | 1.000 |
| clean_10000 | robust_subset_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0006 | 39 | 1.000 |
| clean_10000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.433 |
| clean_10000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0013 | 88 | 0.898 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0012 | 81 | 0.456 |
| clean_10000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0015 | 105 | 0.837 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0018 | 125 | 0.924 |
| clean_10000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0027 | 183 | 0.938 |
| clean_50000 | source_model_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0005 | 38 | 1.000 |
| clean_50000 | normalized_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0021 | 144 | 1.000 |
| clean_50000 | robust_subset_target_threshold | 1.000 (1.000) | [1.000, 1.000] | 0.0008 | 56 | 1.000 |
| clean_50000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.433 |
| clean_50000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0010 | 72 | 0.907 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0015 | 105 | 0.445 |
| clean_50000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0010 | 71 | 0.911 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0009 | 60 | 0.945 |
| clean_50000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0022 | 149 | 0.961 |
| unlabelled_50000 | source_model_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 1.000 |
| unlabelled_50000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.411 |
| unlabelled_50000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0002 | 13 | 0.784 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0020 | 138 | 0.444 |
| unlabelled_50000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0015 | 104 | 0.810 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0017 | 119 | 0.891 |
| unlabelled_50000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0036 | 250 | 0.943 |

## NF-IDS2018 -> NF-UNSW, nf_flow_ctx (1 seeds)

Test rows 39151, attack rows 20621, 3.25 h; labels {'benign': 18530, 'reconnaissance': 3172, 'backdoor': 1238, 'worms': 24, 'analysis': 269, 'exploits': 5426, 'fuzzers': 5738, 'dos': 857, 'generic': 3602, 'shellcode': 295}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 0.346 (0.346) | [0.294, 0.390] | 0.3454 | 30370 | 0.477 |
| clean_1000 | source_model_target_threshold | 0.004 (0.004) | [0.003, 0.005] | 0.0030 | 264 | 0.477 |
| clean_1000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0250 | 2203 | 0.214 |
| clean_1000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0129 | 1138 | 0.346 |
| clean_1000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.868 |
| clean_1000 | target_iforest_flow | 0.035 (0.035) | [0.014, 0.065] | 0.0020 | 177 | 0.936 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0014 | 125 | 0.539 |
| clean_1000 | target_autoencoder_flow | 0.272 (0.272) | [0.218, 0.328] | 0.0004 | 38 | 0.912 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.067 (0.067) | [0.044, 0.091] | 0.0005 | 40 | 0.712 |
| clean_1000 | target_autoencoder_all | 0.098 (0.098) | [0.062, 0.143] | 0.0014 | 121 | 0.904 |
| clean_10000 | source_model_target_threshold | 0.004 (0.004) | [0.003, 0.006] | 0.0033 | 292 | 0.477 |
| clean_10000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0242 | 2125 | 0.248 |
| clean_10000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0192 | 1689 | 0.403 |
| clean_10000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.886 |
| clean_10000 | target_iforest_flow | 0.019 (0.019) | [0.006, 0.042] | 0.0008 | 74 | 0.932 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.560 |
| clean_10000 | target_autoencoder_flow | 1.000 (1.000) | [1.000, 1.000] | 0.0009 | 82 | 1.000 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.364 (0.364) | [0.317, 0.408] | 0.0009 | 81 | 0.977 |
| clean_10000 | target_autoencoder_all | 0.750 (0.750) | [0.697, 0.798] | 0.0011 | 95 | 0.998 |
| clean_50000 | source_model_target_threshold | 0.005 (0.005) | [0.003, 0.006] | 0.0039 | 342 | 0.477 |
| clean_50000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0234 | 2056 | 0.256 |
| clean_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0111 | 976 | 0.403 |
| clean_50000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.886 |
| clean_50000 | target_iforest_flow | 0.024 (0.024) | [0.009, 0.049] | 0.0010 | 88 | 0.931 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.559 |
| clean_50000 | target_autoencoder_flow | 1.000 (1.000) | [1.000, 1.000] | 0.0005 | 46 | 1.000 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.916 (0.916) | [0.904, 0.927] | 0.0004 | 38 | 0.999 |
| clean_50000 | target_autoencoder_all | 0.755 (0.755) | [0.701, 0.803] | 0.0006 | 55 | 1.000 |
| unlabelled_50000 | source_model_target_threshold | 0.004 (0.004) | [0.002, 0.005] | 0.0028 | 250 | 0.477 |
| unlabelled_50000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0239 | 2100 | 0.234 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0262 | 2301 | 0.390 |
| unlabelled_50000 | target_robust_z_flow | 0.001 (0.001) | [0.001, 0.001] | 0.0004 | 38 | 0.886 |
| unlabelled_50000 | target_iforest_flow | 0.009 (0.009) | [0.001, 0.026] | 0.0004 | 38 | 0.945 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.545 |
| unlabelled_50000 | target_autoencoder_flow | 0.001 (0.001) | [0.001, 0.002] | 0.0006 | 51 | 0.885 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.011 (0.011) | [0.003, 0.026] | 0.0002 | 21 | 0.879 |
| unlabelled_50000 | target_autoencoder_all | 0.001 (0.001) | [0.001, 0.001] | 0.0006 | 50 | 0.751 |

## NF-IDS2018 -> NF-UNSW, nf_portable_ctx (1 seeds)

Test rows 39151, attack rows 20621, 3.25 h; labels {'benign': 18530, 'reconnaissance': 3172, 'fuzzers': 5738, 'generic': 3602, 'worms': 24, 'exploits': 5426, 'dos': 857, 'analysis': 269, 'shellcode': 295, 'backdoor': 1238}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 0.081 (0.081) | [0.064, 0.101] | 0.4186 | 36812 | 0.355 |
| clean_1000 | source_model_target_threshold | 0.007 (0.007) | [0.005, 0.010] | 0.0005 | 42 | 0.355 |
| clean_1000 | normalized_target_threshold | 0.003 (0.003) | [0.001, 0.005] | 0.0330 | 2906 | 0.388 |
| clean_1000 | robust_subset_target_threshold | 0.011 (0.011) | [0.004, 0.019] | 0.0034 | 302 | 0.323 |
| clean_1000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.845 |
| clean_1000 | target_iforest_flow | 0.047 (0.047) | [0.025, 0.072] | 0.0014 | 122 | 0.958 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0014 | 125 | 0.539 |
| clean_1000 | target_autoencoder_flow | 0.053 (0.053) | [0.032, 0.079] | 0.0008 | 67 | 0.817 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.053 (0.053) | [0.032, 0.079] | 0.0008 | 67 | 0.817 |
| clean_1000 | target_autoencoder_all | 0.001 (0.001) | [0.000, 0.001] | 0.0024 | 215 | 0.795 |
| clean_10000 | source_model_target_threshold | 0.006 (0.006) | [0.004, 0.009] | 0.0000 | 0 | 0.355 |
| clean_10000 | normalized_target_threshold | 0.002 (0.002) | [0.001, 0.004] | 0.0331 | 2914 | 0.382 |
| clean_10000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0033 | 289 | 0.371 |
| clean_10000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.574 |
| clean_10000 | target_iforest_flow | 0.081 (0.081) | [0.044, 0.114] | 0.0025 | 219 | 0.955 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0001 | 7 | 0.560 |
| clean_10000 | target_autoencoder_flow | 0.168 (0.168) | [0.128, 0.202] | 0.0010 | 87 | 0.970 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.168 (0.168) | [0.128, 0.202] | 0.0010 | 87 | 0.970 |
| clean_10000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.001] | 0.0009 | 76 | 0.750 |
| clean_50000 | source_model_target_threshold | 0.001 (0.001) | [0.001, 0.002] | 0.0000 | 0 | 0.355 |
| clean_50000 | normalized_target_threshold | 0.002 (0.002) | [0.001, 0.004] | 0.0334 | 2933 | 0.383 |
| clean_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0020 | 178 | 0.370 |
| clean_50000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.570 |
| clean_50000 | target_iforest_flow | 0.042 (0.042) | [0.013, 0.077] | 0.0008 | 68 | 0.962 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.559 |
| clean_50000 | target_autoencoder_flow | 0.128 (0.128) | [0.095, 0.159] | 0.0004 | 36 | 0.990 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.128 (0.128) | [0.095, 0.159] | 0.0004 | 36 | 0.990 |
| clean_50000 | target_autoencoder_all | 0.026 (0.026) | [0.004, 0.051] | 0.0008 | 75 | 0.801 |
| unlabelled_50000 | source_model_target_threshold | 0.003 (0.003) | [0.002, 0.005] | 0.0000 | 0 | 0.355 |
| unlabelled_50000 | normalized_target_threshold | 0.002 (0.002) | [0.001, 0.004] | 0.0231 | 2033 | 0.395 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0020 | 180 | 0.362 |
| unlabelled_50000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.565 |
| unlabelled_50000 | target_iforest_flow | 0.005 (0.005) | [0.001, 0.013] | 0.0004 | 36 | 0.909 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0000 | 0 | 0.545 |
| unlabelled_50000 | target_autoencoder_flow | 0.006 (0.006) | [0.003, 0.011] | 0.0002 | 14 | 0.955 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.006 (0.006) | [0.003, 0.011] | 0.0002 | 14 | 0.955 |
| unlabelled_50000 | target_autoencoder_all | 0.001 (0.001) | [0.001, 0.001] | 0.0002 | 22 | 0.780 |

## NF-UNSW -> NF-IDS2018, nf_flow_ctx (1 seeds)

Test rows 21408, attack rows 5910, 8.00 h; labels {'web_bruteforce': 1, 'bot': 5890, 'benign': 15498, 'web_sql_injection': 19}

| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |
|---|---|---|---|---|---|---|
| none | source model, source threshold | 1.000 (1.000) | [1.000, 1.000] | 0.9915 | 68352 | 0.649 |
| clean_1000 | source_model_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0031 | 213 | 0.649 |
| clean_1000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0071 | 489 | 0.507 |
| clean_1000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0029 | 200 | 0.072 |
| clean_1000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.391 |
| clean_1000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0069 | 476 | 0.886 |
| clean_1000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0040 | 279 | 0.415 |
| clean_1000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0032 | 219 | 0.397 |
| clean_1000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0035 | 239 | 0.397 |
| clean_1000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0074 | 508 | 0.387 |
| clean_10000 | source_model_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0016 | 111 | 0.649 |
| clean_10000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0021 | 145 | 0.558 |
| clean_10000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0008 | 52 | 0.165 |
| clean_10000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.433 |
| clean_10000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0013 | 88 | 0.898 |
| clean_10000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0012 | 81 | 0.456 |
| clean_10000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0015 | 105 | 0.837 |
| clean_10000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0018 | 125 | 0.924 |
| clean_10000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0027 | 183 | 0.938 |
| clean_50000 | source_model_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0018 | 126 | 0.649 |
| clean_50000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0020 | 136 | 0.560 |
| clean_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0013 | 92 | 0.158 |
| clean_50000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.433 |
| clean_50000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0010 | 72 | 0.907 |
| clean_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0015 | 105 | 0.445 |
| clean_50000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0010 | 71 | 0.911 |
| clean_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0009 | 60 | 0.945 |
| clean_50000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0022 | 149 | 0.961 |
| unlabelled_50000 | source_model_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0019 | 131 | 0.649 |
| unlabelled_50000 | normalized_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0024 | 165 | 0.534 |
| unlabelled_50000 | robust_subset_target_threshold | 0.000 (0.000) | [0.000, 0.000] | 0.0011 | 75 | 0.006 |
| unlabelled_50000 | target_robust_z_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0003 | 22 | 0.411 |
| unlabelled_50000 | target_iforest_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0002 | 13 | 0.784 |
| unlabelled_50000 | target_iforest_ctx | 0.000 (0.000) | [0.000, 0.000] | 0.0020 | 138 | 0.444 |
| unlabelled_50000 | target_autoencoder_flow | 0.000 (0.000) | [0.000, 0.000] | 0.0015 | 104 | 0.810 |
| unlabelled_50000 | target_autoencoder_flow_noshortcut | 0.000 (0.000) | [0.000, 0.000] | 0.0017 | 119 | 0.891 |
| unlabelled_50000 | target_autoencoder_all | 0.000 (0.000) | [0.000, 0.000] | 0.0036 | 250 | 0.943 |

## Pre-registered hypotheses

| ID | supported | values (mean over seeds) |
|---|---|---|
| H1 | **yes** | [[1.0, 0.0011059392763232434], [0.9999795728638604, 0.0006080852127219091]] |
| H2 | **yes** | [[0.47741096512814885, 0.34535239439253884], [0.35455243444792867, 0.4186091554909399], [0.6486958877556949, 0.9914895627125324]] |
| H3 | **no** | [[0.003884817208392383, 0.004700752716664377], [0.0, 0.0014023231474768981], [0.0018266386671128639, 0.0]] |
| H4 | **yes** | {"final_ids2ids_nf_flow_ctx:target_robust_z_flow": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_flow": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_flow": 0.0, "final_ids2ids_nf_flow_ctx:target_robust_z_ctx": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_ctx": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_ctx": 0.0005091297745045201, "final_ids2ids_nf_flow_ctx:target_robust_z_all": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_all": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_all": 0.0, "final_ids2ids_nf_flow_ctx:target_robust_z_flow_noshortcut": 0.0, "final_ids2ids_nf_flow_ctx:target_iforest_flow_noshortcut": 0.0, "final_ids2ids_nf_flow_ctx:target_autoencoder_flow_noshortcut": 0.0, "final_unsw2ids_nf_flow_ctx:target_robust_z_flow": 0.0, "final_unsw2ids_nf_flow_ctx:target_iforest_flow": 0.0, "final_unsw2ids_nf_flow_ctx:target_autoencoder_flow": 0.0, "final_unsw2ids_ |
| H5 | **yes** | [[0.9998317671765565, 0.9159134301335289], [0.9998317671765565, 0.9159134301335289]] |
| H6 | **no** | {"final_unsw2unsw_nf_flow_ctx:target_autoencoder_flow": [0.0014138632060889755, 0.9998317671765565], "final_unsw2unsw_nf_flow_ctx:source_model_target_threshold": [0.007152551457650265, 1.0], "final_ids2ids_nf_flow_ctx:target_autoencoder_flow": [0.0, 0.0], "final_ids2ids_nf_flow_ctx:source_model_target_threshold": [0.0, 0.9999795728638604], "final_ids2unsw_nf_flow_ctx:target_autoencoder_flow": [0.0014138632060889755, 0.9998317671765565], "final_ids2unsw_nf_flow_ctx:source_model_target_threshold": [0.0035335235607515517, 0.004700752716664377], "final_ids2unsw_nf_portable_ctx:target_autoencoder_flow": [0.005637058423321882, 0.12801532008020586], "final_ids2unsw_nf_portable_ctx:source_model_target_threshold": [0.0032100038297865905, 0.0014023231474768981], "final_unsw2ids_nf_flow_ctx:target_autoencoder_flow": [0.0, 0.0], "final_unsw2ids_nf_flow_ctx:source_model_target_threshold": [0.0, 0.0]} |
