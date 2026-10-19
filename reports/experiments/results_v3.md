# Results v3: corrected open-set protocol and context ablation (validation)

Hold-out groups are defined by behaviour so that twin classes (identical traffic under different family labels) are held out together; label cleaning v2. Seeds {42,1,2,3,4} (model + split). Thresholds at benign-validation FPR <= 1e-3.

## Unseen-group recall, features `flow`

| held-out group | rows | supervised | anomaly | fused | supervised benign FPR |
|---|---|---|---|---|---|
| port21_failed_conn | 42196 | 0.315 +- 0.437 (n=5) | 0.000 +- 0.000 (n=5) | 0.000 +- 0.000 (n=5) | 0.001 +- 0.000 (n=5) |
| ssh_bruteforce | 21656 | 0.595 +- 0.226 (n=5) | 0.000 +- 0.000 (n=5) | 0.261 +- 0.247 (n=5) | 0.001 +- 0.000 (n=5) |
| dos_http | 46862 | 0.046 +- 0.012 (n=5) | 0.000 +- 0.000 (n=5) | 0.040 +- 0.012 (n=5) | 0.001 +- 0.000 (n=5) |
| ddos | 38041 | 0.111 +- 0.137 (n=5) | 0.000 +- 0.000 (n=5) | 0.048 +- 0.099 (n=5) | 0.001 +- 0.000 (n=5) |
| web_attack | 709 | 0.093 +- 0.030 (n=5) | 0.000 +- 0.000 (n=5) | 0.076 +- 0.029 (n=5) | 0.001 +- 0.000 (n=5) |
| botnet | 24494 | 0.251 +- 0.227 (n=5) | 0.000 +- 0.000 (n=5) | 0.177 +- 0.242 (n=5) | 0.001 +- 0.000 (n=5) |

## Unseen-group recall, features `flow_ctx`

| held-out group | rows | supervised | anomaly | fused | supervised benign FPR |
|---|---|---|---|---|---|
| port21_failed_conn | 42196 | 0.999 +- 0.002 (n=5) | 0.000 +- 0.000 (n=5) | 0.998 +- 0.003 (n=5) | 0.001 +- 0.000 (n=5) |
| ssh_bruteforce | 21656 | 0.998 +- 0.003 (n=5) | 0.000 +- 0.000 (n=5) | 0.997 +- 0.004 (n=5) | 0.001 +- 0.000 (n=5) |
| dos_http | 46862 | 0.951 +- 0.017 (n=5) | 0.000 +- 0.000 (n=5) | 0.919 +- 0.030 (n=5) | 0.001 +- 0.000 (n=5) |
| ddos | 38041 | 0.680 +- 0.091 (n=5) | 0.001 +- 0.000 (n=5) | 0.596 +- 0.107 (n=5) | 0.001 +- 0.000 (n=5) |
| web_attack | 709 | 0.015 +- 0.008 (n=5) | 0.000 +- 0.000 (n=5) | 0.006 +- 0.004 (n=5) | 0.001 +- 0.000 (n=5) |
| botnet | 24494 | 0.663 +- 0.060 (n=5) | 0.000 +- 0.000 (n=5) | 0.634 +- 0.098 (n=5) | 0.001 +- 0.000 (n=5) |

## Unseen-group recall, features `flow_ctx_inv`

| held-out group | rows | supervised | anomaly | fused | supervised benign FPR |
|---|---|---|---|---|---|
| port21_failed_conn | 42196 | 0.999 +- 0.002 (n=5) | 0.000 +- 0.000 (n=5) | 0.998 +- 0.003 (n=5) | 0.001 +- 0.000 (n=5) |
| ssh_bruteforce | 21656 | 0.999 +- 0.002 (n=5) | 0.000 +- 0.000 (n=5) | 0.999 +- 0.002 (n=5) | 0.001 +- 0.000 (n=5) |
| dos_http | 46862 | 0.943 +- 0.010 (n=5) | 0.000 +- 0.000 (n=5) | 0.926 +- 0.019 (n=5) | 0.001 +- 0.000 (n=5) |
| ddos | 38041 | 0.676 +- 0.123 (n=5) | 0.000 +- 0.000 (n=5) | 0.609 +- 0.110 (n=5) | 0.001 +- 0.000 (n=5) |
| web_attack | 709 | 0.074 +- 0.021 (n=5) | 0.000 +- 0.000 (n=5) | 0.058 +- 0.017 (n=5) | 0.001 +- 0.000 (n=5) |
| botnet | 24494 | 0.705 +- 0.004 (n=5) | 0.000 +- 0.000 (n=5) | 0.695 +- 0.006 (n=5) | 0.001 +- 0.000 (n=5) |

## Per-label unseen recall (supervised, `flow_ctx`)

| group | label | recall |
|---|---|---|
| port21_failed_conn | dos_slowhttptest | 1.000 +- 0.001 (n=5) |
| port21_failed_conn | ftp_bruteforce | 0.998 +- 0.004 (n=5) |
| ssh_bruteforce | ssh_bruteforce | 0.998 +- 0.003 (n=5) |
| dos_http | dos_goldeneye | 0.729 +- 0.175 (n=5) |
| dos_http | dos_hulk | 0.994 +- 0.001 (n=5) |
| dos_http | dos_slowloris | 0.092 +- 0.087 (n=5) |
| ddos | ddos_hoic | 1.000 +- 0.001 (n=5) |
| ddos | ddos_loic_http | 0.373 +- 0.172 (n=5) |
| ddos | ddos_loic_udp | 0.984 +- 0.036 (n=5) |
| web_attack | web_bruteforce | 0.013 +- 0.005 (n=5) |
| web_attack | web_sql_injection | 0.005 +- 0.007 (n=5) |
| web_attack | web_xss | 0.024 +- 0.030 (n=5) |
| botnet | bot | 0.663 +- 0.060 (n=5) |

## Context scale ablation, seen attacks (LightGBM binary, episode split)

| features | PR-AUC | recall @ FPR 1e-3 | recall @ FPR 1e-2 |
|---|---|---|---|
| flow_ctx_inv | 1.000 +- 0.000 (n=5) | 1.000 +- 0.000 (n=5) | 1.000 +- 0.000 (n=5) |
| flow_ctx_abs | 1.000 +- 0.000 (n=5) | 1.000 +- 0.000 (n=5) | 1.000 +- 0.000 (n=5) |

Batch v3 cost (measured): 25 processes, 50.1 min, max peak working set 2333 MB.
