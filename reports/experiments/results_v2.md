# Results v2: seed variance and temporal open-set (validation, measured)
Seeds {42, 1, 2, 3, 4}; each changes model and split seed. Seed 42 = batch v1 runs. Mean +- sample std. Test split untouched.
## A - unseen family: GRU / MLP (flow + per-port sequence) vs LightGBM
| held-out family | MLP recall | GRU recall | GRU unseen PR-AUC | GRU benign FPR | LightGBM flow | LightGBM flow+ctx |
|---|---|---|---|---|---|---|
| bruteforce | 0.5082 (n=1) | 0.8505 (n=1) | 0.9774 (n=1) | 0.0010 (n=1) | 0.5118 (n=1) | 0.9983 (n=1) |
| dos | 0.1982 (n=1) | 0.4066 (n=1) | 0.9145 (n=1) | 0.0010 (n=1) | 0.2291 (n=1) | 0.9678 (n=1) |
| ddos | 0.0060 (n=1) | 0.0575 (n=1) | 0.9350 (n=1) | 0.0009 (n=1) | 0.2259 (n=1) | 0.7221 (n=1) |
| web_attack | 0.0141 (n=1) | 0.0085 (n=1) | 0.0006 (n=1) | 0.0010 (n=1) | 0.1171 (n=1) | 0.0268 (n=1) |
| botnet | 0.0000 (n=1) | 0.0000 (n=1) | 0.3060 (n=1) | 0.0009 (n=1) | 0.0037 (n=1) | 0.6127 (n=1) |

## B1 - binary LightGBM across seeds (episode split)
| features | PR-AUC | recall @ FPR 1e-3 | recall @ FPR 1e-2 | ECE |
|---|---|---|---|---|
| flow | 1.0000 +- 0.0000 (n=5) | 0.9999 +- 0.0001 (n=5) | 1.0000 +- 0.0000 (n=5) | 0.0002 +- 0.0001 (n=5) |
| flow_noshortcut | 0.9969 +- 0.0001 (n=5) | 0.8759 +- 0.0021 (n=5) | 0.9994 +- 0.0002 (n=5) | 0.0088 +- 0.0016 (n=5) |
| flow_ctx | 1.0000 +- 0.0000 (n=5) | 1.0000 +- 0.0000 (n=5) | 1.0000 +- 0.0000 (n=5) | 0.0000 +- 0.0000 (n=5) |

## B2 - unseen-family recall (LightGBM) across seeds
| held-out family | flow | flow + ctx | anomaly (flow) | fused (flow+ctx) |
|---|---|---|---|---|
| bruteforce | 0.6545 +- 0.1452 (n=5) | 0.9986 +- 0.0014 (n=5) | 0.0000 +- 0.0000 (n=5) | 0.9978 +- 0.0023 (n=5) |
| dos | 0.3365 +- 0.1449 (n=5) | 0.9669 +- 0.0083 (n=5) | 0.0000 +- 0.0000 (n=5) | 0.9532 +- 0.0135 (n=5) |
| ddos | 0.2188 +- 0.1318 (n=5) | 0.6644 +- 0.1012 (n=5) | 0.0000 +- 0.0000 (n=5) | 0.5826 +- 0.1019 (n=5) |
| web_attack | 0.0857 +- 0.0313 (n=5) | 0.0132 +- 0.0108 (n=5) | 0.0000 +- 0.0000 (n=5) | 0.0051 +- 0.0068 (n=5) |
| botnet | 0.1784 +- 0.2426 (n=5) | 0.6806 +- 0.0380 (n=5) | 0.0000 +- 0.0000 (n=5) | 0.5916 +- 0.1028 (n=5) |

## B3 - GRU vs MLP on seen attacks across seeds
| model | PR-AUC | recall @ FPR 1e-3 | web_xss recall | epochs |
|---|---|---|---|---|
| mlp | 0.9997 +- 0.0001 (n=5) | 0.9986 +- 0.0007 (n=5) | 0.5471 +- 0.0485 (n=5) | 10.0000 +- 1.7321 (n=5) |
| gru | 0.9999 +- 0.0000 (n=5) | 0.9993 +- 0.0003 (n=5) | 0.7218 +- 0.1115 (n=5) | 8.0000 +- 0.7071 (n=5) |

Batch v2 cost (measured): 29 processes, 49.7 min total, max peak working set 3420 MB.
