# Phase 8v: independent review and actions

**The review.** A separate agent did a read-only audit as six reviewers: telemetry correctness, ML
methodology, temporal leakage, statistics, security relevance, reproducibility.
- It had the protocol, code and saved results, but not the author's conclusions.
- It fitted no model.
- Its first run was cut off by a connection error and resumed with its context.

Every finding used below was re-checked by the author (`scripts/phase8v/ton_concentration.py`
for the NF-ToN findings).

## Recomputed by the reviewer with its own code: all matched

| quantity | result |
|---|---|
| exact partial AUC (FPR ≤ 1 %) and recall at 1 % FPR: 9 domains × 5 models (45 cells) | equal to `evaluation_screening.json` to 1e-9 |
| network means, hard-network and macro deltas (`TIME` + 0.116971 / + 0.094071) | match |
| as-calibrated FPR and recall on NF-ToN, NF-UNSW, NF-BoT for 5 models | match |
| 11 enriched features recomputed from raw NF-UNSW flows (1,698 host-windows) | max difference 1.8e-15; 0 mismatches |
| flag semantics in that sample | `tcp_flags` = client OR server in 100 %; server flags are 0 whenever there is no reverse packet |
| hashes | evaluation; 16 / 16 models after CRLF → LF; all manifest score hashes; 14 / 14 enriched tables |
| registered gates (`selection.decide`) | match PREREGISTRATION § 6 and were applied exactly: none passed, no replication, 16 fits |
| leakage | none found: windows use flow end times; lags are strictly earlier; no target rows in training; `INV` selection uses training rows only |
| chronology | registration `e5c08a6` → first fit 17 minutes later → evaluation on a clean tree, committed (`f43ac20`) before any post-hoc (`35c4f2b`) |

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| E1 | **high** (interpretation) | **`TIME`'s NF-ToN gain is volume and host persistence:** 63 % of its true positives come from one host and 90 % from three; only the two high-volume labels improve; `log_flows` alone reaches partial AUC 0.793 on NF-ToN against the model's 0.247 | yes (`ton_concentration.json`) | MODEL_COMPARISON § 3a; the final report states it is not new attack evidence |
| B1 | medium | **No null control for the pipeline.** All four candidates add nearly the same as-calibrated false-alert block on NF-ToN; adding columns changes every tree's column draw, so "same seed" is not strictly paired | yes (511 of `TIME`'s 626 new false alerts are shared by all four) | stated as the main methodological gap; a null control needs new approval |
| D3 | medium | **The deciding FPR guardrail is noise-dominated** (NF-BoT: one host; baseline seeds 7–19 % FPR vs a 1-point tolerance) | yes | stated; the verdict stands as registered, and § 3a explains why the guardrail result carries little information |
| D4 | medium | **Single-seed weight:** only NF-ToN's change is large against seed noise; NF-CIC's rests on one day and one host; seed 1060 is the baseline's weakest NF-CIC member | yes | stated per network |
| F4 | medium | "NF-UNSW did not move" understated the result: partial AUC fell 0.006 → 0.001 under `TIME`, and as-calibrated recall collapsed under every candidate (0.706 → 0.463 / 0.327 / 0.225 / 0.001) | yes | corrected in MODEL_COMPARISON § 3 |
| A2 | low–medium | "available when the window closes" is too strong: an idle-timeout flow is exported later | yes | FEATURE_SCHEMA now says window close plus the exporter's unrecorded delay |
| A3 | low | midpoint-slot counts were wrong ("14–64"; actual 5–64, 0 on NF-BoT) | yes | corrected |
| A4 | low | mixed missing-value policy; `gap_cv` missingness is a domain fingerprint (50–58 % on NF-CIC vs 10 % on NF-UNSW) | yes | stated in FEATURE_SCHEMA |
| C3 | low | context features after an NF-UNSW file boundary read the withheld tail as silence | yes | recorded in PREREGISTRATION |
| D2 | low | the entity guardrail's threshold was unspecified in the text (code: as calibrated) | yes | recorded in PREREGISTRATION |
| F2 | low | "clean commits" overstated: the tree check runs once per variant | yes | recorded; wording corrected |
| F4b | low | "peak 1.9 GiB" was not in a saved report (ledger: 1.47 GiB resident) | yes | both figures given with their sources |
| B2 | low | `INV`'s design and 0.1 margin were chosen after seeing all networks' evaluation labels | yes (disclosed at registration) | restated |
| E2 | low | the NF-UNSW direction inversion is supported, on 4 attacker hosts vs 34 benign hosts | yes | stated as a testbed property |

## Not changed

- The registered verdicts: no candidate passes; model development NO-GO.
- The registered evaluation file and its hash.
- The frozen M2 and all historical artifacts.
