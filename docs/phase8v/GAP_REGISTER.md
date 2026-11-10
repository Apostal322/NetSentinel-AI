# Phase 8v gap register

Written 2026-11-09 (Stage 0).

**Starting point:**
- `main` = `origin/main` = `aed9b40`, with a clean tree and no tags; CI run 42610556047 success.
- 38 GB of disk and about 1 GB of RAM free.

**Reused, unchanged:**
- Phase 8i window frames;
- Phase 8o F0 frozen member scores;
- Phase 8q label audit;
- Phase 8u training driver, ledger pattern and exact partial AUC (`lowfpr.partial_auc_exact`).

| ID | scientific issue | existing evidence | competing explanations | affected | available telemetry | experiment | leakage risk | compute | decision gate | status |
|---|---|---|---|---|---|---|---|---|---|---|
| V0.1 | **What do the raw records actually contain?** | never audited beyond the 9 fields the windows use | — | all | 78-column NetFlow v3 records; no PCAP | field audit (TELEMETRY_AUDIT) | none (no labels) | 1 min, 1.0 GiB | G0 | **done: COMPLETE**; flow level only; retransmission, IAT, TTL and window fields are not cross-network safe |
| V0.2 | **Does the 12-feature window discard attack information?** | Phase 8t: attacks on NF-UNSW/NF-ToN score below benign medians; Phase 8u: no objective helps | information loss / model limit / domain shift / observability | NF-UNSW, NF-ToN | per-flow packets, flags, sizes, end times | 18 enriched features in 3 families; univariate and within-network diagnostics | labels used descriptively only (EXPLORATORY) | build about 4 min; diagnostics under 2 min | Stage 3 decision | open |
| V0.3 | **Does any enriched information transfer across networks?** | Phase 8p: service and victim context hurt transfer | topology or testbed shortcuts | all | as V0.2 | registered leave-one-network-out fits per family | none in features; development networks consumed | up to 24 fits (**needs approval**) | G1–G3, G5 | open |
| V0.4 | **Temporal order within and across windows** | Phase 8 GRU/TCN: no general advantage | summary statistics already capture it | all | ms end times; 120 s flow cut | within-window timing features and 4-window causal context (TIME) | context uses strictly earlier windows (tested) | included | G2 | open |
| V0.5 | **Sequence model** | none new | — | — | flow sequences only | only if TIME shows ordering information beyond its summaries | — | up to 3 small runs | G4 | gated |
| V0.6 | **The midpoint slot is shared by calibration and evaluation** (Phase 8t review) | 5–64 windows per domain (0 on NF-BoT) | — | all | — | disclosed; enriched features of those windows cover the whole 30 s slot | none (features only) | — | — | documented |
| V0.7 | **Seed noise is as large as effects on NF-CIC and NF-BoT** (Phase 8u) | baseline seed SD 0.08–0.12 partial AUC | — | NF-CIC, NF-BoT | — | gates centred on NF-UNSW and NF-ToN, whose seed SD is about 0.0025 | — | — | pre-registration | open |
| V0.8 | **No independent network** | Phases 8o–8u | — | all | — | — | — | — | independent validation | **NOT READY** (carried) |
