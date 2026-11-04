# Phase 8q gap register

Written 2026-11-04.

**Starting point:**
- `main` = `origin/main` = `f112a1c`, with a clean tree and no tags;
- 38 GB disk and about 1.1 GB RAM free (other projects' test runs active);
- CI is not verifiable (`gh` is not installed).

| ID | issue | evidence | severity | root cause / hypothesis | affected metrics | correction | validation | cost | status |
|---|---|---|---|---|---|---|---|---|---|
| Q0.1 | **Evaluation populations mixed documented attackers, attacked hosts and undocumented sources** | LABEL_AUDIT § 2–4 | high | historical flow labels assigned by host or time without per-host documentation | entity recall, R/U/N, "missed attackers" | versioned audit `label-audit-1.0.0`; views V0/V1/V2; categories reported separately | reproduces Phase 8p roles and S0 exactly | minutes | **done** |
| Q0.2 | **02-20 family mismatch** (LOIC-UDP onset labelled LOIC-HTTP) | LABEL_AUDIT § 3 | medium | dataset labelling | NF-CIC 02-20 recall | category `documented_family_mismatch`; V1 excludes it | official table re-read | — | **done** |
| Q0.3 | **03-02 bot windows mostly outside documented intervals** | 2,317 / 2,408 | medium | the intervals cover operator activity, not infection | V1 strict | V1 kept as sensitivity only | — | — | **documented** |
| Q0.4 | **No verified-benign population** | no dataset supplies it | medium | — | every FPR | dataset-labelled benign, with an uninvolved-host sensitivity | sensitivity reported | — | **documented limit** |
| Q1.1 | **Calibration-label dependency not decomposed** | Phase 8p C1 0.372 vs C0 0.869 | high | threshold contamination vs memory (state) contamination | recall without labels | Experiment B decomposition from saved scores | path-order check | minutes | **done** (CALIBRATION_DECOMPOSITION) |
| Q1.2 | **No label-free threshold estimator beats the unlabelled T0** | Phase 8p C3 failed | high | attackers dominate the hold-out tail; equal host weights hand it to transient hosts | recall, FPR | Experiment F (L1 host cap α/2, L2 block median, L4 leave-one-host-out trim, L5 abstention) | registered rule | minutes | **NOT SUPPORTED** (Experiment F) |
| Q1.3 | **Memory (state) contamination has no label-free fix** | decomposition: about one third of the loss; all of NF-CIC's | high | attackers' calibration destinations enter the frozen memory | NF-CIC recall | exploratory feature-level guard (≥ 2 sources); a scored test needs refits | feasibility only | refits not authorized | **guard fails** where attackers share targets (02-22, 03-02); it restores novelty only on 02-14, which needed no restoring |
| Q1.4 | **Robustness of threshold estimators to contamination and sparsity not measured** | — | medium | — | T0 stability | Experiment G | registered descriptive | minutes | **done**: bounded (≤ 10 %) contamination only; robustness costs false alerts on NF-ToN/NF-BoT |
| Q2.1 | **Pre-registered L1/L4 drafts were defective** (a cap > α; a self-masking pooled quantile) | synthetic unit tests | medium | design error | — | fixed before commit (c = α/2; leave-one-host-out) | tests | — | **fixed before registration** |
