# Phase 8l: data eligibility, statistical power and the design of an independent test

**Date:** 2026-11-02.

**Question:** can a scientifically valid, adequately powered independent experiment test
calibration reliability and useful attack detection across previously unseen networks?

**Preserved:**
- Phase 8j: development NO-GO.
- Phase 8k: NOT EVALUABLE.
  - Its confirmatory protocol remains a *frozen candidate only*:
    `docs/phase8k/FREEZE_CANDIDATE.md` matches `confirm_analysis.py` (SHA-256 `ca2d566a…`).
  - **No `docs/phase8k/FREEZE.md` exists, so nothing is unlocked.**
  - The 7 AIT confirmation networks remain untouched.

| document | contents |
|---|---|
| [LABEL_INTEGRITY.md](LABEL_INTEGRITY.md) | how AIT labels are made (time windows, defaults, catch-alls) and what they do on the probe network; why UWF has no usable benign calibration |
| [DATASET_ELIGIBILITY.md](DATASET_ELIGIBILITY.md) | eligibility criteria and the inventory of public candidates; independent units available |
| [FORMULATION.md](FORMULATION.md) | tasks A–D; which failures history foreshadows (turnover) and which it cannot (behavioural change of a host) |
| [POWER_ANALYSIS.md](POWER_ANALYSIS.md) | label noise; power and minimum N for network-level confirmation |
| [PROSPECTIVE_DESIGN.md](PROSPECTIVE_DESIGN.md) | revised evaluation design, utility and controls, exact model comparison plan, data and compute needs |
| [REVIEW.md](REVIEW.md) | independent skeptical review and dispositions |

## Findings

1. **F1 (AIT) labels are not host-level ground truth.**
   - Attack steps are labelled by time window, whatever host sent the flow: 94% of attack-step
     labels sit on the VPN server.
   - Defaults and catch-alls fill the rest.
   - The attacker machine emits 218 benign-labelled flows.
   - Benign senders amount to 3.6–7 effective hosts per network.
   - F1 is development or demonstration material, not confirmation evidence.
2. **F2 (UWF) has no usable benign calibration.** The parquet release is attack traffic only;
   benign traffic is a single 10 MB file pooled over 7 weeks. Rebuilding a mixture would mean
   opening protected evaluation-period traffic, which is rejected.
3. **Public data offers about 1 confirmation-grade independent network** (DEDALE, Inria/DGA
   2025), possibly 2 (OpTC at ~940 GB), plus 3–6 development-grade ones.
4. **A powered confirmation needs about 20–30 independent networks**, each with ≥ 1,000
   effective verified-benign windows, and only for a good rule.
   - A moderate rule needs 60–100.
   - The Phase 8k design had 2–21% power.
   - Three-state adequacy labels are required.
5. **History foreshadows population turnover, not behavioural change.**
   - Within-calibration turnover was 0.79 on NF-ToN-IoT vs 0.15–0.19 on NF-CIC. This is a
     candidate decision-time feature, post-hoc on 4 networks.
   - N4's dominant host drifted only after calibration, so that failure needs online
     monitoring.

## Decision: **NO-GO**

**An adequately powered independent confirmatory experiment cannot be built from the public
data available today:** about 1–2 eligible networks against the 20–30 needed. Running one
anyway would repeat Phase 8k: an unpowered test whose likely outcomes are "not evaluable" or a
failure that says nothing about the method.

**No protected data was opened.** No download beyond the reviews of the publishers' listings
was made, and the AIT and DEDALE confirmation data remain untouched.

**What would change the decision:** a source of ≥ 20 independent monitored networks with
documented attacks and verifiable benign hosts. For example, a consortium of operators running
authorised red-team exercises, or a future multi-institution corpus. The revised design
(PROSPECTIVE_DESIGN.md) is ready for that case.

**Not recommended:**
- spending DEDALE, the only clean public confirmation unit, on an unpowered single-network test;
- further method development on the same 4 development networks.
