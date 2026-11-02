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
| [DEDALE_FEASIBILITY.md](DEDALE_FEASIBILITY.md) | DEDALE single-network feasibility: hosts, licence, taps, minimum download, labels, independence, memory plan, verdict |
| [DEDALE_PREREGISTRATION.md](DEDALE_PREREGISTRATION.md) | draft pre-registration of the longitudinal test (not frozen) |
| [DEDALE_MANIFEST.md](DEDALE_MANIFEST.md) | member-level download manifest with offsets, sizes and CRC32s |
| [DEDALE_STAGE_A.md](DEDALE_STAGE_A.md) | authorized calibration download and gate N1–N6 outcome (PASS) |

## Findings

1. **F1 (AIT) labels are flow-level, and attack-entity attribution is ambiguous.**
   - The attack enters through the VPN, so 94% of attack-step flows come from the VPN server's
     address. That is plausibly correct per flow, but it makes a relay the main "attacker".
   - Time-window spill-over onto other hosts is small: 3 flows.
   - In the calibration period the attacker machine sends only benign-labelled flows.
   - The probe network has 3.6 effective benign senders by flows, and 7.0 effective hosts by
     hold-out windows.
   - F1 is development or demonstration material, not confirmation evidence.
2. **F2 (UWF) has no usable benign calibration.**
   - The probe week is attack-only. The other weeks are unverified.
   - The benign partition is a single 10 MB file pooled over 7 weeks: heavily reduced, so no
     realistic benign mixture exists.
3. **Public data offers 0–1 confirmation-grade independent networks, pending verification**
   (DEDALE, Inria/DGA 2025: emulated clients, one APT campaign). OpTC would add 1 at ~940 GB.
   There are 3–6 development-grade networks besides.
4. **A powered confirmation needs at least about 15–30 independent networks**, each with
   ≥ 1,000 effective verified-benign windows, and only for a good rule.
   - It is a lower bound: the simulation models only the discrimination criteria.
   - A moderate rule needs far more, largely because its false acceptance (0.20) sits next to
     the 0.25 criterion.
   - The Phase 8k design had 3–26% power for any rule (an upper bound).
   - Three-state labels are recommended for validity, not power.
5. **History showed turnover on one network, and no behavioural change.**
   - Within-calibration turnover was 0.79 on NF-ToN-IoT vs 0.15–0.19 on NF-CIC (n = 1, post-hoc).
   - N4's dominant host drifted only after calibration, so that failure needs online
     monitoring.

## Decision: **NO-GO for network-level accept/reject confirmation**

**An adequately powered independent test of calibration-reliability *decisions* across
networks cannot be built from the public data available today:** 0–2 eligible networks
against the ≥ 15–30 needed.

This is a NO-GO and not NOT EVALUABLE: no test was run. It is a design-stage finding that the
test cannot be powered. Running one
anyway would repeat Phase 8k: an unpowered test whose likely outcomes are "not evaluable" or a
failure that says nothing about the method.

**No protected data was opened.** No download beyond the reviews of the publishers' listings
was made, and the AIT and DEDALE confirmation data remain untouched.

**What would change the decision:** a source of ≥ 20 independent monitored networks with
documented attacks and verifiable benign hosts. For example, a consortium of operators running
authorised red-team exercises, or a future multi-institution corpus. The revised design
(PROSPECTIVE_DESIGN.md) is the starting point for that case. Its power simulation must first be extended to every registered criterion.

**A narrower question is answerable, and is named here rather than dismissed:**
- *On one unseen environment, does a calibrated threshold hold its false-alert budget over
  time?* That is a single-network external validation of temporal validity, with window-level
  and host-cluster intervals.
- With N = 1 it can be pre-registered and powered at the window level. It says nothing about
  accept/reject discrimination.
- DEDALE fits it: two benign weeks for calibration, then an 8-day APT. It would cost about
  11 GB of Zeek-log downloads (approval needed), and would spend DEDALE.
- **It is not started.** First DEDALE's host count must be verified from its documentation
  (the repository blocked automated access), since emulated clients collapsed to 3.6–7
  effective hosts on AIT. Then it is a decision for the user.
- **Update (DEDALE_FEASIBILITY.md, desk assessment, no data downloaded):**
  - **Verified:**
    - the roster: 30 internal clients among about 55 VMs (the user's count; the roster gives
      about 56);
    - CC BY 4.0;
    - the label format (from code; no label file seen).
  - **Candidates:** 28 internal clients are not compromised according to the timeline. 26
    remain once clients 3–4 are excluded.
  - **Download:** the minimum is 0.78 GB of selected members from one tap, not 11 GB.
  - **Verdict:** conditionally eligible for the single-network test only, pending a gate on the
    calibration fortnight. The active, independent benign hosts are unverified, and 28 is below
    E2.
  - The draft pre-registration is DEDALE_PREREGISTRATION.md.
  - **Stage A (authorized; DEDALE_STAGE_A.md).**
    - Downloaded: 28 calibration members, 384 MB, CRC32-verified.
    - Gate N1–N6: **PASS**. There are 26 eligible internal clients, with Kish 26.0 (balanced
      clones) and 54,120 hold-out windows, and every calibration label is 0.
    - No scores were computed.
    - **The remaining risk is N8,** the dependence-adjusted n, which is checked before any
      evaluation data is downloaded.
  - **The network-level NO-GO above is unchanged; a single-network result cannot revise it.**

**Not recommended:** further method development on the same 4 development networks.
