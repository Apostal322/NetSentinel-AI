# Phase 8l independent skeptical review

**Reviewer:** a separate, read-only agent given the files of commit `f71dbfe` (not my
conclusions). It ran two short sensitivity simulations of its own.

**Verified correct:**
- **Power simulation code:**
  - Clopper-Pearson bounds;
  - E3 on the determinable count;
  - the hypergeometric call order and edge cases;
  - the family-shift construction.
- **Every power table value** matched the JSON.
- **Label-audit arithmetic:**
  - 146,292 / 155,250 = 94.2%;
  - 218 benign-labelled = 2.4% of 9,176;
  - all 36 steps between hours 75.02 and 76.0;
  - 15,778 exfiltration flows, all to the attacker as server;
  - 35 never-malicious sources, 3.56 effective.
- **Data access:** no committed code reads any AIT network other than the spent probe, any UWF
  week other than the probe, or `csv/Benign/`.

**Decision:** NO-GO is supported, and the blocking finding strengthens it. It should be scoped to
network-level accept/reject confirmation, and the narrower single-network option should be
named.

| finding | severity | disposition |
|---|---|---|
| The prospective design's minimum N is not supported for its own criteria. Per-family FAR ≤ 0.25 is unattainable in families of 2–3: power fell from 0.35 (N = 20) to 0.09 (N = 50). Criteria (c), (e) and U(c) are not modelled | blocking | per-family FAR dropped in favour of pooled FAR with a family-level permutation test; every minimum N is now labelled a **lower bound**; the design requires the simulation to be extended to all criteria before registration |
| "Verified benign would include the attacker" contradicts the JSON: the attacker is excluded through its 8,958 scan flows | should fix | reworded: the problem is the calibration period (P1x), where the attacker sends only benign-labelled flows |
| The 94% "on the VPN" figure was shown as label error; it is mostly expected relay traffic, and time-window spill-over is 3 flows | should fix | reframed as ambiguous attack-entity attribution, in the label audit and the README |
| "3.6–7 effective hosts per network" combined two metrics from one network | should fix | both labelled (3.6 by flows over the capture; 7.0 by hold-out windows); "per network" dropped |
| The UWF probe numbers were not reproducible; "parquet is attack-only" was generalised from one week | should fix | `scripts/phase8l/uwf_probe_audit.py` and `reports/phase8l/uwf_probe_audit.json` added; the claim is restricted to the probe week |
| The rejection of `csv/Benign/` rested on the wrong argument | should fix | it now leads with the pooled, heavily reduced benign partition; the streaming option is named as not pursued |
| Power: point labels are *more* powerful at prev ≤ 0.5; three-state was justified on power | should fix | three-state is now justified on validity; both columns are shown |
| The dependence shift was not mean-preserving; the moderate and weak conclusions are threshold artefacts | should fix | the shift is centred (marginal rates checked: 0.900 / 0.100 / 0.200); the model is labelled optimistic; the moderate/weak dependence on the 0.25 threshold is stated; F1-like power is now 3–26% (an upper bound) |
| DEDALE overstated as "E1–E7 met strictly" | should fix | now "0–1 confirmation-grade unit, pending verification". Consumed Stratosphere datasets added to the inventory. The host count could not be verified: the RESCOUSSE repository blocked automated access |
| M5 primary was inconsistent with demoting M1 as circular; M2 hidden behind M5; "dominance" claim | should fix | **M2 is now primary**, with a fixed sequence M2 → M5 → M6 → M1. The same circularity standard applies to M1 and M5, and M5 claims turnover only |
| The turnover claim overstated (n = 1, confounds) | should fix | retitled "visible in history on NF-ToN-IoT (n = 1)", with its confounds listed |
| `REVIEW.md` missing; gate-name clash; method-specific adequacy could turn failures into NOT EVALUABLE; U(c) aggregation unspecified; F1-like n_eff assumed | minor | this file; gates renamed G1–G3; G2 judged at the common T0; U(c) macro-averaged; F1-like n_eff marked as assumed |
| The narrower single-network validation was dismissed in one line | should fix | named in the README as an answerable, different question (temporal validity on one unseen environment), not started, pending verification of DEDALE's host count and the user's decision |

**Sensitivity simulations by the reviewer** (they leave the conclusion unchanged):
- the adequate range further from 2% gives a minimum N of about 16;
- point labels give 16;
- estimation with intervals needs about 80;
- the order-of-magnitude gap to the 0–2 available networks holds.

## DEDALE feasibility package: independent review

**Reviewer:** a separate, read-only agent given the files, not my conclusions. It made no
downloads.

**Verified:**
- 22 of 24 numeric claims, checked against the reports, the Dataverse API and the DEDALE pages;
- the zip offsets;
- the zip64 field order;
- the validity of the gzip wrapper.

**Decision:** "conditionally eligible, single-network only" is justified, and the Stage A
request is minimal.

| finding | severity | disposition |
|---|---|---|
| Evaluability rested on `neff_m3` of evaluation alerts, so a real failure (clustered alerts) could become NOT EVALUABLE | blocking | N9 now uses counts only; FAILS is possible at any n; the score-based check (N8) runs on the hold-out before Stage B |
| "Week 4 is after the attack" was false: beacons continue to 13 January | blocking (fact) | the periods follow the timeline: attack period 6–13 January, post-attack period 14–19 January |
| Assigning flows by folder could stop the study (long flows, CET folders) | should fix | assignment by flow end time, with a tolerance in N2 |
| Hosts were keyed by IP although DHCP may move leases | should fix | hosts are keyed by MAC through DHCP leases when they exist; IP otherwise |
| Clients 3–4 may be involved (the publisher's forensic artefacts cover clients 1–4) | should fix | excluded in the primary analysis, included in a sensitivity analysis; at most 26 candidates |
| The meaning of the 590 gate was unclear; HOLDS was worded as "≤ 2 %" | should fix | explained (Clopper-Pearson claim rule vs the 313 conformal guarantee); the ledger wording corrected |
| The destination-memory asymmetry was not stated | should fix | stated, and its share of false alerts reported |
| Fetch checked only the header signature; `.part` was left on errors | should fix | checks name, Content-Range total and leftover data; `try/finally` cleanup; tests added |
| An empty freeze file would unlock Stage B | minor | it must be tracked in git and hold the pre-registration's SHA-256 (LF-normalised) |
| zip64 locator not found; 4-byte disk field | minor | explicit error; the field is ignored |
| Arithmetic: 780.2 MB, 8.4 % by count, router 4.1 GB; "55 VMs verified"; labels "verified" | minor | corrected |
| Evaluation-day archive metadata was read (sizes, `pe.log` on D17) | minor | disclosed in the pre-registration |
| Use the repository's own citation; disk needs missing from the manifest | minor | both added |

## DEDALE analysis code: independent pre-freeze audit

**Reviewer:** a separate, read-only agent. It opened no data and ran no data script.

**Verified:**
- T0 rank and strict alert;
- the seed-mean;
- `neff_m3` row order;
- the Clopper-Pearson and bootstrap bounds;
- H1, H2 and N9 logic;
- Holm and M2;
- the window-truth index;
- lease attribution;
- labels kept out of the features.

**Verdict:** not ready until findings 1–3 were fixed. The dispositions are below.

| # | finding | severity | disposition |
|---|---|---|---|
| 1 | Stage B was not locked on N8 PASS | blocking | `download("B")` requires `freeze_ok()` and `n8_passed()` |
| 2 | N7 checked models against an editable report; code hashes were never verified; the freeze file was not checked against HEAD | blocking | `freeze_ok` verifies every `<sha256>  <path>` line (LF-normalised) and a clean HEAD for the freeze file and listed tracked files; used by all modes |
| 3 | Exclusions found only in evaluation DHCP could change T0 after unblinding | blocking | T0 is fixed at N8 from calibration-only attribution; late exclusions leave only the evaluation sets (amendment 4) |
| 4 | The daily tests included weekends | should fix | weekdays only |
| 5 | Unparseable evaluation rows could drop attack labels | should fix | truth from every row with parseable time, source and label; unparseable rows counted by label |
| 6 | The entity host was arbitrary under several hosts | should fix | the host holding the address at compromise time |
| 7 | The secondary population's threshold was unstated | should fix | primary T0 (amendment) |
| 8 | Time assignment by window end put boundary windows on the wrong day | minor | `window_end_ms − 1` |
| 9 | Excluded-host alerts could undercount | minor | all excluded addresses |
| 10 | `--n8` did not check Stage A | minor | it does |
| 11 | The logistic fit diverges with no alerts | minor | reported as undefined |
| 12 | `W_MS` was hard-coded | minor | asserted against the builder |
| 13 | `cal_scores.npy` was not hashed | minor | hashed in the N8 report and checked in `--final` |
| – | Test gaps | – | tests added for: freeze verification, the N8 lock, weekdays and time helpers, the logistic guard, `overrun_p` against scipy, Holm ties, lease ties and missing leases, calibration-host exclusion, and the truth/builder window index. No end-to-end run on synthetic data (the modes need the frozen repository state); the run modes' internal consistency checks (T0, hosts, scores, calibration windows) stop on any mismatch |
