# Phase 8n gap register

Written 2026-11-03 at the start of Phase 8n.
- **Starting point:** `main` = `origin/main` = `80c0b5c`; clean working tree; no tracked or
  untracked changes.
- **Evidence:** saved artifacts and code. Each line says where it comes from.

**Statuses:**
- **open:** not yet investigated.
- **investigating:** an experiment is registered.
- **closed:** resolved, with evidence.
- **documented limit:** cannot be resolved with the data at hand.

## P0: validity of evaluation and inference

| ID | gap | evidence | severity / risk | investigation and fix | cost | status |
|---|---|---|---|---|---|---|
| G0.1 | **The NF-CIC collapse is unexplained** (Phase 8m): every retrained variant reaches recall ≈ 0 on 02-14, 02-16 and 02-21, where B0 and Q1 reach 0.96–0.996 | `reports/phase8m/model_comparison.json`; Phase 8n diagnostic (below) | high: any feature or training change could be misjudged as good or bad | Experiment A (factorial perturbations, below) | ≈ 1 h CPU | investigating |
| G0.2 | **The B0 reference must be reproducible** before any comparison | Phase 8m B0r: max \|Δ\| 0.0; Phase 8n `fragility.py` P_ref (NF-CIC, seed 0): 0.0 on 6 days | high if it failed | P_ref is rerun for every target and seed inside Experiment A | included | closed for NF-CIC seed 0; full check in Experiment A |
| G0.3 | **Ranking vs threshold** were never separated for the failures | first diagnostic (below) | high: a calibration effect could be read as a model effect | per-case AUC, ranking recall at the benign 99th percentile and T0, in `analyze_fragility.py` | none | investigating |
| G0.4 | **Attacks on a day are few independent units**: 02-14 and 02-16 each have 1 attacker entity, 02-21 has 10 | Phase 8m bootstrap degenerate on 02-14/02-16 | high: correlated windows can look like strong evidence | results reported at entity level; intervals marked degenerate; NF-CIC days never counted as independent networks | none | documented limit |
| G0.5 | **P1x assumes confirmed calibration-period attacker labels.** A deployed model does not have them | Phase 8j DATA_INTEGRITY_AUDIT; Phase 8m REVIEW (seen-host artefact) | medium: optimistic calibration | stated in every Phase 8n result; no change of protocol (Phase 8j frozen) | none | documented limit |

## P1: robustness, generalisation, detection

| ID | gap | evidence | severity / risk | investigation and fix | cost | status |
|---|---|---|---|---|---|---|
| G1.1 | **B0 is seed-unstable on NF-CIC 2018-03-02** | the seeds score 0.855 / 0.057 / 0.161 recall, with attack median within 0.04 of T0 (diagnostic below) | high: the deployed model's recall depends on the seed | Experiment A (A5) quantifies it; Experiment B tests seed ensembling and regularisation | in A / B | investigating |
| G1.2 | **The models learn `new_dst_frac` interactions** that other features cannot replace after a refit | the contributions (below): B0 attack windows on 02-14 get +3.0 from `new_dst_frac`; on 02-16 (non-novel attacks) +1.8 from `rst_frac`, which the 11-feature refit no longer gives | high | Experiment A: A4 drop of each feature, shuffle control, A2 no-op controls | in A | investigating |
| G1.3 | **Retrained variants score NF-CIC benign traffic much higher:** benign 99th percentile 0.97–0.98 against B0's 0.82–0.88 | diagnostic below | high: the threshold rises and the attacks fall under it | Experiment A; Experiment B (domain reweighting, regularisation) | in A / B | investigating |
| G1.4 | **No worst-case or entity-level selection criterion** for model choice. Mean recall hides total misses | Phase 8m used network means | medium | Experiment B/C selection rule with entity-level catastrophic-failure counts (to be registered after A) | none | open |
| G1.5 | **Candidate selection on consumed development networks.** No independent confirmation set exists (DEDALE consumed; AIT and UWF ineligible) | Phase 8l, 8k | high for claims | any Phase 8n candidate is development-only; a freeze package is prepared only if a candidate passes | none | documented limit |

## P2: supporting engineering and documentation

| ID | gap | evidence | fix | status |
|---|---|---|---|---|
| G2.1 | The Phase 8m report says "local only, never pushed", but 80c0b5c is on `origin/main` | `git log origin/main` | editorial addendum, without changing results | closed (addendum in `docs/phase8m/FINAL_RESEARCH_REPORT.md`) |
| G2.2 | `docs/HYPOTHESIS_LEDGER.md`, `docs/RESULTS.md` and the README have no Phase 8m entries | grep | added at Phase 8n closure | open |
| G2.3 | The model artifacts carry no feature-schema identifier. Phase 8m boosters were trained on 11–16 columns, and nothing stops loading one with the wrong column list | `data/derived/phase8m/models/*.txt`; LightGBM stores only `Column_k` names | check the expected feature count at load; register a schema id per variant in the Phase 8n outputs | open |
| G2.4 | The CI status cannot be checked from here (`gh` is not installed) | shell | reported as not verified | documented limit |

## First Phase 8n diagnostic (no training; saved Phase 8j and 8m scores)

**Labels:** EXPLORATORY; the networks are consumed development data.

**NF-CIC, per seed:**

| day | B0 | retrained variants (B2, A_none, B1u) | reading |
|---|---|---|---|
| 02-14 | AUC 0.993–0.999 | AUC 0.52–0.59 | ranking collapse |
| 02-16 | AUC ≈ 0.98 | AUC 0.48–0.84; recall 0 | mostly ranking |
| 02-21 | AUC ≈ 0.998 | A_none AUC 0.86–0.93, recall 0 | attacks just under a raised benign tail: mostly threshold |
| 03-02 | recall 0.855 / 0.057 / 0.161 by seed | — | B0's own instability; attack median 0.84–0.87 against T0 0.82–0.875 |

**The benign tail in the retrained variants:**
- Every retrained variant pushes the benign 99th percentile to 0.97–0.98, against B0's 0.82–0.88.
- So T0 rises to about 0.97.
- Q1 (B0's models, novelty input substituted) keeps B0's ranking on 02-14, 02-16 and 02-21. It
  loses it on 03-02 and 02-22.

**Contributions** (`pred_contrib`, seed 0). These are model attributions, not causes:
- **02-14:** B0's attack windows get `new_dst_frac` +3.0 and `log_flows` +2.5. The 11-feature refit
  keeps `log_flows` (+2.8) but is pulled down by `log_pkts` (−1.0), and its margin turns negative.
- **02-16:** the attack windows have `new_dst_frac` = 0. B0 scores them through `rst_frac` (+1.8);
  that contribution is absent after the refit.

**Hypotheses:**
- The learned interaction structure, not the novelty value itself, carries B0's NF-CIC detections.
- The missing piece is whether *any* refit does this, or only one that loses `new_dst_frac`.
  Experiment A tests that.
