# Phase 8o gap register

Written 2026-11-03 at the start of Phase 8o.

**Starting point:**
- `main` = `origin/main` = `1ea3243`, with a clean working tree.
- Other projects' Python processes were running on the machine (causalverse, cryptocheck);
  about 2.1 GB of RAM was free.
- No NetSentinel process was running.

**Evidence:**
- saved artifacts and code;
- the Stage A audit, `scripts/phase8o/semantics_audit.py`, which reads only saved windows, the
  Phase 8m novelty columns and the Phase 8n scores (EXPLORATORY), and writes
  `reports/phase8o/semantics_audit.json`.

**Statuses:**
- **open:** not yet investigated.
- **registered:** an experiment is registered in PREREGISTRATION.md.
- **closed:** resolved, with evidence.
- **documented limit:** cannot be resolved with the data at hand.

## Status after Experiment D and the review (2026-11-03)

The tables below keep the start-of-phase wording.

| ID | outcome | evidence |
|---|---|---|
| G0.1 | **tested; partial alignment has no detectable effect.** H1 NOT SUPPORTED. The confound itself remains: F2 shows that F0's NF-CIC detection rests on the frozen-novelty attack association | MODEL_COMPARISON § 2–3 |
| G0.2 | **tested; harm not established.** H1b NOT SUPPORTED: dropping the cold-start days cuts NF-ToN recall by 0.20 | MODEL_COMPARISON § 2 |
| G0.3 | **tested; open.** C1 NOT SUPPORTED: it moves FPR toward α on 3 networks but halves NF-UNSW recall; NF-ToN is unchanged | CALIBRATION_ANALYSIS |
| G1.1 | **documented; open.** No tested method controls FPR without removing detection somewhere. Without calibration labels (C3) detection collapses through both the threshold and the memory | CALIBRATION_ANALYSIS |
| G1.2 | **closed.** No prefix K < 5 meets the rule; K = 5 is retained; cost is linear in K and small in absolute terms | ENSEMBLE_EFFICIENCY |
| G1.3 | **explained.** The flips are near-threshold clusters (margins +0.00–0.06) that ensembling stabilises. The 20 never-detected entities are representation failures far below T0 | ENTITY_ROBUSTNESS |
| G1.5 | **documented limit;** desk check found no eligible network | INDEPENDENT_DATA |
| G2.1, G2.2 | **documented;** tests pin the behaviour | `tests/unit/test_phase8o.py` |
| G2.3 | **measured** | ENSEMBLE_EFFICIENCY § 3 |
| G2.4 | **closed** (addendum) | — |

## P0: correctness and validity

| ID | gap | evidence | impact | investigation | acceptance | status |
|---|---|---|---|---|---|---|
| G0.1 | **Training rows mix two memory semantics, and the label is confounded with them.** Source calibration rows (all benign) use an expanding memory; source evaluation rows (all attack rows, plus benign) use a memory frozen at the midpoint. Target windows are always frozen | `windows.aggregate`; Phase 8b `WindowBuilder`; Phase 8h `train_matrix` (cal_clean + eval_clean) | the model can learn "frozen-memory novelty ⇒ possible attack" from how the rows were built | H1, arms F0–F4 | F3 reproduces the historical values bit for bit; the decision follows the registered H1 rule | registered |
| G0.2 | **Cold-start source memories.** In NF-CIC 2018-02-28 the time midpoint leaves 855 calibration flows against 1.74 M evaluation flows; in 2018-02-27, 331 against 591. 89 % of 02-28's 223,182 benign training rows are "novel" (mean `new_dst_frac` 0.85; other days 3–7 %) | Phase 8i `meta.json`; audit `sources` | after the 50,000-row cap, 02-28 supplies an expected 73 % of the novel *benign* NF-CIC training rows (≈ 44,700 of ≈ 61,200): a construction artifact, not network behaviour | H1b, arm F5 | registered H1b rule | registered |
| G0.3 | **The T0 hold-out underestimates evaluation-time novelty.** Share of benign windows with `new_dst_frac` > 0: hold-out (expanding) vs evaluation (frozen) | audit `targets` | T0 is set on a population the model never meets in evaluation; FPR rises where the model relies on novelty | H4, method C1 | registered C1 rule | registered |

Shares for G0.3:

| network | hold-out | evaluation |
|---|---|---|
| NF-CIC | 1.5–2.1 % | 2.0–9.8 % (rising by quarter) |
| NF-ToN | 0.9 % | 14–65 % |
| NF-BoT | 0.13 % | 1.8–8 % |
| NF-UNSW | 0.45 % | 0.03 % |

## P1: ML quality

| ID | gap | evidence | impact | investigation | acceptance | status |
|---|---|---|---|---|---|---|
| G1.1 | **Excess FPR has a different cause on each network** (M0/M2, 12 fits each, at T0) | audit `fits`; see the breakdown below | no single calibration fix can be expected to work everywhere | H4: C1 (aligned hold-out), C2 (minimum evidence), C3 (no calibration labels), C4 (shift abstention, exploratory) | per-method registered or descriptive outcome; the guardrails in PREREGISTRATION § 6 | registered |
| G1.2 | **M2 costs 5 single models;** a smaller K has never been evaluated | Phase 8n FREEZE_CANDIDATE | inference cost | H2: K = 1, 2, 3, 5 nested members on fresh randomness; measured inference cost | registered H2 rule | registered |
| G1.3 | **Whole-entity flips** on single-attacker days; 20 entities never detected | Phase 8n | missed attackers | H3: member-level (30 single-model fits) and ensemble-level entity analysis | descriptive (registered metrics) | registered |
| G1.4 | **Frozen-memory attack novelty is a dataset-specific signal.** Attack windows are 100 % novel on NF-CIC 02-14 and 03-02 and 99.9 % on NF-UNSW, but 0 % on 02-16, 02-20 and 02-21 | audit `sources` | detection of brute force and scans rests on "a destination never contacted during calibration" | reported with H1; no fix this phase | — | documented |
| G1.5 | **No independent confirmation** | Phase 8n G1.5 | — | desk check only, no download (§ Part 13) | — | documented limit |

Causes behind G1.1:

| network | FPR | dominant supported cause |
|---|---|---|
| NF-CIC | 1.2–1.6 % | close to α; the novel windows alert at 8–14 % |
| NF-UNSW | 4.3 % | the hold-out has 443 windows in 17 host-hour blocks (insufficient independent calibration evidence); false alerts are not novel |
| NF-ToN | 14–16 % | 99 % of false alerts are novel windows; FPR 28–31 % on hosts first seen after the freeze vs 8–9 % on known hosts; 5 hosts carry 93 % of false alerts (stale memory plus host turnover) |
| NF-BoT | 10–12 % | every false alert comes from 2 benign hosts; the hold-out has 80 host-hour blocks (host concentration and too little evidence) |

## P2: supporting engineering

| ID | gap | evidence | status |
|---|---|---|---|
| G2.1 | **A missing `out_pkts` is read as "no reply".** `prepare_flows` fills nulls with 0, so one-directional telemetry gives `no_reply_frac` 1 and `upload_share` ≈ 1, and looks like scanning. `telemetry_health` is supplied by the caller, not derived from null rates | `windows.prepare_flows`; `inference/assessment.py` | documented; a regression test pins the behaviour. No change to the deployed feature behaviour without authorization |
| G2.2 | **Batch/streaming equivalence of `aggregate` holds only for window-aligned chunks.** A window split across two calls yields two partial rows. The live windower (`streaming/live.py`, 360 s lateness) closes whole windows | `windows.aggregate` | tests added (window-aligned equivalence; split-window behaviour) |
| G2.3 | **Inference cost of M2 never measured** | Phase 8n reported only training time | measured (`scripts/phase8o/profile_inference.py`) |
| G2.4 | **Publication-status notes.** The Phase 8n report says "nothing pushed"; `1ea3243` is on `origin/main` | `git log origin/main` | editorial addendum |
| G2.5 | **CI not verifiable** (`gh` not installed) | shell | documented limit |
