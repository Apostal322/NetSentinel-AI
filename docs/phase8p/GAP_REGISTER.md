# Phase 8p gap register

Written 2026-11-03.

**Starting point:**
- `main` = `origin/main` = `8e5d079`, with a clean tree and no tags.
- CI is configured (`.github/workflows/ci.yml`), but its status is not verifiable (`gh` is not
  installed).

**Evidence:** ATTACK_OBSERVABILITY.md (Stage 1, EXPLORATORY) and the code paths below.

## Code map

| function | code |
|---|---|
| flow ingestion | `src/netsentinel/telemetry/*`, `scripts/phase8i/build_windows.py` (`chunks`, development cut, `with_flags`) |
| 30 s source windows | `src/netsentinel/behavior/windows.py` (`prepare_flows`, `aggregate`) |
| destination memory | `windows.aggregate(known_dst / prior_dst)`, `behavior/novelty.py` |
| model training (M0/M2) | `scripts/phase8n/candidates.py` (`source_data`, `fit_one`), `scripts/phase8i/common.py` (`LGB`) |
| M2 inference and per-member scores | `scripts/phase8o/experiment_d.py` |
| calibration (P1x, T0) | `scripts/phase8j/build_p1x.py`, `scripts/phase8b/scorers.py` (`split_cut`), `scripts/phase8o/analyze_d.py` (`t0_of`) |
| entity metrics, delay | `scripts/phase8o/analyze_d.py` (`metrics`, `summarise`) |
| streaming | `src/netsentinel/streaming/live.py` (closes whole windows, 360 s lateness) |
| **new:** victim windows and source context | `src/netsentinel/behavior/victim.py`, `scripts/phase8p/build_victim.py` |

## Gaps

| ID | gap | evidence | impact | investigation | status |
|---|---|---|---|---|---|
| P0.1 | **Entity evaluation counted label artifacts as missed attackers** | 19 of the 20 never-alerted entities are undocumented sources on NF-CIC 02-22 | Phase 8n/8o "missed web attacks" overstated | role audit; documented-attacker set primary in Experiment E | registered |
| P0.2 | **02-20 "LOIC-HTTP" evaluation windows are the onset of the documented DDoS-LOIC-UDP attack under the HTTP class label;** the HTTP flood (99.3 % of its flows) is in calibration. *Corrected after review: first described as post-attack residue* | ATTACK_OBSERVABILITY § 3 | the "LOIC miss" concerns a mislabelled UDP/SYN flood onset, not the HTTP flood | documented; kept as a documented-attacker target | documented |
| P0.3 | **The deployed memory semantics remain confounded with the label** | Phase 8o | — | not re-opened | documented (Phase 8o) |
| P1.1 | **Documented misses separable in-domain but not detected cross-network** (02-20 LOIC; NF-ToN .37 weakly) | ATTACK_OBSERVABILITY § 3 | the gap is not missing in-domain evidence; whether evidence transfers is the question | H1 (victim context), H2 (service), H3 (fusion) | registered |
| P1.2 | **Calibration needs confirmed calibration-period labels** (Phase 8o C3) | Phase 8o | deployment realism | H4: C1 unlabelled, C2 delayed labels, C3 host-balanced | registered |
| P1.3 | **No victim-side representation existed** | code map | attacks visible mainly at the victim cannot be expressed | `behavior/victim.py` (16 VW + 5 context + 4 service features), 8 tests | implemented |
| P2.1 | **Memory leak in the victim build:** small kept slices of string columns pinned whole slices (NF-ToN peaked 3.3 GiB; NF-BoT exceeded the cap) | build logs | — | contacts written per slice; peaks now 1.2–1.7 GiB | fixed |
| P2.2 | **The Stage 1 inventory exceeded the cap** when collecting NF-BoT/ToN attack flows | logs | — | lazy streaming aggregates | fixed |
| P2.3 | **The univariate AUC broke ties by position;** a first reading called the LOIC source side weak | ATTACK_OBSERVABILITY § 4 | — | average ranks | fixed before registration |
| P2.4 | The CSE-CIC-IDS2018 local-time offset was first assumed UTC−5; the data fixes UTC−4 | `observability.py` | interval shares | corrected before registration | fixed |
| P2.5 | **The documented-interval table missed 02-20's DDoS-LOIC-UDP row** and pooled the 02-14/02-16 intervals across attackers (found by the independent review) | official table | the "post-attack residue" reading was wrong | per-attack, per-host intervals; roles unchanged | fixed after review |
| P2.6 | **D3's empirical-CDF fusion is not tie-safe:** T0 = 1.0 on NF-UNSW, so it cannot alert | INDEPENDENT_REVIEW | NF-UNSW D3 not operable | documented; the verdict does not depend on it (NF-BoT guardrail) | documented (registered design) |
| P2.7 | `victim_windows` relied on a join keeping row order without `maintain_order` | review | none observed (max error 1e-14) | `maintain_order="left"` | fixed after review |
