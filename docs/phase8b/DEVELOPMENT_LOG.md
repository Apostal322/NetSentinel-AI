# Phase 8b development log (exploratory work before the next confirmatory test)

Goal: stronger independent evidence (docs/HYPOTHESIS_LEDGER.md gaps 1-4). Fresh captures are
downloaded and hashed, but not read until the Phase 8b plan is frozen.

## Fresh data

| Capture | Family | Bytes | SHA-256 | Status |
|---|---|---|---|---|
| IoT-23 CTU-IoT-Malware-Capture-1-1 | Hide and Seek | 148,305,428 | `953e8c27a9b2fcfc2776aa136baf9249e6dde4cf752b9192ac7ca0e63b86e232` | downloaded, not read |
| IoT-23 60-1 | Gafgyt | 467,559,811 (HTTP size) | — | needs download approval |
| IoT-23 9-1 | Hajime | 993,459,767 (HTTP size) | — | needs download approval |

- Licence: IoT-23 is CC BY 4.0 (Zenodo 10.5281/zenodo.4743746); cite Garcia, Parmisano,
  Erquiaga (2020).
- Consumed and never fresh again: 49-1 (Phase 8), plus the CIC and NF test sets.

## Why P8-H3 failed (to be investigated on development data only)

Mechanism on 49-1, known from the confirmatory output:
- the infected device produced 1 pure incident;
- the 9 false-alert windows on benign devices were isolated, so each became its own
  incident;
- mean purity over incidents was therefore 0.10.

The criterion weighted every incident equally, and the aggregation reported single-window
deviations as `medium` incidents.

**Rule selection, fixed before running `scripts/phase8b/incident_rules.py`:**
- Candidate rule R(k, r): an incident is *reportable* once it has >= k anomalous windows OR
  its max score/threshold >= r, for k in {1, 2, 3} and r in {1.5, 2, 3, 5, inf}.
- R(1, inf) is the Phase 8 behaviour (every incident reportable). Non-reportable incidents
  remain stored with status `insufficient_evidence`; nothing is deleted.
- Data: development captures only (IoT-23 x9 inspected, NF-UNSW dev, CTU-Normal x12), product
  robust_z scores, clean calibration, gap 300 s.
- Objective: minimise pooled benign-only reportable incidents per hour, subject to:
  - attacking-entity recall (entities with >= 1 reportable incident containing an attack
    window) >= 0.95 x that of R(1, inf);
  - the median entity-level delay to the first reportable incident rising by <= 60 s.
- Ties go to the simpler rule (smaller k, then larger r).
- The selected rule is then pre-registered for the fresh captures (Phase 8b plan). It is not
  adopted in the product before that test.

## Result: incident rules (exploratory, `reports/phase8b/incident_rules.json`)

- **Diagnosis.** On development data the P8-H3 mechanism is the norm, not a 49-1 accident.
  - 161 of 193 incidents (Phase 8 behaviour) are single-window, and 139 of those are
    benign-only.
  - Incident-mean purity: **0.17**. Window-weighted purity: **0.84**.
  - Most alerted windows belong to attacks; most incidents are isolated false alerts.
- **No reportability rule meets the pre-declared constraint.**
  - k >= 2 or 3 cuts benign-only incidents from 1.43/h to 0.15-0.35/h.
  - But attacking-entity recall drops from 0.9 to 0.2-0.5: the product scorer also detects
    many real attackers through a single window.
  - Score-ratio thresholds do not separate the two groups.
- Selected per the rule: **R(1, inf)**, i.e. no change to the product.
- Consequence for the next test:
  - P8-H3's incident-mean purity is replaced by window-weighted purity plus alert reduction
    (B6);
  - incident-mean purity stays a reported secondary metric;
  - P8-H3 itself stays refuted.

## Result: unified comparison (exploratory, `reports/phase8b/dev_compare.json`, 3.5 min, 1.3 GB)

Leave-one-capture-out over 22 development captures; device windows; 3 eligible units
(3-1, 34-1, NF-UNSW).

| scorer | clean PR-AUC | unlabelled PR-AUC | median false alerts/h (clean) |
|---|---|---|---|
| lgbm_raw (trained on other captures) | **0.901** | **0.862** | 0.62 (@source) / 2.5 (@local) |
| lgbm_local | 0.890 | 0.836 | 0.0 (@source) |
| robust_z | 0.846 | 0.672 | 0.91 |
| robust_z_product | 0.833 | 0.766 | 0.0 |
| guarded_ewma | 0.723 | 0.737 | 0.73 |
| gru / tcn / lag_iforest | 0.682 | 0.64-0.65 | 0-0.5 |

- **Cross-dataset (NF-UNSW, sources = IoT-23 + CTU):**
  - lgbm_raw: PR-AUC 0.804, recall 0.57 at FPR 0.031 (41 false alerts/h: UNSW has many
    device windows per hour);
  - robust_z_product: PR-AUC 0.597, FPR 0.034, recall 0.003;
  - median per-feature KS shift to the sources: 0.70.
- **Delay.** Observable delay (end of first attack window -> first alert) is mostly 0 s;
  robust_z_product 255 s. Delays from attack start are hours (Zeek logging of long
  connections).
- These motivate B1-B6 in [RESEARCH_PLAN.md](RESEARCH_PLAN.md).
- Dry run of `confirm.py` on 34-1 and 3-1 (development, software check only): all paths ran,
  92 s, 1.4 GB.

## Fresh data (completed 2026-10-21)

- 60-1: 467,559,811 B, SHA-256 `4e15902f6c39b1fad60605e667761b10c0c9866beb514aa6320b7baf108ea7c0`.
- 9-1: 993,459,767 B, SHA-256 `b2749ab394d6a8f96dab5f9aa0e848c9c5b85ad4a6fa3034040d718de56c918b`.
- Both are evaluated; see [CONFIRMATORY_RESULTS.md](CONFIRMATORY_RESULTS.md). All four fresh
  IoT-23 captures (49-1, 1-1, 60-1, 9-1) are now consumed.

## Open question for the next development cycle (do not use the fresh captures for it)

Why does the deployed robust_z_product path detect none of the attackers on 1-1, 60-1 and 9-1,
while ranking them well (PR-AUC 0.92-0.95)? It detected 9/10 development attackers. Investigate
on development data only (threshold method, per-device vs pooled profiles, top-k scoring),
then test any change on a new fresh capture.
