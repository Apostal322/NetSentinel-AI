# Phase 8m: memory contamination (H2)

**Source:** `reports/phase8m/contamination.json`, produced by `scripts/phase8m/contamination.py`.
- It replays the saved P1x contact stream of each domain through `NoveltyMemory`, restoring the
  calibration checkpoint for each scenario.
- Runtime: 171 s; peak 0.6 GiB.
- **Labels:**
  - H2 measures: REGISTERED DEVELOPMENT;
  - the injected beacons are SYNTHETIC traffic;
  - the parameter grid is EXPLORATORY.

## H2: NOT SUPPORTED

The measures are pooled as registered (amendment 2): mean over a network's domains, then an
equal-weight mean over networks.

| measure (registered threshold) | value | result |
|---|---|---|
| single-host beacon windows still novel under A3 (≥ 95 %) | **100 %** on every network | met |
| … under A1 (≤ 5 %) | 3.5 % (NF-CIC 9.2 %, NF-UNSW 4.4 %, NF-ToN 0.5 %, NF-BoT 0.1 %) | met |
| benign post-freeze destinations promoted by A3 (≥ 50 %) | **5.5 %** (NF-CIC 16.2 %, NF-ToN 0.15 %, NF-BoT 0 % of 2) | **not met** |

Notes on the measures:
- **NF-UNSW has no post-freeze destination contacted only by benign hosts.** So the third measure is
  the mean of the other 3 networks. NF-BoT's value rests on 2 destinations.
- **Even with NF-UNSW set to 100 %**, the mean would be 0.29, so the verdict does not depend on this.
- **Only the third clause is empirical.**
  - Under A3, a destination with one source can never be promoted, so the single-host share is
    1.0 by construction.
  - The A1 share is 1 / (number of beacon windows), so it depends only on evaluation length and
    beacon period.
- The A1 value is above 5 % on NF-CIC only because a single evaluation day holds few 1-hour beacon
  windows: one novel window in about 11 is 9 %.

**Reading.** The guarded memory is safe against a single-host beacon by construction, but it almost
never adapts.
- Most benign destinations first seen after the freeze are contacted by one host only, or never
  for an hour by two.
- So they stay "novel" for ever, exactly as under the deployed frozen memory.
- Benign adaptation, the reason for the method, therefore does not happen at the registered
  parameters.

## Synthetic beacons

The most active verified-benign evaluation host beacons to a fresh destination. In the two-host
variant, the second most active host does too.

| period | single host: novel A3 / A1 | two hosts: accepted by A3 after |
|---|---|---|
| 1 min | 100 % / ≤ 0.6 % | **1.0 h** (every domain) |
| 10 min | 100 % / ≤ 5.6 % | 1.0 h |
| 1 h | 100 % / ≤ 33 % (a few windows per day) | 1.0 h |

- **Two hosts defeat the guard in exactly the registered span.** Two compromised hosts beaconing to
  the same C2 make it normal after 1 hour, at any beacon period.
- **Alert change at B2's frozen T0** (1-min single-host beacon, the host's existing windows that
  carry it, seed mean). Only the novelty columns change (amendment 2).
  - The host is verified benign, so the baseline alerts are false alerts; this does **not** measure
    detection of the beacon.
  - The change mixes three effects: the dilution of the novel share, `familiarity_decay` (the beacon
    was contacted a minute earlier) and `log_prevalence`.
  - Values:
  - NF-CIC 2018-02-21: 6 % → 54 %;
  - the other NF-CIC days and NF-UNSW: no change, at ≤ 3 %;
  - NF-ToN-IoT: 0.2 % → 0.03 %;
  - **NF-BoT-IoT: 50 % → 0 %.** Adding a novel destination *lowered* B2's score on this host.
- **These alert changes are model properties, not policy properties.** How large the column changes
  are depends on how many destinations the host contacts; how B2 weighs them depends on what it
  learned from the source networks.
- **NF-BoT-IoT matters for evasion:** there, adding a beacon *suppressed* B2's alerts on the host.

## Real attack traffic

Evaluation-period attack windows contact destinations that were unknown at the freeze. The A1
memory learns every one of them after one window, by definition. Share the A3 memory promoted by the
end of evaluation:

| network | post-freeze attack destinations | promoted by A3 | median time to promotion |
|---|---|---|---|
| NF-UNSW-NB15 | 9 | **100 %** | 1.0 h |
| NF-ToN-IoT | 218 | **45 %** | 11.1 h |
| NF-BoT-IoT | 69 | 12 % | 1.0 h |
| NF-CIC (6 days) | 0–4 per day | 0–33 % | 1.0 h |

- **The accounting is asymmetric, so read it with care.**
  - The "attack" set is every post-freeze destination an attacker contacted in a labelled attack
    window, even if benign hosts contacted it too.
  - The "benign-only" set excludes anything an attacker ever contacted.
- **Who made the promoted attack destinations reach ≥ 2 sources** (checked from the contact stream
  after review):

  | network | promoted attack destinations | with ≥ 2 attacker sources | also with a benign source |
  |---|---|---|---|
  | NF-UNSW | 9 | 9 | 3 |
  | NF-BoT-IoT | 8 | 8 | 1 |
  | NF-ToN-IoT | 99 | 73 | 52 |

- **So coordinated attacks alone are enough to satisfy the "≥ 2 sources over ≥ 1 h" rule** on all
  three networks.
  - On NF-ToN-IoT, about half of the promoted destinations are shared with benign hosts.
  - These are labelled "attack destinations", not verified victims.
- **Not computed:** the registered "recall in their windows" measure.
- **The result:** attack-window novelty collapses (MODEL_COMPARISON.md: NF-UNSW 0.999 → 0.114,
  NF-ToN 0.759 → 0.115), while benign novelty barely moves.
- **So the guard accepts attacker-contacted destinations far more readily than benign-only ones,**
  the opposite of its purpose. Part of the gap comes from the shared destinations described above.

## Negative controls

- **A0 (frozen) and always-quarantine:** no post-freeze promotion, and 100 % of beacon windows
  novel. This is safe by construction, with zero adaptation. It is the deployed behaviour and the
  source of the stale-novelty false alerts on NF-ToN-IoT and DEDALE.

## Sensitivity grid (EXPLORATORY; memory level, no retraining)

The grid covers sources {2, 3} × span {10 min, 1 h, 6 h}. τ points need retrained models and were
not run (amendment 2).

| network | benign promotion | attack promotion |
|---|---|---|
| NF-CIC | at most **33 %** (2018-02-21, 2 sources / 10 min); 0 % at 6 h | 0–33 % |
| NF-ToN-IoT | ≤ 0.2 % at every point | 20–47 % |
| NF-UNSW | (no benign-only post-freeze destination) | 100 % at every point |

- **No setting reaches 50 % benign promotion.**
- **Stricter settings cut benign promotion faster than attack promotion,** for example
  3 sources / 6 h on NF-ToN-IoT: benign 0 %, attack 20 %.
- Within this family of rules, no parameter separates benign adaptation from attacker acceptance on
  these networks.
