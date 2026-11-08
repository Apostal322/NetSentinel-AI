# Phase 8r Experiment C: destination-memory contamination (feature level)

**Status:** REGISTERED (PREREGISTRATION § 6).
- Sources: `scripts/phase8r/experiment_c_features.py`, `reports/phase8r/experiment_c_features.json`.
- No model was scored.
- **M2 vetting is ORACLE-SIMULATED.** It reuses Experiment A's fit `base_r6` selections: modest
  budget, `random` draws 0–4 and `admin_persistent`.

**Scored-part gate:** a variant must restore ≥ 50 % of the documented-attack novelty gap (U → P1x)
on 02-22 or 03-02, with ≤ 5 points of extra benign novelty.

**No variant passed. The scored part (refits) was NOT RUN, and no refit authorization is
needed.**

**Amendment R-1** (PREREGISTRATION § 10): the first run implemented M3 as "≥ 2 sources OR
≥ 2 hours", because polars' `max_horizontal` ignores nulls. The independent review found it. The
rule was corrected to the registered AND, a unit test was added, and Experiment C was rerun.
Every M3 number below is from the corrected run. The gate verdict is unchanged (M3 failed under
both versions).

## Gate (medians over vetting draws)

| variant | 02-22 restored / benign +Δ | 03-02 restored / benign +Δ | passes |
|---|---|---|---|
| M3 quarantine (≥ 2 sources AND ≥ 2 hours; amendment R-1) | 0.00 / +2.9 pt | 0.004 / +3.5 pt | no |
| M2a purge of vetted-malicious destinations, `random` | 0.00 / 0 | 0.00 / 0 | no |
| M2a purge, `admin_persistent` | 0.00 / 0 | 0.004 / 0 | no |
| M2b trusted-only allowlist, `random` | 1.00 / **+78.7 pt** | 1.00 / **+84.1 pt** | no |
| M2b allowlist, `admin_persistent` | 1.00 / +66.6 pt | 1.00 / +83.1 pt | no |

## Per-network observations (feature level)

| domain | memory | size | attack-only destinations accepted | legitimate destinations rejected | doc-attack novel share | benign novel share |
|---|---|---|---|---|---|---|
| NF-CIC 02-22 | M0 P1x | 7,851 | 0 | 0 | 1.00 | 3.8 % |
| | M1 U | 7,875 | 24 | 0 | 0.00 | 3.8 % |
| | M3 | 4,290 | 1 | 3,562 | 0.00 | 6.7 % |
| NF-CIC 03-02 | M1 U | 5,591 | 9 | 0 | 0.0004 | 3.8 % |
| | M3 | 2,978 | 1 | 2,605 | 0.005 | 7.3 % |
| NF-UNSW | M1 U | 40 | 9 | 0 | 0.00 | 0.0 % |
| | M2a `random` d0 | 31 | 0 | 0 | **1.00** | 0.03 % |
| NF-ToN | M1 U | 8,166 | 7,956 | 0 | 0.36 | 25.0 % |
| | M2a `admin_persistent` | 582 | 372 | 0 | 0.37 | 25.0 % |
| | M3 | 352 | 297 | 155 | 0.38 | 37.9 % |
| NF-BoT | M1 U | 243 | 235 | 0 | 0.01 | 2.1 % |
| | M2a `admin_persistent` | 8 | 0 | 0 | **0.48** (= P1x) | 2.3 % |
| | M2a `random` d0 | 236 | 228 | 0 | 0.01 | 2.1 % |

**M3 promotion delay** (median and 90th percentile, hours from first contact):
- NF-CIC legitimate destinations: about 0.7–0.9 h (90th percentile 1.7–2.3 h);
- 02-22 and 03-02: quarantine keeps all but one attack-only destination out (promoted after
  0.6 h and 0.7 h). Even so, documented-attack novelty is not restored (0.00 and 0.005, against
  1.00 for P1x).
  - The counts imply that the one attack-only destination M3 promotes is the target the
    documented attack windows contact. It meets both conditions because many attacking sources
    reach it across hours.
  - Under P1x those windows are fully novel, and P1x differs from U only in attack-only
    destinations.
  - This is an inference from the counts; the destination was not separately inspected.

**Build runtime** (once contacts are aggregated): at most 0.1 s per variant on most domains;
1.8 s on 02-14; 10 s on NF-BoT (1.7 million calibration flows; why its M2 group-bys are the slowest was not profiled).
The domain totals (5–29 s) include reading the raw flows. **Growth:** in `growth` in the JSON.

## Reading

**A trusted-evidence purge (M2a) works only when vetting finds the attackers.**
- That happens when attackers are a large share of hosts (NF-UNSW: 4 of 21; NF-BoT: 8 of 15) or
  are the persistent hosts (NF-BoT under `admin_persistent`).
- On 02-22 and 03-02 the purge needs every attacker. There, 191 attacker hosts sit among 6,193 on
  02-22, and 10 random hosts find at most one.
- On NF-ToN, vetting 9 attackers purges most attack-only destinations, but 372 from the
  unvetted attackers remain. Documented-attack novelty barely moves: 0.36 → 0.37, against
  P1x's 0.93.

**An allowlist (M2b) restores novelty only by making almost everything novel.** Benign novel share
rises by 67–84 points. That is not detection.

**Quarantine (M3) does not restore attack novelty.** It also rejects 2,600–3,600 legitimate
NF-CIC destinations, raising benign novelty by 3–4 points on 02-22 and 03-02 and by 13 points
on NF-ToN.

**Feature versus threshold effects:**
- Separating them needs the scored part, which the gate did not open.
- Stage 1 already shows the two are separable in kind: with the unlabelled memory, even the
  oracle threshold leaves 02-22 at recall 0.003–0.016 and 03-02 at 0.0004.
- So the memory loss on those days is a feature-state effect.
