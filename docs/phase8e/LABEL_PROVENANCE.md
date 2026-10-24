# ToN_IoT label provenance audit (Phase 8e, Mission 1)

**Status:** retrospective analysis of the consumed ToN_IoT files 1-4 (Phase 8c confirmatory
data). The published Phase 8c verdicts and numbers (X1-X5,
`docs/phase8c/EXTERNAL_RESULTS.md`) are unchanged. The reinterpretation in section 4 is
reported separately and is not a new confirmatory claim.

Scripts: `scripts/phase8e/label_provenance.py`, `scripts/phase8e/initiator_reinterpretation.py`.
Outputs: `reports/phase8e/label_provenance.json`, `initiator_reinterpretation.json`.

## 1. The discrepancy

- **Documentation** (UNSW project page): "ground truth ... labelled by tagging source IP
  addresses (192.168.159.30-39) with their timestamps".
- **Phase 8d observation:** none of the 40 sources with attack-labelled flows lies in that
  range.

## 2. Findings (measured on files 1-4)

| Question | Result |
|---|---|
| Attack types present | only `scanning` (3,776,528 flows); 223,472 `normal` |
| Does 192.168.159.x appear at all? | **no**: 0 flows as source, 0 as destination |
| Who sends the scanning traffic? | 192.168.1.32 (1,719,458 flows), 192.168.1.30 (1,075,202), 192.168.1.31 (875,752): 100% attack-labelled, about 250 distinct destinations each, mostly S0/REJ (unanswered or rejected), ports 443/80/22/53 |
| Do all attack-labelled flows involve those three? | **yes: 100%** have one of them as source or destination; 0 attack-labelled flows without one |
| The other 37 "attack-labelled sources" | 106,116 flows, **all with a scanner as destination**. Source ports are the scanned services (111, 23, 5800, 3306, 5900); conn_state mostly RSTOS0/REJ; 3 distinct destinations, i.e. the scanners |
| Is the label time-bounded? | yes: 192.168.1.30 has 67 benign-labelled flows weeks before the attack interval (2019-04-23/24); in the interval all its flows are attack |
| Mixed vs pure minutes | 2,766 all-benign minutes, 137 mixed, 0 all-attack |

## 3. Interpretation by role

| Role | Hosts | Evidence | Confidence |
|---|---|---|---|
| **Attack initiators** | 192.168.1.30, .31, .32 | scanning signature (hundreds of targets, unanswered or rejected connections), 100% attack-labelled, every attack flow involves them | high |
| **Attack targets** | about 250 hosts contacted by the scanners (mostly 192.168.1.x and other private addresses) | destinations of scanning flows | high |
| **Responders (victims logged as sources)** | 37 addresses (192.168.1.x, 169.254.x link-local, 1 public) | their attack-labelled flows go only to scanners, from service source ports, with reset/reject states: replies or resets that Zeek recorded as new connections from the victim | high for the direction; these are not attackers |
| **Incidental hosts** | none found: no attack-labelled flow lacks a scanner endpoint | — | — |
| **Uncertain identity** | the mapping documented 192.168.159.30-39 vs observed 192.168.1.30-32 | same final octets, different subnet. Consistent with static 1:1 address translation (NAT) between the attack segment and the monitored segment, or with outdated documentation | **unverified**: needs the raw PCAPs or the authors' confirmation |

**Labelling convention, as reconstructed.** A flow is labelled attack if it has an attacker
host as **either endpoint** during the attack interval. This is consistent with the documented
"source IP + timestamp" tagging applied to both directions, except for the subnet. The labels
are therefore **not wrong**. They are **flow-level and direction-agnostic**, so "sources with
attack-labelled flows" ≠ "attackers".

## 4. Retrospective reinterpretation of the Phase 8c attacker counts (not a confirmatory claim)

The frozen "attackers detected n/40" counted attack-*involved* sources. Separated by role,
with identical windows, scores and alerts as the frozen run:

| policy | initiators detected | initiator window recall | responders alerted | FPR (benign windows) |
|---|---|---|---|---|
| A deployed | **3/3** | 0.424 | 8/37 | 0.089 |
| C2 | 3/3 | 0.425 | 7/37 | 0.089 |
| E LightGBM (local threshold) | **3/3** | 0.559 | 6/37 | 0.002 |

**Consequences:**
- On this capture the meaningful attacker-level statement is "3 of 3 scanners detected by
  every policy". Frozen X1 (FPR 8.9%) and X5 are unaffected.
- From now on NetSentinel reports, for datasets whose labels are flow-level and
  direction-agnostic:
  - window-level detection;
  - **attack-involved-source** alerting (not "attacker recall");
  - initiator detection *only* when initiators are established from documentation **and**
    behaviour, as here.
- See [EVALUATION_METHODOLOGY.md](EVALUATION_METHODOLOGY.md).

## 5. What would resolve the remaining uncertainty

- The raw ToN_IoT PCAPs of the attack interval, to check whether 192.168.159.x appears
  before translation.
- Or written confirmation from the dataset authors.
- Neither was obtained (no further download).
