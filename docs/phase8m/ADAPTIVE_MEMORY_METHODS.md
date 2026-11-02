# Phase 8m: adaptive destination memory (methods)

**Code:**
- `src/netsentinel/behavior/novelty.py` (research module; the deployed monitor does not use it);
- the build `scripts/phase8m/build_novelty.py`;
- tests in `tests/unit/test_phase8m_novelty.py`.

**Registered parameters:** PREREGISTRATION.md, section 2.

## The memory

**One record per destination IP**, holding:
- the first and latest contact time;
- up to 8 distinct sources;
- whether, and when, the guarded policy accepted it.

**Per-host pairs** (source, destination) give host-level first contacts. State grows with the number
of destinations and pairs, not with traffic volume.

**Causality is by construction:**
- the stream is processed in 30 s windows, in time order;
- every window of one index is scored from the state *before* that index;
- only then does the state learn the window's contacts.

A window therefore never sees its own or later traffic. Unit tests check that features computed on a
prefix equal those of the full stream, and that out-of-order input is refused.

## Policies

| | becomes "known" when | risk |
|---|---|---|
| A0 frozen (deployed) | seen in calibration; never afterwards | stale: every new benign destination is novel for ever |
| A1 unconditional | after its first window | contamination: an attacker's C2 is normal 30 s later |
| A3 guarded | ≥ 2 distinct sources **and** contacts spanning ≥ 1 h | a slow, multi-host campaign is eventually accepted |
| always-quarantine (control) | never after the freeze | the same as A0 for post-freeze destinations |

**A3 uses no score and no label.** So the detector's own (possibly wrong) decisions never decide
what becomes normal.
- **A single compromised host can never make its C2 normal,** however long it beacons. The unit
  test runs 14 days at 5-minute intervals.
- **Two or more hosts can.** This is the stated limit; the synthetic two-host experiment measures
  it.

**Features per (source, window):**
- `nov_frozen`, `nov_unconditional`, `nov_guarded`: share of the window's distinct destinations
  that are novel under A0, A1 and A3;
- `nov_host`: share of first contacts for this source;
- `log_new_guarded`: log(1 + number of guarded-novel destinations);
- `familiarity_decay`: mean exp(−age / 1 day), where age is the time since anyone last contacted
  the destination;
- `log_prevalence`: mean log(1 + earlier distinct sources), capped at 8.

## Data roles

**Two memories run in one streaming pass per domain.** They differ only in what they learn from
before the freeze (the domain's registered time midpoint):
- **`clean`:** calibration attack *flows* removed. This matches the Phase 8i windows that the
  source models are *trained* on, which use source-network labels only.
- **`p1x`:** calibration-period attacker *hosts* removed. This matches the Phase 8j P1x windows the
  target is calibrated and scored on, and uses calibration-period labels only.

**After the freeze, every flow updates both memories, attackers' included,** as it would in
deployment. That is exactly what makes contamination possible, and what H2 measures.

**Reproduction check.** In both memories, `nov_frozen` reproduces the deployed `new_dst_frac` of
the corresponding window set exactly. The build checks this on every window and records the
largest difference.

## Shadow mode

**Nothing here changes the deployed detector.**
- **Status:** the memory is a research feature, computed offline.
- **What deployment would need:**
  - the guarded memory would run in shadow mode next to the frozen one;
  - its acceptances would be logged for review;
  - it would never block or act on traffic.
- **Precondition:** that requires a registered GO, which this phase can only give on development
  data.
