# Phase 8r: independent review and actions

**The review.** A separate agent did a read-only audit as five reviewers:
- A: identifiability and statistics;
- B: ML methodology;
- C: leakage;
- D: reproduction;
- E: claims and pre-registration.

It was given the pre-registration, the code and the saved results, but not the author's
conclusions. It recomputed the key numbers with its own scripts. Every finding used below was
re-checked by the author against the data before any change.

## Recomputed and matched

| quantity | result |
|---|---|
| A0, A1, A1T per network and macro | match (0.3718, 0.8689, 0.6564) |
| H-A1 primary cell (NF-UNSW, NF-BoT, NF-ToN): recall, FPR, FPR p10/p90 | exact match |
| Experiment B, A3 random at 5 %, per network | match |
| Experiment C M0/M1 on 02-22 and 03-02 | match |
| Decision rules H-A1, H-B1 and the C gate applied to the JSON | applied correctly |
| Leakage | none: policies use label-free metadata only; labels enter vetting (declared ORACLE-SIMULATED), references and metrics |
| Chronology | registration `fd7affa` 22:35:16 → result files 22:41–22:45 → results `a8a6980` 22:47:51; identifiability (22:22) predates registration, as declared |

## Findings and actions

| # | severity | finding | verified | action |
|---|---|---|---|---|
| D1 | high (correctness) | **M3 implemented OR, not the registered AND** (`max_horizontal` ignores nulls) | yes (polars returns `[1, 3]` for `max(1, null)`, `max(2, 3)`) | fixed, unit test added, C rerun; amendment R-1. Corrected numbers equal the reviewer's (02-22 size 4,290, restored 0, +2.9 pt). Gate verdict unchanged |
| B1 | high (interpretation) | A2/A3 "conformal T0" is the sample maximum below 99 trusted windows (100 % of NF-ToN primary draws) | yes (registered `t0` caps the rank) | disclosed (amendment R-2; TRUSTED_CALIBRATION) |
| B2 | high (reading of H-B1) | rounding makes NF-ToN's "5 %" about 9 %; NF-ToN is absent at 1 %; **without NF-ToN every mechanism passes H-B1** | yes (−0.022 to −0.078 from the JSON) | reported as a sensitivity; the registered verdict stays (amendment R-3) |
| E2 | medium | criteria (i)/(iii) pass through over-alerting (A3 0.709 > A1T ceiling 0.656) | yes | stated: "not gap recovery" |
| A2 | medium | the 5 % NF-CIC bound is false on 02-22, and the 1 % bound on 02-22 and 03-02 | yes | CALIBRATION_IDENTIFIABILITY conclusion 2 qualified by day |
| A3 | medium | the 99-host argument counts the population; no trusted cell reaches 99 hosts; NF-ToN has 92.8 effective hosts; host-level ≠ window FPR | yes | conclusion 4 restated |
| B3 | medium | in B, injected hosts become "vetted", which removes their other windows from A3's pool (partial offset) | yes (registered) | disclosed |
| A4 | low | "oracle threshold recall 0.003–0.016" mixes A1T (0.0031) with the identified-set range | yes | corrected |
| B4 | low | the A4 bootstrap seed differs between clean and contaminated runs; error cells reseed selection | yes | disclosed |
| B5 | low | NF-BoT has 15 hold-out hosts, so "modest" vets 10 of 15 | yes | noted |
| E3 | low | timestamps are self-attested until pushed | — | push needs the user's authorization |

## Not changed

- Registered rules and verdicts: H-A1 NOT SUPPORTED, H-B1 NOT SUPPORTED, C gate closed.
- Experiment A and B outputs; no rerun was needed.
- The frozen M2 and every Phase 8h–8q artifact.
