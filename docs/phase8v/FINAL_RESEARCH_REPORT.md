# Phase 8v final report: flow-level representations and cross-network transfer

**Question.** Is attack information lost when flow records are compressed into the 12-feature,
30-second host window? If so, can a richer representation improve detection at FPR ≤ 1 %,
especially on NF-UNSW and NF-ToN?

**Answer on development data:**
- **No richer representation passed the registered test.** Flow statistics, timing and context,
  bidirectional statistics, and an invariant-direction selection all failed screening. Model
  development is a NO-GO.
- **NF-UNSW's failure is not information loss.** The existing 12 features separate its attacks
  almost perfectly in-network (recall 0.996 at 1 % FPR). Transfer fails because the same features
  point the opposite way there.
- **NF-ToN's information was also already present.** One original feature, the flow count, reaches
  partial AUC 0.79 on NF-ToN by itself. The transferred model reaches 0.008, and 0.25 with the
  temporal columns.
- **The limit is cross-network shift:** 17 of 30 features (8 of the original 12) reverse direction
  between networks. It is not the window's information content, and not observability.

## Decisions

| gate | verdict | basis |
|---|---|---|
| G0 telemetry availability | **COMPLETE** | one 78-column NetFlow v3 schema in all four networks; flow records only, no packet data |
| G1 representation information (flow statistics) | **NOT SUPPORTED** | `FLOW`: hard-network partial AUC + 0.004 (needs + 0.02); every guardrail fails |
| G2 temporal features (H1, H3) | **NOT SUPPORTED** | `TIME`: ranking criteria met (+ 0.117), but as-calibrated FPR and entity guardrails fail; the gain is volume in three NF-ToN hosts |
| G3 bidirectional features (H2) | **NOT SUPPORTED** | `BIDIR`: + 0.035; the same guardrails fail; 17 entities missed vs 8 |
| G4 sequence learning (H4) | **NOT ATTEMPTED** | ordering features added no in-network information; nothing new justified GRU/TCN |
| G5 cross-network generalisation (H5) | **NOT SUPPORTED** | no candidate passes; `INV` collapses (macro 0.254 → 0.091) |
| model development | **DEVELOPMENT NO-GO** | no candidate passed screening; no replication was run |
| independent validation | **NOT READY** | no unused eligible network |
| deployment | **NO-GO** | — |

## Repository

**Commits:**
- **Start:** `aed9b40` (= `origin/main`; CI run 42610556047 success), with a clean tree.
- **Commits:**
  - `e5c08a6`: registration, before any registered fit;
  - `f952dc1`, `e4fcb3e`, `bc32c96`, `dd184bc`: fit ledger after each variant;
  - `f43ac20`: registered evaluation;
  - `35c4f2b`: failure analysis and amendment V-1;
  - review corrections and closure follow.

**Push:** not pushed (needs authorization). Branch `main`.

**New code:**
- `scripts/phase8v/{flow_features, build_enriched, learnability, selection, experiment, baseline_reference, posthoc, ton_concentration, figures}.py`;
- `tests/unit/test_phase8v.py` (13 tests).

**Unchanged:** `src/`, the deployed detector and its defaults, the frozen M2, every Phase 8h–8u
artifact.

**Tests:** see § Validation.

## Telemetry (TELEMETRY_AUDIT.md)

- **Levels:** flow records for all four networks; no PCAP for any of them. Everything is
  flow-based.
- **Time:** millisecond start and end times; `end − start` = duration within 1 ms; the exporter
  cuts flows at about 120 s.
- **Availability:** a flow's fields are final at its end (or the 120 s cut), plus an exporter
  delay these datasets do not record. No online latency claim is made.
- **Common schema:** end time, duration, protocol, forward/reverse bytes and packets,
  client/server TCP flags, the packet-size histogram.
- **Not cross-network safe:**
  - retransmissions (74 % of NF-UNSW flows vs 0.6–9.5 % elsewhere);
  - per-flow inter-arrival fields (inconsistent with packet counts; median 0 ms to 4.3 s by
    testbed);
  - TTL and TCP window (topology and operating system);
  - addresses and ports as values.
- **Direction:** the record's source is usually, not always, the initiator (72–94 % of TCP flows
  have an ephemeral source port).

## Representation (FEATURE_SCHEMA.md)

**`flowwin-1.0.0`:** 18 features per (source host, 30 s window) in three families.

| family | features |
|---|---|
| FLOW | share of tiny flows; mean log packets per flow; SD of log forward bytes; 90th-percentile duration; small-packet share |
| TIME | active seconds; busiest-second share; gap variation; long-flow share; forward inter-arrival mean (audited out); previous-4-window mean, change and activity |
| BIDIR | SYN-only share; server-RST share; client-FIN share; per-flow byte ratio; retransmission share (audited out) |

- **Registered:** 16 features. Two were removed on the label-free audit; none for its evaluation
  performance.
- **Causality:** windows are keyed by flow end time; context uses strictly earlier windows
  (tested).
- **Build:** 65.1 M flows → 2.45 M windows in 270 s. An independent recomputation from raw flows
  matched to 1.8e-15.
- **Research-only:** nothing was added to the deployed feature pipeline.

## Exploratory analysis (OBSERVABILITY_ANALYSIS.md)

| network | cross-network recall at 1 % FPR (frozen M2) | in-network, 12 features | explanation |
|---|---|---|---|
| NF-UNSW | 0.023 | 0.996 | cross-domain shift: its attackers are quieter than its benign hosts |
| NF-ToN | 0.007 | 0.19 (chronological); 0.90 (host-grouped) | shift within and between networks; some in-network gain from enriched features (0.127 → 0.238) |
| NF-CIC | 0.500 | ≈ 1.0 | shift and memory contamination (earlier phases) |
| NF-BoT | 0.571 | 0.94–0.98 | a benign tail of a few windows |

- **Every feature set fingerprints the network:** a classifier names the network of a benign
  window with 96 % accuracy from the 12 original features (97.7 % with all 30).
- 48 small diagnostic fits (39 s). They are not registered fits.

## Machine learning (MODEL_COMPARISON.md)

**Recipe:** the frozen M2 member.
- LightGBM 4.7, 200 trees, 15 leaves, learning rate 0.05, subsample and colsample 0.8.
- Network- and class-balanced weights; 50k cap per source domain.
- Leave-one-network-out, seed 1060.

**Baseline:** the saved member with the same seed (Phase 8u showed the refit is bit-identical).

**Fits:** 16 of 24 approved; 637 s in the ledger; 1.47 GiB resident (1.9 GiB for the process
tree); no neural run.

**Results** (exact partial AUC at FPR ≤ 1 %; single member):

| model | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | macro | as-calibrated FPR on NF-ToN / NF-BoT | entities missed (as calibrated) |
|---|---|---|---|---|---|---|---|
| frozen member | 0.331 | 0.006 | 0.008 | 0.671 | 0.254 | 15.9 % / 18.5 % | 8 |
| `FLOW` | 0.160 | 0.006 | 0.017 | 0.938 | 0.280 | 23.6 % / 10.8 % | 17 |
| `TIME` | 0.444 | 0.001 | 0.247 | 0.700 | 0.348 | 24.3 % / 31.0 % | 11 |
| `BIDIR` | 0.289 | 0.002 | 0.082 | 0.883 | 0.314 | 23.6 % / 6.9 % | 17 |
| `INV` | 0.013 | 0.000 | 0.001 | 0.352 | 0.091 | 24.4 % / 7.4 % | 31 |

**Recall at the retrospective 1 % FPR, macro:** 0.266 (frozen member), 0.311, 0.389, 0.342, 0.099.

**Frozen five-member M2 for reference:** recall 0.275 macro (0.500 / 0.023 / 0.007 / 0.571),
reproducing Phase 8t; exact partial AUC 0.255.

**No hold-out threshold reaches 1 % FPR** on NF-UNSW, NF-ToN or NF-BoT for any model. False alerts
per hour on NF-CIC: 289–375.

## Scientific analysis

**Information loss.**
- Shown only weakly and only in-network on NF-ToN (single diagnostic fits).
- It is not what blocks transfer. On NF-ToN the flow count alone outranks every transferred
  model.

**Model-learning limit.** Phase 8u's objectives and this phase's features both leave NF-UNSW at
the floor. A model fitted on other networks learns their direction.

**Cross-domain shift is the dominant limit.**
- Feature directions invert between networks.
- Selecting only directions the source networks agree on (`INV`) destroys detection, because the
  useful signal and the conflicting signal are the same volume features.
- A conflict with the target cannot be seen from the sources.

**Observability.** No limit is shown. Every network is learnable from flow windows in-network
(NF-ToN only partly across time; its `backdoor`, `mitm` and `ransomware` labels, 548 windows,
are not detected by any model).

**`TIME` on NF-ToN (exploratory, one seed).**
- Partial AUC 0.008 → 0.247.
- 63 % of the true positives come from one host and 90 % from three. Only the two high-volume
  labels improve.
- This is volume and persistence, not newly visible attack behaviour.

**Statistical limits.**
- 4 networks from 2 institutions, 9 domains, 48 entities; **one seed**.
- **No null control.** All four candidates share most of their extra NF-ToN false alerts, so part
  of every difference is a pipeline effect.
- The FPR guardrail is noise-dominated on NF-BoT (one host).
- NF-UNSW's inversion rests on 4 attacker hosts.

**Corrections after the independent review** (INDEPENDENT_REVIEW.md):
- the NF-UNSW calibrated-recall collapse is now reported;
- the `TIME` gain is reinterpreted;
- availability wording, midpoint-slot counts and memory figures are corrected;
- amendment V-1: model files were saved with CRLF; hashes verified.

## Validation

**Full suite on `f72d468`** (the final code): 470 passed, 0 failed, 0 errors, 0 skipped,
2 deselected, in 856 s.
- That includes the 13 Phase 8v tests and the dashboard test that timed out under load in Phase 8u.
- JUnit file: `reports/phase8v/junit_phase8v_final.xml`.

**Other checks:**
- `ruff check` and `ruff format --check`: clean (524 files);
- dependency gate: OK;
- dependencies added: none.

## Three highest-priority gaps

1. **Direction conflict between networks.** Attack windows are high-volume on three networks and
   low-volume on NF-UNSW.
   - *Next evidence:* representations *relative to each network's own benign baseline* (deviation
     in either direction, per host or per service), tested with a null control and at least five
     paired seeds. Phase 8h's global standardisation did not do this per direction.
2. **No null control and one seed in this phase.** Any follow-up needs a permuted-column or no-op
   control and several seeds before a family's effect can be read.
3. **No independent network, and testbed-specific roles.** NF-UNSW's inversion may be a property
   of one synthetic testbed. Only an unused network with host-level ground truth can tell whether
   "quiet attackers" are common.

**Phase 8w is not started.**

## Portfolio summary (verified claims only)

**ML Research Engineer:**
- "Audited raw NetFlow telemetry across four intrusion datasets: field semantics, time precision
  and cross-dataset comparability.
- Built a causal, leakage-tested enriched flow-window representation: 18 features over 65 M
  flows, independently recomputed from raw data to 1e-15.
- Showed with in-network learnability diagnostics that cross-network failure is caused by feature
  directions inverting between networks, not by information lost in aggregation.
- Pre-registered four representation candidates with guardrails; none passed. Reported the
  negative result, including an independent review that reinterpreted the one apparent gain as a
  volume effect in three hosts."

**Do not claim:**
- improved detection;
- that richer features help transfer;
- a validated model;
- generalisation;
- production readiness.
