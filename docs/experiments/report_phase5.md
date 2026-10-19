# NetSentinel AI, Phase 5: domain adaptation, generalisation and production validation

Status: **draft in progress** (2026-10-20). Sections are added as their evidence is complete.
All numbers come from files under `reports/` that are named in each section. Validation and
calibration partitions only, unless a section explicitly says "final test".

## 1. Why cross-dataset transfer failed (Mission 1)

Evidence: `scripts/audit/audit_transfer.py` -> `reports/audit/transfer.json`,
`reports/figures/transfer_shift.png`. Datasets: NF-CICIDS2018-v3 ("IDS") and NF-UNSW-NB15-v3
("UNSW"), both in the nProbe 53-field NetFlow-v3 schema.

Sharing a schema did not make the features mean the same thing. Six causes were measured.
They point the same way and do not separate cleanly.

1. **The benign traffic of the two networks is almost perfectly separable.** A domain
   classifier on benign flows reaches AUC 0.992–1.000 (3 folds) with all features. Using only
   the 5 most portable fields (packets, bytes, duration) it reaches 0.99995. There is no
   region of common support, so importance-weighting adaptation has nothing to reweight. We
   therefore did not use it (Mission 2).
2. **Broad marginal shift.** 72% of features have benign KS > 0.3. The largest shifts are in
   the context rates (`ctx_flow_rate_300s` KS 0.96, PSI 12.4).
3. **The same field has different extractor semantics.** These identities should hold under a
   single field definition:

   | Identity (share of flows satisfying it) | IDS | UNSW |
   |---|---|---|
   | mean IAT x (pkts-1) ~ client duration | 0.995 | 0.717 |
   | size-bin counts sum to packet count | 0.978 | 0.839 |
   | zero-duration flows | 0.000 | 0.153 |
   | single-packet flows | 0.064 | 0.006 |
   | duration p99 (ms) | 120,106 | 8,987 |
   | flows >= 119 s (active-timeout cut) | 0.016 | 0.0005 |
   | `SRC_TO_DST_SECOND_BYTES` ~ bytes/s | 0.0002 | 0.00003 |
   | throughput = 8 x bytes/s | 1.000 | 1.000 |

   The IDS export applies a 120 s active timeout; UNSW flows are short and often have zero
   duration. `SRC_TO_DST_SECOND_BYTES` is not bytes/s in either dataset.
4. **Topology.** IDS has 181,876 source and 29,036 destination addresses. UNSW has 40 and
   40, with only 4 attacking hosts. Context features (per-destination fan-in, rates) measure
   different things in such different networks.
5. **Label incompatibility.** The attack families overlap only in `benign` and `dos`. IDS
   attacks are brute force, DoS/DDoS floods, web attacks and botnet. UNSW attacks are
   exploits, fuzzers, generic, reconnaissance, shellcode, worms, backdoor and analysis.
   Transfer therefore asks a source model to detect attack types it never saw.
6. **Direction conflicts (class-conditional shift).** Eight features separate attacks in
   *opposite* directions in the two datasets. For example, `ctx_noreply_frac_*` has
   attack-vs-benign AUC 0.15–0.17 on IDS and 0.75 on UNSW. The others are `in_pkts`,
   `out_pkts`, `num_pkts_up_to_128_bytes`, `cli_psh` and `srv_psh`. No monotone recalibration
   or normalisation can fix a feature whose evidence reverses sign.

Threshold calibration is a separate, smaller failure. Source thresholds flagged 59–99.9% of
target benign flows (v4). Calibrating on target benign data controls the FPR, but cannot
restore ranking quality the model does not have (section 2).

## 4. PCAP / Zeek pipeline on a real capture (Mission 6)

Evidence: `scripts/audit/validate_pcap_vs_zeek.py` -> `reports/audit/pcap_vs_zeek.json`.
Capture: CTU-Normal-26 (Stratosphere Lab; `docs/datasets/ctu_normal_26.md`): 199,279
packets, about 6.5 h of one host's benign browsing. Reference: the Zeek 2.5.1 `conn.log`
produced by the dataset authors.

**Packet layer.** 198,760 packets parsed. The 519 skipped are 518 non-IP ethertypes (ARP and
similar) and 1 truncated Ethernet frame. No IP packet was dropped. The assembled flows account
for exactly the same number of packets as Zeek's connections (198,760 = 198,760).

**A real defect was found and fixed.** In the original assembler a flow ended immediately on
FIN/FIN or RST, so the final ACK opened a new 1–2-packet "flow". On this capture that created
2,161 spurious TCP flows and left 1,826 matched TCP flows short of packets. Zeek holds a
closed connection open for `tcp_close_delay` (5 s). The assembler now does the same
(`close_linger=5.0`), and a new SYN on the same 5-tuple still starts a new flow. Regression
test: `tests/unit/test_telemetry.py::test_close_linger_absorbs_final_ack_and_new_syn_restarts`.

| Agreement with Zeek (matched flows) | v0 (no linger), nProbe timeouts | fixed, nProbe timeouts | fixed, Zeek timeouts |
|---|---|---|---|
| our flows / Zeek conns | 19,423 / 15,081 | 17,268 / 15,081 | 15,049 / 15,081 |
| TCP flows (Zeek: 1,867) | 6,173 | 4,018 | **1,867** |
| Zeek conns matched | 0.999 | 0.999 | 0.998 |
| our flows matched | 0.776 | 0.873 | 0.9998 |
| direction (orig = client) | 0.9999 | 0.9999 | 0.9999 |
| total packets equal | 0.875 | 0.961 | 0.998 |
| orig / resp IP bytes equal | 0.917 / 0.913 | 0.961 / 0.965 | 0.998 / 0.998 |
| start time within 1 ms | 1.000 | 1.000 | 1.000 |
| duration within 1 ms (p99 error) | 0.960 | 0.903 | 0.913 (6.8 ms) |
| TCP termination class equal | 0.716 | 0.722 | **1.000** |

Under Zeek-default timeouts (TCP 300 s, UDP/ICMP 60 s idle, no active timeout) the remaining
differences are small:
- 32 UDP connections where Zeek and we split a long UDP exchange differently;
- 3 Zeek ICMP connections without a counterpart, and 3 flows of ours (2 ICMPv6, 1 IPv6
  hop-by-hop with protocol 0) that Zeek does not log;
- duration differences of a few milliseconds (median 0.28 ms) from our millisecond
  truncation of start times.

Under the nProbe-style timeouts used for the models (30 s idle, 120 s active), the extra flows
are the expected effect of the shorter timeouts: long connections split into chunks with no
SYN. They are not errors.

**Malformed data.** The reader stops cleanly on corrupt record lengths and skips unparseable
frames by reason. These paths are covered by unit tests on hand-built captures. The real
capture contained no malformed IP packets, so they were not exercised on real data.

**Compatibility with model features.** The 17,268 assembled flows produced a 68-column frame
with no null, non-finite or negative cells. The same identities as in section 1 hold on our
flows: IAT x pkts ~ duration 1.000; size bins sum 1.000; throughput 1.000; zero-duration
0.010; p99 duration 115 s with a 120 s active cut. So our extractor resembles the **IDS**
export, not the UNSW one. One field differs from both NF datasets:
`SRC_TO_DST_SECOND_BYTES`/`DST_TO_SRC_SECOND_BYTES` is exactly bytes/s in our records but
not in nProbe's (<= 0.02%). nProbe's definition is not documented in the dataset feature
file. Models using these two fields (`nf_flow*` feature sets) must not be applied to
PCAP-derived flows. The deployed portable bundle (`nf_portable_ctx`) does not use them.

**Not validated.** We have no paired capture with nProbe NF-v3 output, so the field-level
agreement with the training features is still unverified. That includes the per-direction
IAT, TTL, window and retransmission fields, nProbe's own flow-cut rules, and nDPI labels.
Agreement with Zeek covers flow boundaries, packet and byte accounting, direction and TCP
state only.
