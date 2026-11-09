# Phase 8v Stage 1: raw telemetry availability audit

**Sources:**
- `scripts/phase8v/build_enriched.py audit` → `reports/phase8v/telemetry_audit.json`.
- Sample: one 100k-flow batch from each of 6 evenly spaced row groups per network, taken only from
  row groups lying wholly inside the development part (NF-CIC and NF-UNSW keep their last 22 %
  per file withheld).
- Sampled flows: NF-CIC 574,853; NF-UNSW 232,496; NF-ToN 506,745; NF-BoT 417,017.

**Gate G0: COMPLETE.** The four networks hold flow records with one shared 78-column schema.
That is enough to build flow-statistical, within-window temporal and bidirectional features. It is
**not** packet-level data.

## 1. Telemetry levels

| level | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|
| A: raw packets (PCAP) | not held locally | not held | not held | not held |
| B: flow records (NetFlow v3, nProbe export; `data/interim/nf_*_v3`) | 20.1 M flows, 11 days | 2.4 M, 3 days | 27.5 M, 7 days | 16.9 M, 6 days |
| C: (source host, 30 s) windows, 12 features | built (Phase 8i) | built | built | built |

- The only PCAP on disk is a CTU normal capture, which is not a development network.
- NF-CIC also has the original CICFlowMeter CSVs (`data/raw/cse-cic-ids2018`): a different
  exporter with different field definitions. They are not used.
- **Everything in Phase 8v is flow-based.** A "sequence" here can only be a sequence of flow
  records.

## 2. Field availability (identical schema in all four networks; no nulls in any field)

| group | fields (original name = canonical name) | unit | used by the 12 features? | safe for cross-network modelling? |
|---|---|---|---|---|
| identity | `ipv4_src_addr`, `ipv4_dst_addr`, `l4_src_port`, `l4_dst_port` | — | source as the window key; destination and port only as distinct counts and the destination memory | **no** as values (topology) |
| time | `flow_start_milliseconds`, `flow_end_milliseconds`, `flow_duration_milliseconds` | ms since epoch; ms | end time (window), duration | yes |
| transport | `protocol` | IANA number | UDP share | yes |
| volume, both directions | `in_bytes`, `in_pkts` (source → destination), `out_bytes`, `out_pkts` (destination → source) | bytes, packets | sums; "no reply" = `out_pkts` = 0 | yes |
| TCP flags per direction | `client_tcp_flags`, `server_tcp_flags`, `tcp_flags` | bit mask (cumulative OR) | RST only | yes, with the direction caveat (§ 4) |
| packet-size histogram | `num_pkts_up_to_128_bytes` … `num_pkts_1024_to_1514_bytes`, `longest_flow_pkt`, `shortest_flow_pkt`, `min/max_ip_pkt_len` | packets; bytes | no | mostly (§ 4) |
| per-flow packet timing | `src_to_dst_iat_{min,max,avg,stddev}`, `dst_to_src_iat_*`, `duration_in`, `duration_out` | ms | no | **doubtful** (§ 4) |
| retransmissions | `retransmitted_{in,out}_{bytes,pkts}` | bytes, packets | no | **no** (§ 4) |
| throughput | `src_to_dst_second_bytes`, `*_avg_throughput` | bytes/s, bits/s | no | no (`inf` values; derived from duration) |
| TTL, TCP window | `min_ttl`, `max_ttl`, `tcp_win_max_in/out` | hops; bytes | no | **no** (path length and operating system: topology shortcuts) |
| application hints | `l7_proto` (nDPI), `dns_query_id/type`, `dns_ttl_answer`, `ftp_command_ret_code`, `icmp_type` | codes | no | no (classifier output and payload-derived; coverage differs) |
| labels | `label`, `attack`, `family` | — | evaluation and training labels only | never a feature |

## 3. Time precision and availability

- **Millisecond precision in all four networks:** 99.9 % of start and end times are not whole
  seconds.
- **`end − start` equals `flow_duration_milliseconds` within 1 ms for every sampled flow.**
- **The exporter cuts flows at about 120 s** (maximum duration 120.3–121.0 s everywhere). A
  longer connection arrives as successive records of at most 120 s.
- **Flows longer than a 30 s window:**

  | network | > 30 s | > 120 s |
  |---|---|---|
  | NF-CIC | 11.5 % | 0.7 % |
  | NF-UNSW | 0.1 % | 0.06 % |
  | NF-ToN | 0.05 % | 0.01 % |
  | NF-BoT | 37.0 % | 0.1 % |

**Availability time.** A flow record's counts, flags and durations are final only when the flow
ends or the 120 s cut fires.
- Windows are keyed by the flow **end** time, so every per-flow field used is available when the
  window closes.
- A window's features therefore describe flows that *finished* in it. Their packets may be up to
  120 s old.
- The exporter's own delay (idle timeout, export batching) is not recorded in these datasets.
  **No online latency claim is made**; this is retrospective analysis of completed flow records.
- Sub-second packet timing is not reconstructible. Only per-flow inter-arrival summaries exist.

## 4. Semantic checks: where the same field does not mean the same thing

| check | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | consequence |
|---|---|---|---|---|---|
| flows with any retransmission | 9.5 % | **74.2 %** | 2.6 % | 0.6 % | retransmission fields are not comparable (NF-UNSW's replayed traffic); **excluded from registered candidates** |
| forward IAT > 0 when ≥ 2 forward packets | 95.6 % | **47.7 %** | 64.6 % | 99.2 % | ms resolution is too coarse for fast flows |
| forward IAT > 0 with a single forward packet | 10.1 % | 28.7 % | 0.01 % | 0.00 % | the IAT fields are inconsistent with the packet counts on NF-CIC and NF-UNSW |
| median forward IAT | 20 ms | 0 ms | 0 ms | 4,285 ms | scale is set by the testbed's traffic generator: a **domain fingerprint** |
| size bins sum to total packets | 95.3 % | 79.1 % | 99.7 % | 100 % | NF-UNSW has packets outside the bins; shares are computed over binned packets |
| TCP flows with a client SYN | 82.9 % | 71.8 % | 72.6 % | 97.5 % | 3–28 % of TCP records are mid-connection (120 s cuts or missed handshakes) |
| TCP source port > destination port | 90.3 % | 80.8 % | 72.5 % | 93.6 % | the "source" is usually, **not always**, the initiator |
| server SYN without client SYN | 0 % | 0 % | 0.01 % | 1.3 % | clear direction reversals are rare |
| flows with no reverse packets | 11.2 % | 2.3 % | 44.0 % | 42.8 % | already used ("no reply") |
| `min_ttl` = 0 | 42 % | 1 % | 69 % | 34 % | TTL population differs by network: excluded |

**Direction.** "Forward" is the exporter's source → destination direction, taken from the record's
first packet.
- No label is used to orient a flow.
- Bidirectional features therefore carry orientation noise wherever the source is not the
  initiator (up to about a quarter of TCP flows on NF-ToN).

## 5. Common schema for Phase 8v

Features may use only: end time, duration, protocol, forward/reverse bytes and packets,
client/server TCP flags, the packet-size histogram, and (flagged as domain-dependent) the forward
inter-arrival mean.

**Excluded as values:** addresses, port numbers, TTL, TCP window, nDPI and DNS fields, throughput,
and (after this audit) retransmission counts.

No availability mask is needed: no field is missing in any network.
