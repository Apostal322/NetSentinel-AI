# Phase 8v feature schema `flowwin-1.0.0`

**Code:** `scripts/phase8v/flow_features.py` (definitions; 9 unit tests) and
`scripts/phase8v/build_enriched.py` (build).

**Built table:** `data/derived/phase8v/enriched/<network>/<domain>.parquet`, one row per
(source host, 30 s window).
- 65.1 M flows → 2.45 M windows across 14 domains;
- 270 s in total, about 240k flows/s;
- peak 2.6 GiB for the whole capped process tree (1.4 GiB in the builder);
- hashes in `reports/phase8v/build_enriched.json`.

## Common properties

- **Telemetry:** completed NetFlow v3 records (level B). No packet data, payload or label.
- **Unit:** the existing window, keyed by source host and flow **end** time.
- **Availability:** at window close **plus the exporter's delay**, for flows that finished in the
  window (TELEMETRY_AUDIT § 3).
  - A flow closed by an idle timeout is exported only after that timeout, which these datasets do
    not record. It can be a window or more later.
  - The three context features use only strictly earlier windows of the same host.
- **Missing values of the new features stay missing** (NaN). They are never replaced by 0;
  LightGBM handles them natively.
  - The 12 original features keep their historical handling (`nan_to_num`), so the policy is
    mixed.
  - Missingness differs by network and is itself a fingerprint: `gap_cv` is missing for 50–58 % of
    NF-CIC windows and 10 % of NF-UNSW's.
- **No identity fields:** no address, port number, TTL or TCP window.
- **Cost:** one grouped pass over the flows. The quantile and gap statistics need the window's
  flows in memory (bounded by the window), so they are computable in streaming with a per-window
  buffer. Research code only: **nothing was added to `src/` or the deployed feature pipeline.**

**Consistency with the frozen windows:** the flow count equals the Phase 8i window's on every
(host, window), except the one 30 s slot at each domain's calibration/evaluation midpoint.
- That slot is split between the two frames (5–64 windows per domain; 0 on NF-BoT).
- The enriched features of those windows cover the whole slot.

## Features

Benign shift = mean pairwise |2·AUC − 1| between the networks' benign windows (0 = same
distribution; OBSERVABILITY_ANALYSIS § 5).

| family | feature | definition | expected attack signal | benign confound | missing when | benign shift | registered? |
|---|---|---|---|---|---|---|---|
| FLOW | `tiny_flow_frac` | share of flows with ≤ 2 packets | scans, floods of unanswered probes | DNS and other one-packet protocols | never | 0.47 | yes |
| FLOW | `mean_log_pkts` | mean of log(1 + packets per flow) | floods of small flows (low) or bulk transfer (high) | workload mix | never | 0.78 | yes |
| FLOW | `sd_log_up` | SD over flows of log(1 + forward bytes) | automated tools send near-identical flows (low) | single-service clients | never (0 for one flow) | 0.44 | yes |
| FLOW | `p90_log_dur` | 90th percentile of log(1 + duration ms) | slow attacks, long sessions | long-lived benign connections | never | 0.55 | yes |
| FLOW | `small_pkt_share` | packets ≤ 128 bytes / size-binned packets | control-only traffic without payload | ACK-heavy downloads | no packet binned | 0.54 | yes |
| TIME | `active_sec_frac` | distinct seconds with a flow end / 30 | sustained activity | busy servers | never | 0.61 | yes |
| TIME | `peak_sec_share` | flows in the busiest second / flows | bursts (high) vs steady automation (low) | page loads | never | 0.56 | yes |
| TIME | `gap_cv` | SD / mean of gaps between consecutive flow ends | scripted regular timing (low) | timers, polling | fewer than 3 flows | 0.56 | yes |
| TIME | `long_flow_frac` | share of flows lasting > 30 s | slow or persistent sessions | streaming, keep-alives | never | 0.38 | yes |
| TIME | `mean_log_fwd_iat` | mean log(1 + forward packet inter-arrival mean, ms) | packet pacing of tools | traffic generator speed | no flow with ≥ 2 forward packets | 0.73 | **no** (audit: inconsistent field; testbed fingerprint) |
| TIME | `prev4_mean_log_flows` | mean `log_flows` of the host's previous 4 windows (silent = 0) | persistent campaigns | steady servers | never | 0.56 | yes |
| TIME | `d_log_flows` | `log_flows` minus the previous window's (silent = 0) | onset of activity | any start of work | never | 0.24 | yes |
| TIME | `active_prev4` | active windows among the previous 4 | persistence | steady servers | never | 0.37 | yes |
| BIDIR | `syn_only_frac` | share of flows: TCP, client SYN, no client ACK | SYN scans and floods | lost handshakes | never | 0.10 | yes |
| BIDIR | `srv_rst_frac` | share of flows: TCP with a server RST | probes of closed ports | resets by middleboxes | never | 0.13 | yes |
| BIDIR | `cli_fin_frac` | share of flows: TCP with a client FIN | completed scripted sessions | ordinary completed sessions | never | 0.38 | yes |
| BIDIR | `mean_log_ratio` | mean of log(1 + reverse bytes) − log(1 + forward bytes) | exfiltration (low), downloads (high) | role of the host | never | 0.58 | yes |
| BIDIR | `retrans_frac` | share of flows with a retransmitted packet | lossy floods | link quality | never | 0.48 | **no** (audit: 74 % of NF-UNSW flows) |

**Registered families:** FLOW (5), TIME (7), BIDIR (4) = 16 features.

**Candidates considered in total:** 18 features. Two were removed on the label-free audit; none
was removed for its evaluation performance.

**Direction of the bidirectional features** follows the exporter's source → destination record.
Up to about a quarter of TCP records on NF-ToN are not client-initiated (TELEMETRY_AUDIT § 4),
so these features carry orientation noise.
