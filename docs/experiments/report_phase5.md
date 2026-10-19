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

## 2. Label-free domain adaptation (Mission 2), validation

Evidence: batch v5 (`scripts/run_batch_v5.py`) -> `reports/experiments/results_v5.{md,json}`,
`reports/figures/adaptation_calibration.png`. Setup:
- 3 seeds; the target is the chronological split of the other dataset.
- Calibration data comes from the target's earlier 60% of time; evaluation is the following
  20%.
- No target attack label sets anything. "Clean" calibration contains benign flows only;
  "unlabelled" is a random sample of all traffic with its true attack share.
- The FPR target is 1e-3 throughout. Each cell gives mean recall / FPR across seeds.

Domain adaptation (DA) here means changing a *source-trained* detector using unlabelled or
benign target data. Domain generalisation (DG) means using only features expected to be
stable. Supervised retraining uses target labels and is reported only as the in-domain upper
bound. Importance-weighting DA was **not run**: with domain-classifier AUC of about 1 there
is no common support to reweight (section 1).

| Method (clean calibration, 50k flows) | IDS -> UNSW, nf_flow_ctx | IDS -> UNSW, nf_portable_ctx | UNSW -> IDS, nf_flow_ctx |
|---|---|---|---|
| source model, source threshold (no adaptation) | 0.264 / 0.339 (ROC 0.44) | 0.074 / 0.354 (ROC 0.37) | 1.000 / 0.994 (ROC 0.68) |
| DA: source model, target-calibrated threshold | 0.002 / 0.0018 | 0.005 / 0.0003 | 0.000 / 0.0009 |
| DA: robust per-domain normalisation + target threshold | 0.000 / 0.015 | 0.002 / 0.010 | 0.000 / 0.0025 |
| DG: KS < 0.3 shift-robust feature subset + target threshold | 0.000 / 0.0043 (ROC 0.41) | 0.000 / 0.0011 (ROC 0.41) | 0.000 / 0.0009 (ROC 0.15) |
| supervised in-domain retraining, target labels (upper bound) | 1.000 / 0.0007 | 1.000 / 0.0007 (nf_flow_ctx) | 1.000 / 0.0008 |

1. **No source-based method recovered detection.** Threshold calibration did its job: it cut
   the FPR from 34–99% to about 1e-3. But the source model ranks target attacks no better
   than chance (ROC 0.37–0.68), so a calibrated threshold leaves recall about 0. Robust
   normalisation lowered ROC further (0.26–0.41 into UNSW), because it maps the
   direction-conflicting features onto the source scale.
2. **Calibration size.** For the source-based methods, 1,000 clean flows already gave a
   stable FPR (0.0012 ± 0.0008), and more data did not help, since there was nothing left to
   recover. Target-benign normal models (section 3) are where size matters.
3. **Unlabelled calibration is harmful.** The calibration samples carried their true attack
   share: 9.1% (UNSW), 16.5% (NF-IDS) and 13.1% (CIC). Then even the *in-domain* supervised
   model's calibrated recall fell from 1.000 to 0.011 (UNSW) and to 0.000 (NF-IDS and CIC).
   The attack mass in the calibration quantile pushes the threshold above most attacks. Every
   target-normal model degraded the same way. Real networks have lower attack shares, but
   the result shows calibration needs vetted benign data or a robust (trimmed) quantile.

## 3. Normal-behaviour modelling (Mission 3), validation

Same protocol, with one-class detectors fit on half of the clean target calibration sample
and thresholded on the other half (FPR 1e-3). Feature views: per-flow ("flow"), multi-scale
context ("ctx"), both ("all").

| Target, detector (clean 50k) | NF-UNSW | NF-IDS2018 | CIC-IDS2018 |
|---|---|---|---|
| robust-z, flow | 0.001 / 0.0008 (ROC 0.88) | 0.000 / 0.0008 (ROC 0.45) | 0.000 / 0.0015 (ROC 0.56) |
| Isolation Forest, flow | 0.007 / 0.0009 (ROC 0.94) | 0.000 / 0.0009 (ROC 0.92) | 0.000 / 0.0010 (ROC 0.80) |
| Isolation Forest, ctx | 0.000 / 0.0000 (ROC 0.61) | 0.000 / 0.0000 (ROC 0.40) | 0.000 / 0.0000 (ROC 0.95) |
| autoencoder, flow | **1.000** / 0.0006 (ROC 1.00) | 0.000 / 0.0010 (ROC 0.91) | 0.000 / 0.0014 (ROC 0.76) |
| autoencoder, all | 0.745 / 0.0007 | 0.000 / 0.0009 (ROC 0.87) | 0.000 / 0.0009 (ROC 0.93) |

(In-domain runs B; the UNSW column agrees with the target-side detectors of the IDS -> UNSW
runs, e.g. autoencoder flow 0.979.)

- **On both IDS2018 variants, no detector reaches non-zero recall at FPR 1e-3.** This holds
  even where ranking is good (Isolation Forest on ctx, ROC 0.95 on CIC). The attacks score
  higher than typical benign flows but not higher than the benign tail, so an operational
  threshold removes them. This replicates v1–v3 (audit V5–V7) with three detector families
  and two feature schemas.
- **NF-UNSW is the exception, and the reason is an artefact.** The flow autoencoder's recall
  rises with calibration size: 0.14 (1k), 0.83 (10k), 0.98–1.00 (50k).
  `scripts/audit/audit_autoencoder.py` (`reports/audit/autoencoder_unsw.json`, seed 42)
  shows why. UNSW benign flows have essentially constant TTL and minimum packet length
  (median |z| = 0); attacks sit at |z| ≈ 20 on TTL. `min_ttl`/`max_ttl` carry 65% of the
  attacks' reconstruction error. Without TTL and window fields, recall is 0.95, now carried
  by `shortest_flow_pkt`/`min_ip_pkt_len`. Dropping the top 5 error features leaves 0.18.
  The detector flags "a host stack other than the testbed's", which works on a 40-host IXIA
  testbed whose 4 attacking hosts differ in OS stack. It is not evidence of behavioural
  unknown-attack detection.
- **Isolation Forest misses the same signal.** With 512-sample trees over 49 features it
  rarely splits on near-constant features, so robust-z and Isolation Forest stay at about
  0.01 recall.
- **No unknown-attack detection claim is made.** The same "unusual" verdict is kept separate
  from "suspicious" in the product. Section 6 shows what that means on a real benign capture.

## 5. Multi-task objectives audit (Mission 4)

| Objective | Training data / label | Model | Evidence (best, honest number) | Integrated in product? | Limitation |
|---|---|---|---|---|---|
| Application / service identification | (a) IANA port category (deterministic); (b) **new**: nDPI master protocol from NF-v3 `L7_PROTO`, benign flows | (a) lookup; (b) LightGBM on flow shape, with abstention | (b) validation macro-F1: NF-IDS 0.941 without port vs 0.840 port lookup; NF-UNSW 0.730 vs 0.634 | (a) yes, labelled "port heuristic"; (b) no (needs nDPI-compatible fields at inference) | the label is DPI output, not ground truth; TLS is one class (no app-in-TLS claim) |
| Normal-behaviour modelling | benign flows (global or per service) | EmpiricalScorer reference, robust-z, IForest, autoencoder | recall about 0 at FPR 1e-3 on IDS2018 (both schemas); UNSW success is a host-stack artefact (section 3) | yes: anomaly score 0–100, "unusual" verdict | does not transfer to a new network without target calibration (section 6) |
| Anomaly score | percentile of the benign reference | EmpiricalScorer with tail extension | on real benign CTU-26 traffic, p01 = 99.4 against a threshold of 97.5 | yes | uncalibrated on new networks: almost everything is "unusual" |
| Binary attack detection | labelled flows, episode split | LightGBM (v1–v5) | in-domain recall about 1.0 at FPR 1e-3 (validation); CIC test 0.983 at FPR 0.0009 | yes ("suspicious") | saturated in-domain; fails across networks (sections 1–2) |
| Attack-type classification | labelled attacks (label / family) | LightGBM multiclass | CIC test macro-F1 0.889; SQLi recall 0.017 | CIC replay bundle only; not in the portable bundle | fixed confidence threshold 0.6 (not tuned; docstring corrected) |
| Unknown-attack handling | held-out behaviour groups | supervised flow+ctx; anomaly fusion | v3 open-set: context lifts port-21/SSH/HTTP-DoS to 0.95–0.999, web attacks stay at 0.015; anomaly-only 0 | partly: "unusual" vs "suspicious" verdicts | no claim of unknown-attack detection |

**Application identification details.** Evidence: run `20261020-022406_appid_nf`
(`appid_results.json`); validation B rows, 10 most frequent classes plus "other"; benign only;
episode-split train/validation; test excluded. Accuracy / macro-F1:

| Model | NF-IDS2018 | NF-UNSW |
|---|---|---|
| majority class | 0.394 / 0.051 | 0.340 / 0.046 |
| port lookup (protocol, dst_port) | 0.906 / 0.840 | 0.691 / 0.634 |
| LightGBM, flow shape, no port information | 0.989 / 0.941 | 0.834 / 0.730 |
| LightGBM, flow shape + port class | 0.991 / 0.952 | 0.837 / 0.734 |
| abstention (threshold from val A): coverage at 99% accepted accuracy on val B | 0.996 (accepted acc. 0.990) | 0.654 (accepted acc. 0.991) |

- Flow shape adds to the port where port and DPI label disagree. On NF-IDS, SMB2/3 recall is
  0.979 from shape vs 0.003 from the port, and RDP 1.000 vs 0.794. On NF-UNSW, NFS is
  1.000 vs 0.352 and eDonkey 1.000 vs 0.238.
- The port alone is better for SMTP/IMAP/telnet/HTTP-proxy, and adding the port class gives
  only +0.01 macro-F1.
- **Caveats.**
  1. The target is nDPI's guess. On NF-UNSW, 52% of benign flows are labelled
     eDonkey/BitTorrent. That is more plausibly nDPI guessing P2P on the IXIA generator's
     random ports than real P2P.
  2. The shape features include TTL and TCP window, which identify *hosts*. In networks with
     few servers the model can learn "which server" rather than "which application". A
     no-shortcut ablation was not run.
  3. The nDPI version, and so the ID-to-name mapping, is assumed (nDPI 4.8).
  4. Encrypted traffic: TLS is a single class, recovered with 0.984 recall on NF-IDS. We
     make no claim about identifying applications inside TLS or QUIC.
- **Integration.** Not added to the PCAP/Zeek bundle. The model uses per-direction IAT,
  TTL and size-bin fields, and our PCAP extractor matches nProbe on these only in aggregate
  identities (section 6), not field by field.

**Did application-aware modelling reduce false positives?** The only application-aware
mechanism evaluated end to end is the service-conditioned anomaly reference (v1 H2). It
changed Isolation Forest PR-AUC by +0.05 and robust-z by −0.14, with recall about 0 either
way. No evidence that it reduced false positives at an operating point. The learned
application label (above) was not used for conditioning; that remains future work.

## 6. PCAP / Zeek pipeline on a real capture (Mission 6)

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

**End to end on real traffic.** `netsentinel analyze` with the deployed portable bundle
(`models/bundle-20261019T202605Z`: threat model and anomaly reference trained on NF-IDS2018)
ran on the whole capture. Outputs: `reports/experiments/ctu26_analyze_{pcap,zeek}.json` and
`ctu26_verdict_breakdown.json`; 38 s for both inputs.

| Input | Flows | benign | unusual | suspicious | attack | suspicious per hour (6.5 h) |
|---|---|---|---|---|---|---|
| PCAP (our assembler) | 17,268 | 0 | 17,129 (99.2%) | 139 (0.8%) | 0 | 21.4 |
| Zeek conn.log | 15,081 | 0 | 14,858 (98.5%) | 223 (1.5%) | 0 | 34.3 |

- The capture is benign, so every "suspicious" verdict is a false alert. All but one are on
  web ports.
- The anomaly score has p01 = 99.4 against an "unusual" threshold of 97.5, so the anomaly
  output carries no information on this network.
- This is the transfer failure of sections 1–3, reproduced on real telemetry with both
  extractors. The bundle **must not be used on a new network without target calibration**
  on vetted benign traffic. The product exposes no calibration step for that yet
  (`analyze` has no calibrate mode); this is listed as unsolved.

**Not validated.** We have no paired capture with nProbe NF-v3 output, so the field-level
agreement with the training features is still unverified. That includes the per-direction
IAT, TTL, window and retransmission fields, nProbe's own flow-cut rules, and nDPI labels.
Agreement with Zeek covers flow boundaries, packet and byte accounting, direction and TCP
state only.

## 7. End-to-end system audit (Mission 7), 2026-10-20

"Verified" means exercised in this phase, by an automated test or by a run on real data whose
output is in `reports/`. Anything else is labelled.

| Component | Status | Evidence |
|---|---|---|
| CLI (`netsentinel data/features/train/bundle/replay/analyze/serve/evaluate`) | verified | 74 default tests pass (`uv run pytest`); every stage used in v5, app ID and the final runs ran via the CLI |
| PCAP / pcapng reader | verified on real data | CTU-26: 199,279 packets, 0 IP packets lost (section 6); malformed paths covered by unit tests only |
| Flow assembler | verified against Zeek; **defect fixed** | close-linger fix; TCP flow count equals Zeek's; 99.8% packet/byte agreement under Zeek timeouts |
| Zeek conn.log reader | verified on real data | 15,081 / 15,081 records parsed, 0 skipped |
| Field compatibility with NF-v3 (nProbe) | **not verified field by field** | aggregate identities match NF-IDS; `*_SECOND_BYTES` semantics differ; no paired nProbe capture |
| Context features / windowing on PCAP-derived flows | verified to run, no nulls | `analyze` frame: 0 null / non-finite cells; correctness vs training-time context only by shared code |
| Inference engine + bundle integrity (SHA-256) | verified | integration tests incl. tampered-bundle refusal; real-capture run |
| Decision layer | verified (unit) | `test_decision.py`; docstring corrected (attack-type threshold is a fixed 0.6) |
| Model quality on a new network | **fails without calibration** | CTU-26: 99% "unusual", 21–34 false "suspicious" flows/h (section 6) |
| SQLite event store | verified | written by `analyze` (CTU-26) and replay tests; idempotent ids (tests) |
| FastAPI (`/predict/flow`, `/analyze`, `/events`, auth, size limits) | verified by tests only | `test_serving.py`, `test_offline_app.py` (TestClient); not load-tested; not exposed on a network |
| Streamlit dashboard | **not re-verified in Phase 5** | no automated test; last manual check in Phase 2 (README screenshots) |
| Docker image / compose | **unverified** | Docker is not installed on this machine; the Dockerfile has never been built |
| GitHub Actions CI | **unverified** | the workflow exists but has never run: no remote repository (pushing needs your authorisation) |
| Pre-registered final test (NF) | see section 4 | one-shot markers in `reports/final/` |
