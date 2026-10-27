# CTU-13 eligibility check (for INDEPENDENT_VALIDATION_PROTOCOL.md)

- **Checked:** 2026-10-28.
- **Sources:**
  - stratosphereips.org/datasets-ctu13 (overview);
  - the README.md and directory listings of each scenario under
    mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42 … -54 (the official
    server; the overview names it as authoritative).
- **No data was downloaded.** Only READMEs and directory listings were read.

## Facts

| item | finding |
|---|---|
| licence | **No formal licence.** Every scenario README grants use on condition of attribution: "free to use these files as long as you reference this project" (plus the authors). The overview asks to cite Garcia et al., "An empirical comparison of botnet detection methods", Computers & Security 45 (2014) 100–123, doi:10.1016/j.cose.2014.05.011. |
| network | the CTU university (department) network, Aug 2011, public range 147.32.0.0/16 |
| independence | **New network for NetSentinel.** The CTU-Normal development captures use private 10.0/192.168 ranges. Same lab as IoT-23 (Stratosphere), but a different network and period. |
| initiators | **documented by design per scenario:** the infected VMs (below), from the experiment logs, not inferred from labels |
| telemetry | **Zeek `conn.log` for every scenario** (`bro/` folder, generated 2017 from the full capture): no field mapping needed. Labels are in the Argus bidirectional flows (`detailed-bidirectional-flow-labels/*.binetflow`). |
| labels | Botnet / C&C / Normal / **Background**. Background = unknown, **not** verified benign. Only flows from the 5–6 documented normal hosts per scenario are verified benign. `To-Botnet` flows (sent to the infected host) are not malicious per se (README). |
| full packets | the complete pcaps are private; a truncated pcap (headers only) and a botnet-only pcap are public |

## Per scenario (READMEs and directory listings)

| scenario | ID | botnet | duration | infected hosts (documented) | normal hosts | conn.log | binetflow (labels) |
|---|---|---|---|---|---|---|---|
| 1 | 42 | Neris | 6.15 h | 147.32.84.165 | 6 | 498 MB | 369 MB |
| 2 | 43 | Neris | 3 h 51 min | .165 | 5 | 314 MB | 236 MB |
| 3 | 44 | Rbot | 2 d 18 h 49 min | .165 | 6 | 694 MB | 610 MB |
| 4 | 45 | Rbot | 4 h 29 min | .165 | 6 | 185 MB | 147 MB |
| 5 | 46 | Virut | 30 min | .165 | 6 | 18 MB | 17 MB |
| 6 | 47 | DonBot | 2 h 9 min | .165 | 6 | 90 MB | 73 MB |
| 7 | 48 | Sogou | 21 min | .165 | 5 | 17 MB | 15 MB |
| 8 | 49 | Murlo | 19 h 29 min | .165 | 6 | 477 MB | 385 MB |
| 9 | 50 | Neris | 5 h 38 min | **10:** .165, .191–.193, .204–.209 | 6 | 323 MB | 273 MB |
| 10 | 51 | Rbot | 5 h 8 min | **10:** as scenario 9 | 6 | 1.2 GB | 171 MB (+184 MB labelled) |
| 11 | 52 | Rbot | 16 min | 3: .165, .191, .192 | 6 | 40 MB | 14 MB |
| 12 | 53 | NSIS.ay | 1 h 43 min | 3: as scenario 11 | 6 | 49 MB | 43 MB |
| 13 | 54 | Virut | 16 h 23 min | .165 | 6 | 314 MB | 251 MB |

- **Totals:** about 4.2 GB of conn.log and 2.6 GB of labelled flows. The full archive
  `CTU-13-Dataset.tar.bz2` is 1.9 GB (flows and botnet pcaps; it does not include conn.log).
- **Infected-host notation:** ".165" etc. are 147.32.84.x.
- **Timelines:** the READMEs contain timestamped timelines (CEST) of when the capture, the
  VMs and the bots started.

## Eligibility against the protocol

| requirement | status |
|---|---|
| independent environment | **met.** New network and period. Same lab as IoT-23: disclose it. |
| provenance and licence | **conditional.** Official source confirmed; attribution-only permission with no formal licence text. Your decision whether that is acceptable. |
| verified initiators | **met** (by experiment design). The same IP (.165) is the infected host in every scenario, so scenarios are not independent of each other. |
| compatible telemetry | **met** (Zeek conn.log) |
| ≥ 5 initiators per test | **only scenarios 9 and 10** (10 infected hosts each). Pooling infection episodes across scenarios would repeat the same addresses. |
| ≥ 2.5 h calibration with no initiator active | **not met inside any scenario as written.** The bots start minutes to about an hour after capture start (e.g. scenario 9: capture 12:01, first infected VM 12:27 CEST). The protocol needs a pre-registered amendment before any download. |
| benign false-alarm measurement | **limited** to the 5–6 documented normal hosts. Background traffic is unknown, so alerts on it count as "unverified", not false. |
| size and memory | streaming conn.log keeps memory bounded (Phase 8d: 1.36 GB for 4M records). Scenario 10's 1.2 GB conn.log is the largest single file. |

## Decisions needed before any download

1. **Licence.** Accept attribution-only use, with the citation above.
2. **Calibration amendment** (one of):
   - **(a) Population split:** calibrate on the scenario's first period on all hosts except
     the documented infected VMs (they do not exist before infection), and test on the rest.
   - **(b) Cross-scenario:** calibrate on a long scenario without these VMs active (e.g.
     scenario 13, excluding .165) and test on scenarios 9/10 days later. This collides with
     the 24 h expiry and would be reported as `calibration_expired`.
3. **Scope of the download.**
   - **Minimal:** scenarios 9 and 10 — conn.log (323 MB + 1.2 GB), labelled binetflow
     (273 MB + 171 MB), READMEs. **About 2.0 GB.**
   - **Optional:** scenario 13 for amendment (b) (314 MB + 251 MB).
