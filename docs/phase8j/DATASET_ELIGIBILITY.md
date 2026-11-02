# Phase 8j dataset eligibility assessment

**Date:** 2026-11-02. **Method:** desk research of publisher pages and papers. A research agent
surveyed 15 candidates. The facts used for the decision were then re-checked directly: the AIT
Zenodo record, its README and `label_info.txt`, and the UWF portal. **No dataset file was
downloaded.** The two AIT text files (README, 2.1 kB; label list, 1 kB) were fetched only to
read them. "Unverified" marks every claim that rests on a paper, the agent's reading or a
secondary page only.

## 1. Requirements (from the Phase 8f eligibility table, adapted to the reliability question)

| # | requirement | why |
|---|---|---|
| E1 | network, organisation and capture never used by NetSentinel | independence from development and consumed data |
| E2 | official source; licence permits research use; no login or account creation needed | provenance; the project cannot create accounts |
| E3 | per-flow src/dst IP, ports, protocol, start/end time, per-direction bytes and packets, connection state or flags | the 12 window features |
| E4 | **≥ 10 benign source hosts** active in the calibration period | the reliability question needs host diversity that varies across units |
| E5 | attack host list with time intervals, produced by the experiment design and kept separate from flow labels or recoverable from a schedule | verified initiators; calibration-period exclusion (P1x) needs timed labels |
| E6 | ≥ 2.5 h calibration + ≥ 2.5 h evaluation per unit; ≥ 1 h of benign evaluation | Phase 8e evidence standard |
| E7 | download and processing within the machine limits (≤ ~2 GB without a separate approval; 3.4 GiB memory cap) | resource policy |

## 2. Excluded before assessment (not independent)

CSE-CIC-IDS2018 and NF-CICIDS2018-v3, UNSW-NB15, ToN_IoT, BoT-IoT (all NetFlow v3 variants:
the UQ page lists no v3 dataset from any other source), CIC-IDS2017 and other CIC/UNB sets,
IoT-23, CTU-13 and the CTU-Normal captures (Stratosphere Lab).

## 3. Candidates

| dataset | org, year, environment | access, size | licence | E3 telemetry | E4 benign hosts | E5 labels | verdict |
|---|---|---|---|---|---|---|---|
| **AIT Netflow Data Set v2** (from AIT-LDS v2.0) | AIT Austrian Institute of Technology, 2024 (data 2022); **8 separately generated emulated small-enterprise networks** | Zenodo 10.5281/zenodo.13168643, no login; 8 zips 20.8–56.4 MB, **273.7 MB total** (verified) | **CC BY 4.0** (verified; the raw AIT-LDS is CC BY-NC-SA) | Tstat `tcp_complete`, `tcp_nocomplete`, `udp_complete` on server-side captures (verified from README); Tstat logs carry client/server IPs and ports, per-direction packets and bytes, first/last timestamps and RST counts (Tstat documentation; **the exported CSV columns are unverified**) | 10–24 simulated employees per network plus servers (paper; **unverified**); the flows come from server and attacker captures, so client-to-internet traffic may be missing | per-flow labels from the published attack logs (`label_info.txt`: 13 benign TCP, 39 malicious TCP, 1 malicious UDP category, "data exfiltration"; verified). Attack logs per network with timestamps (paper) | **eligible with caveats** |
| **UWF-ZeekData24** | University of West Florida, 2025 paper (data 2024); VMware cyber range, 15 group subnets (paper, **unverified**) | datasets.uwf.edu, direct HTTP; weekly parquet files, two weeks at 3.7 and 33 MB, 7 weeks in all (agent's reading of the listing, **unverified**) | CC BY 4.0 (portal statement; covers ZeekData24 per the agent, **not confirmed on the portal page**) | Zeek `conn`: ts, IPs, ports, duration, per-direction bytes and packets, `conn_state`: an exact fit | 55 unique source IPs **including attackers** (paper table, **unverified**); benign is VM background traffic | mission logs with technique, src/dst IP/port and UTC start/end (paper; **release not verified**) | **eligible with caveats** |
| DARPA OpTC | DARPA/BAE, 2019; emulated enterprise, ~500 Windows hosts | Google Drive, ~1 TB; Inria corrected release | public domain (agent, **unverified**) | `bro` folder, conn fields **unverified**; one study reports unidirectional flows | ~500 | red-team ground truth; no official flow labels | backup: size and unverified fields |
| 5G-NIDD | Univ. of Oulu, 2022; **real 5G network** | IEEE DataPort shows a login prompt; Fairdata mirror | CC BY 4.0 (Fairdata, unverified) | Argus bidirectional flows | **~8 real users (fails E4)** | scheduled 10-min attack slots from 2 attackers | backup: small-network secondary check only |
| UWF-ZeekData22 | UWF, 2022 | as above | CC BY 4.0 | Zeek conn | not stated | UWF's own 2025 paper documents a 10-hour timestamp offset and ±5 min slop | not eligible: labels |
| LUFlow | Lancaster | GitHub | none stated | Joy flows, no TCP state | – | CTI heuristics | not eligible: IPs anonymised to AS |
| HIKARI-2021, TII-SSRC-23, Westermo, Edge-IIoTset, FLNET2023 | various | – | – | – | ≤ 12 devices or scripted generators | – | not eligible: E4 |
| ACI-IoT-2023, GAMBiT | Army Cyber Institute; Bulls Run et al. | subscription / 0.7–2.8 TB | not stated | – | – | – | not eligible: E2/E7 |
| LANL 2015/2017 | Los Alamos, **real enterprise** | e-mail registration | CC0 | no TCP state; 2015 has no per-direction counts | 17,684 | red team covers authentication only | not eligible: no flow labels |
| MAWILab | WIDE backbone | HTTP | – | anonymised pcap | – | heuristic | not eligible |

Sources: the agent's report (links in `reports/phase8j/dataset_sources.md`) and the pages
re-checked above.

## 4. Shortlist and roles

1. **AIT Netflow v2: primary fresh family F1.** Eight networks give eight calibration units
   whose benign host count and composition differ: the variation the reliability question
   needs. They share one generator and institution, so they are **one environment family**,
   not eight independent environments. Inference across them is clustered by family.
   - **Integrity probe:** the smallest network (`russellmitchell`, 20.8 MB) is opened first
     and only for the telemetry mapping and E3/E4/E6 checks. It is then **excluded from
     confirmation**. Confirmation uses the other 7.
   - **Caveats:** simulated users; server-side vantage point (E4 must be re-checked on the
     probe); according to the paper (as read by the agent, **unverified**), DNS exfiltration
     runs from the start of each simulation, so calibration would contain an attacker from
     the first minute. P1x removes that host only if it is labelled before the calibration
     end; this is checked on the probe.
2. **UWF-ZeekData24: second fresh family F2.** A different organisation, country, range and
   exporter (Zeek). Each week is a calibration unit with its own calibration, but the weeks
   share one range, so F2 counts as one independent environment.
   - **Blocking question (unverified):** the paper reports exactly 50% / 50% malicious and
     benign records, which suggests **down-sampled benign traffic**. That would break 30 s
     windows and fail E4/E6.
   - **Integrity probe:** the smallest weekly file (3.7 MB) is opened for timestamp
     continuity, per-host flow rates and the presence of mission logs. That week is then
     excluded. If benign traffic is sampled, F2 is dropped and DARPA OpTC (a targeted
     download of a few days of `bro` logs, separate approval) becomes F2.
3. **Not a fresh test: NF-BoT-IoT-v3.** It is consumed and used as development data only.
4. **The strongest evidence remains the operator's own network** with a scheduled, authorised
   red-team exercise (Phase 8f protocol). No public dataset combines real production users,
   verified benign hosts and verified initiators.

## 5. Telemetry shift (a known confound)

Development data is nProbe NetFlow v3. F1 is Tstat and F2 is Zeek. Both map to the canonical
flow fields that the window builder needs: IPs, ports, protocol, per-direction bytes and
packets, timestamps, and RST / no-reply indicators. The flow definitions still differ:
timeouts, and how incomplete connections are counted. Source-model ranking may therefore drop
on F1/F2 for reasons unrelated to the network. The reliability question is evaluated
**conditional on the source model as it is**. ROC-AUC and oracle recall on F1/F2 are reported
so that ranking failure and calibration failure stay separate. Each mapping is written and
unit-tested on synthetic records before any fresh file is opened.

## 6. Approvals needed (none requested yet; nothing downloaded)

| step | file(s) | source | size | purpose |
|---|---|---|---|---|
| A1 | `russellmitchell_netflows.zip` | Zenodo 13168643 | 20.8 MB | F1 integrity probe (excluded from confirmation) |
| A2 | smallest UWF-ZeekData24 weekly parquet | datasets.uwf.edu | ~3.7 MB (agent) | F2 integrity probe (excluded) |
| A3 | the other 7 AIT netflow zips | Zenodo 13168643 | 252.9 MB | F1 confirmation, after the freeze |
| A4 | the remaining UWF weeks | datasets.uwf.edu | unknown (≤ ~250 MB expected; listed before asking) | F2 confirmation, after the freeze |
