# Phase 8l dataset eligibility and independent-network inventory

**Date:** 2026-11-02. **Method:**
- desk research by a research agent, with no downloads and no logins;
- the decisive facts re-checked directly:
  - DEDALE through the Dataverse API (Inria/DGA);
  - the UWF listings;
  - the AIT notebook.

**The unit of a cross-network claim is an independent capture environment.** Days, weeks,
hosts, tap points or networks produced by one generator are not independent units.

## 1. Eligibility requirements

| # | requirement |
|---|---|
| E1 | bidirectional flows (src/dst IP, port, protocol, start/end time, per-direction bytes and packets, TCP resets or connection state), or PCAPs from which Zeek/Tstat can produce them |
| E2 | benign traffic from many distinct hosts: ≥ 30 active benign sources, not dominated by a few servers, and verifiably benign rather than "unlabelled background" |
| E3 | attacks with documented attacker and victim hosts and times, from the experiment design |
| E4 | an early benign period usable for calibration |
| E5 | valid temporal ordering: real timestamps, benign traffic not sampled out |
| E6 | clear licence, no-login access, each network ≲ 2 GB of flow data (larger needs approval) |
| E7 | institution / environment distinct from everything consumed or used |

## 2. Inventory

| dataset | environment | E1 | E2 | E3 | E4 | E5 | E6 | E7 | independent units | role |
|---|---|---|---|---|---|---|---|---|---|---|
| NF-CIC, NF-UNSW, NF-ToN, NF-BoT (v3) | testbeds (UNB; UNSW ×3) | ✔ | CIC only | ✔ | ✔ | ✔ | ✔ | – | 4 (2 institutions) | **development (all inspected or consumed)** |
| CTU-13, IoT-23, CTU-Normal (Stratosphere, CTU Prague) | university network captures | Zeek | few hosts per capture | ✔ | – | ✔ | ✔ | – | – | consumed or inspected in Phases 5–8g (E7 for everything else) |
| **AIT Netflow v2** (8 networks) | emulated small enterprises | ✔ Tstat | ✘ 3.6–7 effective hosts | ~ attacker role and step times documented; flow labels by time window | ✔ | ✔ | ✔ CC BY | ✔ | **1–2** (one generator) | development / demonstration only |
| **UWF-ZeekData24** | cyber range | ✔ Zeek | ✘ benign pooled and reduced | flow labels | ✘ | ✘ | ✔ | ✔ | 0 | not eligible |
| **DEDALE** (Inria/DGA, 2025; DOI 10.57745/Y5JLDG) | emulated enterprise (RESCOUSSE) | ✔ Zeek + PCAP | ~30 emulated clients (secondary source; unverified) | ✔ one documented APT campaign | ✔ weeks 1–2 benign only (verified) | ✔ | Zeek 0.4–4.4 GB zipped per tap (verified); licence CC BY 4.0 per the agent (unverified) | ✔ | **1** | the only clean confirmation-grade unit |
| Corrected DARPA OpTC (Inria, 2026) | emulated enterprise, ~500 hosts | eCAR host logs; Zeek only in the original release | many | ✔ corrected labels | ✔ | ✔ | ✘ ~940 GB | ✔ | 1 | needs a separate large-data decision |
| LITNET-2020 | real academic backbone | NetFlow v9, probably unidirectional | real, unverified | method undocumented | ? | archives per attack type | ✔ | ✔ | ≤ 1 | partial (development at most) |
| UGR'16 | real ISP | unidirectional | unverified background | injected, documented | ✔ | ✔ | ~320 GB; site returned 403 | ✔ | ≤ 1 | partial |
| RoEduNet-SIMARGL2021 / 2022 / APPRAISE | real academic / mall | nProbe v9 | real, unverified | ✔ (2021) | ? | ? | Kaggle login / unknown | ✔ | 1–2 | access unverified |
| CIDDS-001/002 | emulated small business | unidirectional + flags | ✘ ~19 clients | ✔ | interleaved | ✔ | ✔ | ✔ | 1 | development only |
| 5G-NIDD | real 5G testbed | ✔ Argus | ✘ ~8 users | ✔ | ✔ | ✔ | login / mirror | ✔ | 1 | not eligible (E2) |
| CTU-SME-11, Cyber Czech 2019, BOUN DDoS, CESNET-CC25/TS24, DAPT2020, Unraveled, SCVIC-APT, CIC/BCCC family, Kitsune, Kyoto 2006+, LANL | various | – | ✘ | – | – | – | – | – | 0 | fail (reasons in the agent report: too few hosts, heuristic or no labels, separate attack networks, same lab as CIC-IDS2018, login, size) |

## 3. How many independent units exist

- **Confirmation-grade: 0–1, pending verification** (DEDALE).
  - Its E2 rests on a second-hand "~30 emulated clients" and its licence is unverified: the
    project repository blocked automated access.
  - Emulated clients collapsed to 3.6–7 effective hosts on AIT.
  - Its single APT campaign gives the same 0/1-like entity recall.
  - Corrected OpTC would add 1 if its ~940 GB host logs, or the original Zeek logs, were
    workable.
- **Development-grade** (relaxed E2/E3: unverified real background, unidirectional flows, or
  < 30 hosts):
  - 3–6: LITNET, UGR'16, SIMARGL, CIDDS, AIT (1–2), 5G-NIDD;
  - plus the 4 development networks already used.
- **Separation:** if any confirmation is ever run, DEDALE must stay unopened until a freeze.
  Development candidates may be inspected freely.

## 4. Data and compute for the candidates

| candidate | download | processing | approval |
|---|---|---|---|
| DEDALE, Zeek logs only (3 internal tap points) | 3.4–4.4 GB zipped per tap; ~11 GB for internal + router + servers | streamed Zeek → canonical, under the 3.4 GiB cap | **required** (above 2 GB) |
| AIT, remaining 7 networks | 252.9 MB | minutes | required (but not recommended: section 2) |
| LITNET / CIDDS (development) | 0.4–1.2 GB | minutes; unidirectional flows need stitching | required |
| corrected OpTC | ~940 GB | beyond this machine | not feasible locally |
