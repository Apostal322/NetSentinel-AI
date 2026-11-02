# Phase 8l: DEDALE feasibility for a single-network longitudinal test

**Date:** 2026-11-02. **Status:** desk assessment. **No data member has been downloaded.** No
flow record and no label value from DEDALE has been read. **No model was trained.**
- **What was read:** archive metadata only, i.e. names, sizes and CRC32s of every member,
  including those of the evaluation days. That is disclosed in the pre-registration.

**Scope.** This is the narrower question named in the Phase 8l README: on one unseen
environment, does a calibrated threshold hold its false-alert budget over time? It is a
single-network external validation (N = 1).
- **It cannot change the Phase 8l decision**, NO-GO for network-level accept/reject
  confirmation. DEDALE adds at most one environment against the ≥ 15–30 needed
  (POWER_ANALYSIS.md).

## Sources read

| source | what was read | how |
|---|---|---|
| Dataverse record, DOI 10.57745/Y5JLDG, version 2.1 (released 2026-09-25) | metadata, licence, file list with sizes and MD5s | Dataverse API, saved JSON |
| `README.md` in the record (4,772 B, MD5 `1fa4df8d…` matched) | documentation | downloaded and checked |
| https://dedale.inria.fr/ (`index`, `download`, `rescousse`, `user_behavior`, `attack_scenario` pages) | documentation, licence, attack timeline | HTML |
| `hash_zeek_archives.md5` (mirror) | archive MD5s | text; identical to the Dataverse MD5s |
| gitlab.inria.fr `mlanvin/dedale_labeling` (GitLab API) | `labelling_script_on_single_conn.log.py`, `zeek_tools.py`, READMEs, licence | public code; read as code only |
| gitlab.inria.fr `mlanvin/rescousse` at commit `ba47b61e` | file tree, Ansible inventory, settings | public code; one inventory template |
| central directories of `zeek_*.zip` (4 taps) and `userbehaviour_logs.zip` | member names, offsets, sizes, CRC32s | HTTP range reads of the zip index only: 131–263 kB per archive, no member data (`scripts/phase8l/dedale_zip_index.py` → `reports/phase8l/dedale_zip_index.json`) |

**The user verified independently:**
- 55 virtual machines in four zones;
- four weeks: two benign weeks, then an 8-day APT;
- CC BY 4.0;
- labelled Zeek connection logs;
- the official split: weeks 1–2 for training and calibration, weeks 3–4 for evaluation.

Every item agrees with the sources above, with the one wording difference noted in section 1.

## 1. Hosts: documented machines vs active, independent benign calibration hosts (task 1)

**What is documented (verified):**
- **The roster.** `userbehaviour_logs.zip` holds one AURA timeline and one execution log per
  machine that generated benign activity. That gives 45 machines:

  | zone | machines |
  |---|---|
  | green (internal company clients, Windows) | 30 (`internal_company_client_windows_1` – `_30`) |
  | external: remote employees (Linux) | 5 (`external_company_client_linux_1` – `_5`) |
  | external: other clients | 5 Windows, 5 Linux |

- **Infrastructure.** The RESCOUSSE inventory adds the servers, routers and the attacker: log
  server, internal server (DC), DMZ server, web server, VPN, external mail, four routers,
  attacker. That gives 11 types, about 56 in total, consistent with the user's 55.
  - The record's README says "about 40 virtual machines". That figure appears outdated.
- **Compromised hosts** (official timeline and labelling script):
  - client 2, `172.16.1.3`, from 2025-01-06 10:00 UTC;
  - client 1 (the administrator), `172.16.1.2`, from 2025-01-08 15:10;
  - the DC / samba server `172.16.0.2` is read for exfiltration from 2025-01-10.
  - So **28 internal clients are never compromised.**

**What is not verified, and cannot be without data:**
- **The active, independently represented benign calibration hosts at the green tap.** It is
  unknown:
  - how many of the 28 send traffic in weeks 1–2;
  - with how many 30 s windows each;
  - how balanced they are (Kish effective hosts, top-host share);
  - whether each keeps one address. The green tap has a `dhcp.log`, so addresses may be leased
    dynamically.
- **The data-plane addresses of the other 28 clients.** The roster gives management addresses
  (192.168.56.51–80). The timeline gives `172.16.1.2` for client 1 and `.3` for client 2,
  suggesting `172.16.1.(k+1)`. That is an inference.
- **28 (or 26) is below the E2 floor of ≥ 30 active benign sources.** So DEDALE is not a strict E2 pass
  even before activity is checked.
- **Independence is weak.** All 30 internal clients are clones driven by one generator (AURA,
  with equiprobable action transitions).
  - A high Kish count would show balanced volume, not behavioural diversity.
  - On AIT, emulated clients collapsed to 3.6–7 effective hosts.

**Correction made in DATASET_ELIGIBILITY.md:**
- "~30 emulated clients (secondary source; unverified)" becomes "30 documented internal
  clients among about 55 VMs, 28 not compromised by the timeline, 26 primary candidates;
  active, independently represented calibration hosts unverified (Stage A gate)".
- The licence is now marked verified.

## 2. Licence and citation (task 2)

**Data licence (verified):**
- **Terms:** Creative Commons Attribution 4.0 International. This is the record's terms of use.
- **The project page adds:** "any use or redistribution of the data must include a citation to
  the DEDALE dataset and a link to this page" (https://dedale.inria.fr/download.html).

**Required attribution** in any report, figure or derived artefact:
- **Dataset**, as generated by the repository:
  - LANVIN, Maxime; MAJORCZYK, Frederic, 2026, "DEDALE: Dataset for Evaluating Detection of APT
    among Logs and Events", https://doi.org/10.57745/Y5JLDG, Recherche Data Gouv, V2.
  - The API reports version 2.1.
  - Also cite https://dedale.inria.fr/download.html.
- **Paper:** Lanvin, M., Majorczyk, F. (2025). Get out of DEDALE with RESCOUSSE: a New Dataset
  and Testbed for Evaluating the Detection of APT attacks among Network and System Logs. In:
  *Computer Security. ESORICS 2025 International Workshops*, LNCS 16232, Springer.
  https://doi.org/10.1007/978-3-032-16092-8_1 (HAL hal-05329482).
- **Producers:** Inria (PIRAT team) and DGA.

**Handling:**
- Raw data stays under the git-ignored `data/raw/dedale/`. Nothing from DEDALE is committed,
  only aggregate results.
- **The labelling code's licence is inconsistent:** its `LICENSE.txt` is MIT, its README says
  GPL-3.0. It is not redistributed or imported, so this does not affect us. It is recorded
  here.

## 3. Monitoring points (task 3)

The Zeek logs are published as **one archive per tap, each spanning all four weeks**. Inside,
there is one folder per day `D1_2024-12-23 … D28_2025-01-19`, and each day has:
- the original Zeek logs, including `conn.log`;
- **`conn_labeled.csv`**: the labelled connection log.

| tap (archive) | archive | conn_labeled, 4 weeks (zip / raw) | benign hosts it sees | attack visibility (from the timeline) | suitable |
|---|---|---|---|---|---|
| `zeek_orange_dmz.zip` | 0.42 GB | 42 MB / 146 MB | DMZ servers (web, mail/DVWA, VPN), external clients | initial access only (the malicious email and its retrieval) | no: few benign hosts, attack mostly invisible |
| `zeek_orange_servers.zip` | 3.41 GB | 713 MB / 2.8 GB | clients and servers talking to the internal servers (log shipping, DC) | SMB/DLL staging, PrintNightmare DLL fetch, SSH collection; not the C2 or reverse shells | partial |
| **`zeek_green_internal.zip`** | **3.54 GB** | **780 MB / 2.77 GB** | **the 30 internal clients** | **all client-side steps: C2 and reverse-shell beacons, lateral movement, DC access** | **yes: smallest suitable** |
| `zeek_router1.zip` (3 interfaces) | 4.40 GB | 1.19 GB / 4.1 GB | inter-zone and Internet traffic | C2 and Internet steps; the labelling code mentions (commented-out) NAT on router zones, so per-host identity may be lost | no: needed for nothing here |

**Weekday pattern.** Weekdays carry about 37 MB of compressed `conn_labeled` per day at the
green tap; weekends about 1 MB. AURA shuts clients down after working hours, so the
calibration fortnight is in effect 10 working days.
- Christmas Day and New Year's Day have full weekday volume: the emulation has no holidays.

## 4. Is the 11 GB download necessary? (task 4)

**No.**
- The 11 GB figure was the four whole Zeek archives (11.76 GB).
- The study needs one tap: green_internal (3.54 GB whole).
- From that tap it needs only one member type per day, `conn_labeled.csv`, plus the tiny
  `dhcp.log` for the address-stability check.
- Zip members can be fetched individually by byte range at the offsets in the central
  directory, and verified against its CRC32 and sizes.

| option | download |
|---|---|
| four Zeek archives | 11.76 GB |
| whole `green_internal.zip` (MD5-verifiable as one file) | 3.54 GB |
| **selected members, both stages** | **780.2 MB** (780,245,342 B: 56 of the archive's 663 files, 22 % of its bytes) |
| of which **Stage A** (calibration days D1–D14) | **384.0 MB** (383,993,579 B; 1.37 GB uncompressed) |
| of which Stage B (evaluation days D15–D28, after the freeze) | 396.3 MB (396,251,763 B) |

**Trade-off.** Member fetching cannot verify the archive-level MD5. Each member is instead
verified against the publisher's CRC32 and both sizes, and its SHA-256 is recorded. Whole-archive
download remains available if MD5-level integrity is preferred.

## 5. Which archives hold the four weeks and the official labels (task 5)

- **Four-week span (verified from the central directories):**
  - all four `zeek_*.zip` archives contain 28 day folders, D1 = 2024-12-23 to D28 =
    2025-01-19, with none missing;
  - green_internal has `conn.log` and `conn_labeled.csv` for every day.
- **Official flow-level labels** live in `conn_labeled.csv` (README: "the labels … in the Zeek
  logs … (conn.log files)"; labelling script).
  - It is written by `labelling_script_on_single_conn.log.py`: `;`-separated, sorted by `ts`.
  - **Columns:** `date`, the 22 `conn.log` fields renamed (`ip_src`, `port_src`, `ip_dst`,
    `port_dst`, …), then `label` (0 benign, 1 attack, 2 attack-related), `step`,
    `attack_step`, `tactic`, `technique`, `comments`.
  - **Not yet seen in a file.** The column list comes from the code. It is checked at Stage A on
    calibration files.
  - **No label value has been read.**
- **The labels are a deterministic function of public information.**
  - The script marks flows that match the documented attack timestamps (UTC), the IP pair, and
    sometimes the port or service, within margins of 0.5 s to 180 s, in both directions.
    Everything else stays 0.
  - Consequence: label values are not secret, and protecting the evaluation means protecting
    our **scores** on days D15–D28. That is enforced by not downloading them before the freeze.
  - The earliest labelled event is 2025-01-06 10:00:13 UTC, minus at most 180 s. So weeks 1–2
    are label-0 by construction.
- **Label completeness is limited.**
  - Only listed events are labelled, for example one C2 beacon per day at 11:00.
  - Unlisted malicious flows of a compromised host stay 0.
  - Therefore compromised hosts are excluded from "verified benign" for the whole study, not
    flow by flow (pre-registration, section 2).
- **Script detail.** The reverse-direction match uses the default 180 s margin even where the
  forward match is narrower. This widens labels slightly; it is noted, not corrected.
- **Ancillary labels, not used:**
  - host labels in `system_logs_labels.zip`;
  - CICFlowMeter labels in `cicflowmeter_*.zip`;
  - the PCAP archives, of which 10 of 24 are declared corrupted by the publisher. None of these
    is needed.

## 6. Taps are not independent networks (task 7)

- **One environment, one unit.**
  - All taps record the same 55 VMs, in the same four weeks, with the same attack.
  - A flow between zones appears at several taps.
  - Using a second tap would duplicate units, not add them.
- **The study uses the green_internal tap only.**
  - No result from another tap may be reported as a replication.
  - Weeks 3 and 4, and individual days, are repeated measurements of one unit, not replications.
- **Network-level count:** DEDALE stays 1 environment from 1 generator, RESCOUSSE/AURA. The
  cross-network inventory is unchanged.

## 7. Bounded-memory processing (task 8)

**Disk.** C: has 39 GB free. The plan needs ≤ 1.5 GB:
- 384 + 396 MB of `.gz` members;
- ≤ 0.6 GB of derived Parquet;
- no uncompressed CSV kept.

**Pipeline**, every step under `scripts/run_capped.py` (3.4 GiB Job Object) with an absolute
interpreter path:

1. **Fetch** (`dedale_fetch.py`):
   - streams each member in 1 MiB chunks to `data/raw/dedale/green_internal/*.gz`;
   - stores the publisher's deflate bytes unchanged in a gzip wrapper;
   - CRC32 and size are checked on the fly; nothing is held in memory.
2. **Per-day conversion**, one day at a time, in date order:
   - read one member with explicit dtypes and only the needed columns (largest member: 152 MB
     uncompressed);
   - map to the canonical flow schema (`telemetry_maps.zeek_conn` field rules), with a DEDALE
     adapter for the renamed columns and the 0/1/2 label;
   - build the 30 s per-source P1x windows;
   - write one Parquet file per day;
   - the calibration destination memory is carried across days as a set;
   - label columns go to a separate per-day Parquet that scoring never reads.

   Expected peak about 1 GB.
3. **Scoring:** at most about 2 M windows × 12 float32 features (< 0.1 GB) per seed.
4. **Statistics:** host-cluster bootstrap in chunks (as in `confirm_analysis.py`, which ran at
   861 MiB).

**One process at a time.** No torch.

**Runtime estimates:**

| step | estimate |
|---|---|
| Stage A conversion + F0 counts | 3–6 min |
| scoring | ~1 min per seed |
| source-model fitting (separate approval) | ~5 min |

## 8. Eligibility verdict

**Conditionally eligible for the single-network longitudinal temporal-validity test only:**
- **Licence:** satisfied.
- **Labels:** documented, flow-level, deterministic.
- **Benign-then-attack timeline:** satisfied, with the official split.
- **Download:** small (0.78 GB in two stages).

**Two conditions are unverified and could make it ineligible:**
- **Active, independently represented benign calibration hosts:**
  - 26 primary candidates (28 not compromised by the timeline, minus clients 3–4), below the
    30 of E2;
  - one generator;
  - activity and address stability unknown.
- **The conn_labeled schema:** known from code only.

Both are checked by the Stage A gate on the calibration fortnight alone. No evaluation-day
file is needed to decide.

**Not eligible as anything more:** it is one environment. **The Phase 8l NO-GO for network-level
accept/reject confirmation stands unchanged.** Even a perfect result would be n = 1.

## 9. Approval requested now: Stage A only (the minimum necessary download)

> **Download 28 members of `green_internal.zip` from https://dedale.inria.fr/data/network_logs/zeek/green_internal.zip by HTTP range: the 14 `conn_labeled.csv` and 14 `dhcp.log` members of days D1–D14 (2024-12-23 – 2025-01-05). That is 383,993,579 bytes, listed with offsets and CRC32s in `docs/phase8l/DEDALE_MANIFEST.md`. They go to `data/raw/dedale/green_internal/`, and the Stage A gate runs on them (counts only, no scores, about 3–6 min under the 3.4 GiB cap).**

**Not included in this approval:**
- the evaluation days D15–D28 (Stage B, 396.3 MB). The code refuses them until
  `docs/phase8l/DEDALE_FREEZE.md` is committed and holds the pre-registration's SHA-256;
- fitting the three registered source models;
- any score, threshold or detection metric;
- any other tap or archive.
