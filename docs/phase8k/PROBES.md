# Phase 8k probes and feasibility gate F0

**Date:** 2026-11-02, under the user's authorization: probes only, no scores, no confirmation
downloads (PREREGISTRATION.md section 8, step 5).
**Code:**
- `scripts/phase8k/telemetry_maps.py`: the Tstat and Zeek → canonical mappings, unit-tested on
  synthetic records before the gate ran;
- `scripts/phase8k/probe_f0.py`: run under the 3.4 GiB cap with isolated Python (`-I`); peak
  831 MiB.

**Output:** `reports/phase8k/probes.json`.

**What was read:** schema, integrity statistics, and on the **calibration half only** the label
vocabulary and the calibration-period attackers that P1x removes. No model was loaded; no score,
threshold or detection metric was computed; no evaluation-period label was read. Both probes are
excluded from confirmation by registration.

## 1. Downloads (verified)

| probe | source | bytes | check | SHA-256 |
|---|---|---|---|---|
| AIT `russellmitchell_netflows.zip` | Zenodo 10.5281/zenodo.13168643 | 20,849,591 | MD5 `290aa5b8b0a9d0515b7e99329c467364` = Zenodo's published checksum | `760e37d2c862c72604920cc1334768d8e582056b6979a3b160923b73525b0186` |
| UWF week "2024-03-03 – 2024-03-10" `part-00000-0955ed97-…-c000.snappy.parquet` | datasets.uwf.edu | 3,733,862 | size = the listing | `5a085f2749556f2c711af6f9c2bca9d43b3f19bb43696ef9194869f4ea69eb21` |

Both are stored in `data/raw/phase8k_probes/` (git-ignored). The AIT zip holds `tcp_complete.csv`
(82.0 MB), `tcp_nocomplete.csv` (41.3 MB) and `udp_complete.csv` (24.8 MB).

## 2. Telemetry: both map completely

| | F1 AIT (Tstat + AIT labels) | F2 UWF (Zeek conn) |
|---|---|---|
| rows | 377,704 | 50,444 |
| flows with every canonical field | 100% | 100% |
| span | 96.0 h | **24.0 h** (the "week" folder holds one day) |
| largest gap between flow ends | 3.7 min | 8.8 min |
| flows per hour (median) | 2,284 | 2,102 |
| label field | `label` (per flow; all values in the published `label_info.txt` lists; none unknown) | `label_binary` |

**Mapping notes:**
- Tstat counts payload bytes, and the mapping adds 40 B (TCP) or 28 B (UDP) of header per packet
  to approximate nProbe's IP bytes.
- Zeek's `orig_ip_bytes` and `resp_ip_bytes` are IP bytes already.

## 3. Gate F0 (calibration half only)

| | F1 AIT probe | F2 UWF probe |
|---|---|---|
| calibration flows | 118,771 | 25,180 |
| calibration label vocabulary | 23 benign categories (e.g. benign DNS 35,664, proxy 25,957, HTTPS 15,814) and **data exfiltration 9,909** | **"True" 24,679, "Duplicate" 501: no benign label at all** |
| calibration-period attackers (P1x exclusion) | 1: `192.168.231.254` | 15: `143.88.{1..15}.x`, the source of every calibration flow |
| benign calibration sources | 39 | **0** |
| P1x hold-out: windows / hosts / sessions | 9,423 / 35 / 273 | none (no benign windows) |
| P1x hold-out: effective hosts / top host share | **7.0** / 18.3% | – |
| gate: ≥ 10 hold-out hosts and ≥ 10 effective hosts | **fail** (35 hosts, but 7.0 effective) | **fail** |
| gate: ≥ 99% complete fields | pass | pass |

## 4. Outcome

**F2 (UWF-ZeekData24): fails F0 unambiguously.**
- The probe's calibration half contains no benign traffic. Every flow is labelled malicious (or
  "Duplicate") and comes from the 15 group attack hosts, so there is nothing to calibrate on.
- This matches the earlier suspicion that the published parquet keeps the malicious flows and
  down-samples (here: omits) benign traffic.
- Under the registered rule, **F2 is dropped and not downloaded**. Its fallback (DARPA OpTC,
  ~1 TB) would need a registered amendment and separate approval.

**F1 (AIT Netflow v2): the registered wording and the decision rules disagree.**
- The pre-registration says a family "cannot test acceptance" if its probe has "< 10
  calibration hosts". By that wording F1 **passes**: 39 benign calibration sources, 35 hold-out
  hosts.
- The gate as coded (written before the run) also requires ≥ 10 *effective* hosts, because M1
  and M2 need them. By that standard F1 **fails**: 7.0 effective hosts. Four always-on hosts
  carry 72% of the hold-out windows.
- That conflict is reported, not resolved here. It is the user's decision (section 5).

**Label-semantics findings on F1** (they affect any confirmation):
1. **AIT labels flows, not hosts.**
   - The exfiltration flows run from the internal DNS resolver (`192.168.231.254`, client) to
     the attacker (`192.168.230.122`, role `attacker_0`, server). The resolver therefore becomes
     the only "calibration attacker" under P1x.
   - The attacker machine's own client flows are labelled benign ("broken flow - benign"), so it
     **stays in the calibration**.
   - Excluding hosts by the dataset's `role_cli` / `role_serv` columns would fix this. That needs
     a registered amendment before any confirmation file is opened.
2. **Per-source windows will attribute the DNS exfiltration to the resolver.** This is
   consistent with the registered definition ("a window holding a malicious flow"), but it
   inflates the attack-entity count with infrastructure.

## 5. Decision (2026-11-02)

The user chose to **stop**. Phase 8k is recorded as NOT EVALUABLE:
- F1's 7 confirmation networks are not downloaded, and remain untouched;
- no source models were trained for confirmation;
- `FREEZE.md` was not written;
- no amendment was made.

The open F1 questions in section 4 stay open for any future registration: the gate wording,
and role-based attacker exclusion.

## 6. What the gate implies

- **With F2 gone, at most one environment family is left.** Any K1 verdict would carry the
  "single environment family" label.
  - With F1's 7 networks, E3 needs ≥ 2 unsafe networks: 1/C(7, 2) = 0.048.
- **The probe's 7.0 effective hosts** (below M1's 10) make it likely that M1 rejects most F1
  networks. The registered outcome would then be K1 failure on (b)/(d) or NOT EVALUABLE (E2/E3),
  in line with the prior stated before any download.
- **Proceeding with F1 needs separate authorization for:**
  - source models (~5 min);
  - the download (252.9 MB);
  - an amendment fixing (i) the gate interpretation and (ii) the role-based attacker exclusion;
  - the protected run.
