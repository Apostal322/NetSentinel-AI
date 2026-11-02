# Phase 8l label-integrity audit (F1 AIT, F2 UWF)

**Date:** 2026-11-02.

**Data read:**
- the two probe units opened under authorization in Phase 8k: AIT `russellmitchell`; UWF week
  2024-03-03. Both are excluded from confirmation by registration, so their full labels may be
  audited;
- publisher documentation;
- the AIT labelling notebook `2_label_logs.ipynb` (Zenodo 13168643), read online.

**Data not read:** the other 7 AIT networks, the other 6 UWF weeks, and UWF's `csv/Benign/`
file.

**Nothing was relabelled.**

**Code:** `scripts/phase8l/label_audit_f1.py`, output `reports/phase8l/label_audit_f1.json`.
It ran under the 3.4 GiB cap and peaked at 442 MiB.

## 1. F1: how the AIT labels are produced (from the notebook)

| label kind | rule | consequence |
|---|---|---|
| benign, complete TCP | ordered role/port rules (e.g. server role `external` → `browsing/update`; employee → intranet → `HTTP(S) intra`), applied **first** | an attacker's flow to an external server is labelled benign, even inside an attack window |
| attack step, TCP | any still-unlabelled flow whose timestamp falls in a step's window (`foothold.yaml`); **no IP check** | every unmatched flow in the window, from any host, gets the step label |
| incomplete TCP outside every window | default `broken flow - benign` | a default, not a benign check |
| UDP | port/role rules; anything unmatched becomes `data exfiltration` | a catch-all, not a detection |

## 2. F1: what the labels do on the probe network (96 h, 377,704 flows)

**Roles and hosts:**
- 23 client roles: 4 internal employees, 3 remote employees, 3 external users, servers (cloud
  share, internal share, intranet, 2 mail, monitoring, webserver, VPN, DNS, 2 firewall
  addresses), 17 external addresses, and **one attacker** (`192.168.230.122`, role
  `attacker_0`).

**The attacker's own flows:**
- As client: 8,958 `service_scan`, and **218 benign-labelled** flows (NTP 143, DNS updates 44,
  browsing 14, broken flow 9, bootp 6, OpenVPN 2), i.e. 2.4%.
- As server: 15,778 `data exfiltration`.

**Attack-step labels, by sending host:**
- 146,292 of the 155,250 attack-step flows (94%) are sent from the VPN server's address. The
  attack enters through the VPN, so this is plausibly correct at flow level: it is the
  attacker's traffic as seen from the VPN.
- Only **3** step-labelled flows from other non-attacker hosts (a firewall address 2, the
  intranet server 1) look like time-window spill-over. The time-window rule therefore produced
  little visible mislabelling on this network.
- **The real limitation is attribution.** The labels are per flow, so the attack *entity* is
  ambiguous. Per-source windows would make the VPN server, not the attacker, the main attack
  entity.

**The attack timeline:**
- All 36 attack steps happen in **hours 75.0–76.0 of 96**.
- The calibration half (before hour 48) holds no attack step, only the catch-all
  "exfiltration" UDP flows (9,909), which run from the DNS resolver to the attacker throughout.
- Hourly flow counts range from 417 to **156,919** (the scan hour); the median is 2,282.

**Benign host diversity:**
Two different metrics from this one network:
- **By flows, over the whole capture:** 35 sources never carry a malicious label (the 5
  malicious-labelled sources, including the VPN server and the resolver, are excluded). They
  amount to **3.6 effective sources**, and the top 5 send 89% of the flows.
- **By windows, in the P1x calibration hold-out:** 7.0 effective hosts (Phase 8k F0).

**Consequences for any F1 confirmation:**
1. **In the calibration period, the attacker machine looks benign.**
   - Before hour 75 it sends only benign-labelled flows, so the P1x calibration (which removes
     hosts with malicious labels before the calibration end) keeps it.
   - Over the whole capture it *is* excluded from "verified benign", through its 8,958
     `service_scan` flows.
   - Its role, not its calibration-period labels, identifies it. Using the role column would be
     documented host-level ground truth, not relabelling. It would have to be registered before
     any confirmation file is opened.
2. **Attack entities would be dominated by relays** (the VPN server, the DNS resolver); the
   attacker is one host.
   - Per network there are 1–5 attack entities and one short attack burst. Entity recall per
     network would therefore be 0/1-like.
3. **Benign evidence on the probe network is small and server-dominated** (3.6 effective
   sources by flows; 7.0 effective hosts by hold-out windows). The unit's adequacy label would
   be noisy (POWER_ANALYSIS.md section 2).

**Verdict on F1:**
- It is usable as a *development or demonstration* source.
- **It is not eligible as confirmation evidence** for a calibration-reliability claim. It has
  1–2 independent units (8 networks from one generator), too few effective hosts per unit, and
  flow-level labels whose attack-entity attribution is ambiguous (relays) and which mark the
  attacker benign in the calibration period.

## 3. F2: why the UWF calibration period contains no benign traffic

**Release structure** (publisher listing, 2026-11-02):
- `parquet/` holds 7 weekly files of 3.7–36.6 MB.
- `csv/` holds label-named folders: `Benign/`, plus Credential_Access, Defense_Evasion,
  Exfiltration, Initial_Access, Persistence, Privilege_Escalation and Reconnaissance.
- `csv/Benign/` is **one 10.2 MB file for all 7 weeks**. For comparison,
  `csv/Reconnaissance/` is 0.6 MB.

**The probe week's whole parquet file** (allowed: the probe is spent; `scripts/phase8l/uwf_probe_audit.py`,
`reports/phase8l/uwf_probe_audit.json`):
- 49,436 flows labelled `True` and 1,008 `Duplicate`; **no benign flow**;
- 15 source addresses, the group attack hosts; 104 destinations;
- it spans one day (2024-03-03).

**Conclusion:**
- **The probe week is attack-only.** Whether the other 6 parquet weeks are also attack-only is
  unverified; checking would mean opening protected files.
- **The decisive argument is the benign partition itself:** one 10.2 MB CSV pooled over all 7
  weeks of an enterprise range, while the attack side is about 140 MB of compressed parquet.
  Benign traffic is published separately and heavily reduced, so no realistic benign mixture,
  and hence no meaningful verified-benign FPR, exists for any week.
- **Not pursued:** a pre-registered, hashed reader that streams `csv/Benign/` and keeps only
  rows before each week's calibration cut-off. It would be an amendment question, not an
  impossibility. It was not pursued because the reduction alone defeats calibration.
- **F2 is not eligible.**
- UWF-ZeekData22 was already excluded for label-timing errors (Phase 8j).
