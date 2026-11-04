# Phase 8p Stage 1: missed attacks, label semantics and observability

**Status:** EXPLORATORY.
- Label-using diagnostics on the four consumed development networks.
- No candidate is selected or evaluated here.
- Written 2026-11-03, before Experiment E was registered.

**Sources:**
- `reports/phase8p/missed_inventory.json` (scripts/phase8p/missed_inventory.py): the Phase 8o
  F0 K = 5 entity outcomes (6 fits) joined with each attacker's evaluation flows;
- `reports/phase8p/observability.json` (scripts/phase8p/observability.py): the label audit and
  the observability diagnostics.

## 1. Label semantics

| dataset | what a label is | what the evaluation uses |
|---|---|---|
| NF-CIC-IDS2018-v3, NF-UNSW-NB15-v3, NF-ToN-IoT-v3, NF-BoT-IoT-v3 | a **flow** label (`label`: benign or an attack class; `attack`; `family`) | window positive if any flow of the (source, 30 s) window is labelled attack (Phase 8b); entity = a source with ≥ 5 attack windows in a target domain (75); NF-CIC `infiltration` windows excluded as noisy |

**A malicious host is not malicious in every flow.** The share of an entity's evaluation flows
labelled attack ranges from 0.6 % to 100 %. Some examples:
- NF-ToN 192.168.1.37: 7 %;
- several NF-CIC 02-22 internet hosts: 0.6–2 %.

**The official NF-CIC ground truth** is the CSE-CIC-IDS2018 table
(https://www.unb.ca/cic/datasets/ids-2018.html, read 2026-11-03). It gives attacker and victim
addresses and **local-time intervals**.
- Local time is UTC−4 (Atlantic). The data fixes this: the 02-20 LOIC-HTTP flows start at
  14:13 UTC against a documented 10:12 start.
- The rows used:
  - 02-14: SSH brute force from 13.58.98.64;
  - 02-16: Hulk from 18.219.193.20;
  - 02-20 / 02-21: LOIC-HTTP, LOIC-UDP and HOIC from the same ten 18.x/52.x hosts;
  - 02-22: web brute force, XSS and SQL injection from **18.218.115.60 only**, against
    172.31.69.28;
  - 03-02: ten infected 172.31.69.x bots.

**The other networks:**
- **ToN-IoT** documents its attackers as the .30–.39 range.
- **UNSW-NB15** attackers are 175.45.176.0–3.
- **BoT-IoT** publishes no addresses on its project page. Roles there are read from the data:
  four hosts (192.168.100.147–150) send 3.7–3.8 M attack flows each to the attacked hosts.

## 2. Role audit of the 75 evaluation entities

| role (rule) | entities | detected at ≥ 20 % in all 6 fits | never at ≥ 20 % | never alerted |
|---|---|---|---|---|
| documented attacker (official table, documented range, or the NF-BoT heavy senders) | 48 | 37 | 11 | 1 |
| attacked host's traffic (its attack-labelled flows go to a documented attacker: NF-BoT .3/.5/.6/.7, NF-ToN .193) | 5 | 2 | 0 | 0 |
| **undocumented source** (an attack label on a host the documentation does not name; all on NF-CIC 02-22) | 22 | 1 | 19 | 19 |

**Of the 20 entities that Phase 8o found are never alerted, 19 are undocumented sources.**

**What their attack-labelled flows look like:**
- internet hosts sending one flow per window to random high ports on 172.31.69.28 (80 bytes up,
  40 down), where the labelled flows are 0.6–2 % of the host's traffic;
- three AWS hosts with UDP port-500 flows (3,168 bytes up, no reply, 89 s; IKE-like);
- **the victim itself**, whose DHCP flows (port 67) to its gateway are labelled `web_xss`;
- three SSH clients on port 22.

**Only 21 % of their attack windows fall inside a documented attack interval.** Whatever these
labels mark, it is not the documented web attack.

**The documented 02-22 attacker is detected:** median recall 0.89; 98 % of its evaluation attack
windows fall inside the documented XSS/SQL-injection intervals.

**This matches published audits** that report labelling errors in CSE-CIC-IDS2018. They are
cited as context, not as evidence for these specific flows.

## 3. The missed or unstable groups, with evidence

The diagnostics compare the group's attack windows with verified-benign windows of the same
domain's evaluation period:
- **per feature:** AUC, and the share of benign windows at or beyond the attack median;
- **an optimistic in-domain ceiling:** LightGBM with time-blocked folds. Host identity can leak
  across folds, so this is an upper bound on separability within the network, not evidence of
  transferable attack signal.

On these data **every** group is separable in-domain (AUC 0.95–1.00 on both sides), including
the mislabelled sources. So the ceiling cannot tell attack evidence from "a different
population". The classification below therefore rests on the label audit, the documented
intervals and the univariate evidence.

| group | role / label reading | source-side evidence | victim-side evidence | primary cause (Part 12 taxonomy) |
|---|---|---|---|---|
| NF-CIC 02-22, 22 undocumented sources | label artifacts: none is named by any documented attack; only 21 % of their windows fall inside any documented interval of the day; flows unlike a web attack | `new_dst_frac` AUC 0.99 (external hosts first seen after the freeze) | separable in-domain | **6. weak or ambiguous labels.** These are not missed attacks in any established sense |
| NF-CIC 02-20 "LOIC-HTTP", 10 documented attackers, never ≥ 20 % | **the onset of the documented DDoS-LOIC-UDP attack (13:13–13:32), carrying the LOIC-HTTP class label.** 99.3 % of the day's LOIC-HTTP-labelled flows (286,436, the 10:12–11:17 HTTP flood) are in the calibration half and purged by P1x. The 2,153 evaluation flows run 13:14–13:29 local, 100 % inside the LOIC-UDP interval: 1,363 TCP SYN-only flows to port 80 (40 bytes up, 0 down, no reply) and 790 UDP flows, all to 172.31.69.25, about 10 per source window. The family label does not match the documented attack (a likely label/family mismatch) | **strong in-domain:** `upload_share` AUC 1.00 and `log_pkts` 0.98, with no benign window at or beyond the attack median | **strong:** the victim's inbound packets and bytes exceed every benign victim window (`v_log_pkts`, `v_log_up` AUC 1.00, benign share beyond the median 0.000) | **5./8. training shift and insufficient training support.** The evidence is present on both sides in-domain; the cross-network M2 does not score it high (margin −0.82). Label status: documented attacker, inside a documented interval, under the wrong family label |
| NF-ToN 192.168.1.37 (documented attacker; 7 % of its flows attack) | SMB/445 ransomware and backdoor, about 2 flows per window, mixed with its normal traffic | weak (best single AUC 0.71, `log_up_bytes`) | weak (best single AUC 0.71, `v_hist_dev` / `v_rst_frac`) | **normal-looking service behaviour on a mixed host**: weakly observable |
| NF-BoT .3/.5/.6/.7 | attacked hosts' traffic (responses to the attackers) labelled attack | `new_dst_frac` 0.98 | separable | **6. label semantics** (target-side traffic); two of the five are detected anyway |
| NF-ToN 192.168.1.193 | infected host's backdoor traffic to an attacker | strong (`log_pkts`, `med_log_dur` AUC 0.98) | strong | detected in 4 of 6 fits at ≥ 20 %: **refit instability**, not observability |
| reference: SSH (02-14), Hulk (02-16), 02-22 documented attacker | documented, inside the intervals (98–100 %) | strong | strong | detected by M2 |

**Observability class, per the diagnostic convention fixed in `observability.py`:**
- every group is "observable" in-domain;
- for the reason given above, that is read only as "separable within its own network";
- the decision-relevant reading:
  - **02-20 LOIC (UDP onset):** separable in-domain on both sides;
  - **NF-ToN .37:** weakly observable;
  - **the undocumented sources:** not established as attacks at all.

**Correction after the independent review (2026-11-03).** A first version of this file called the
02-20 evaluation positives "post-attack residue" outside the documented interval. The official
table has a second 02-20 row that the interval list had missed: DDoS-LOIC-UDP, 13:13–13:32.
The intervals of 02-14 and 02-16 had also been pooled across attackers. Both errors are fixed in
`observability.py`: intervals are now per attack and per host. Roles, and so the Experiment E
entity sets, are unchanged; they are IP-based.

## 4. What this changes for Phase 8p

1. **The headline "missed web attacks" were mostly label artifacts.** The documented web
   attacker is detected. No test of "web exploits observable in flow metadata" is possible on
   02-22 beyond one attacker, and none is claimed.
2. **The remaining documented misses are separable *in-domain*; whether that evidence transfers is the open question.**
   - The 02-20 LOIC windows are separable from benign traffic on both sides *within* NF-CIC. The ceiling can leak host identity, so this is separability, not established transferable evidence.
   - Experiment E later showed that the victim-only model does **not** transfer (MODEL_COMPARISON § 3).
   - Whether victim-side context helps the **cross-network** model is the open, testable
     question (H1).
   - Its victim-side view is extreme (every benign victim window lies below it), which a fan-in
     feature can express in a network-independent form. Its source-side view (`upload_share` 1)
     is also extreme in-domain, but evidently not learned as attack from the other networks.
   - *Correction during Stage 1:* a first version of this file called the source side weak. That
     came from tie-breaking in the univariate AUC, since fixed to average ranks.
3. **Entity metrics need the role audit.** Experiment E reports the documented-attacker set
   (48) as primary and all 75 as secondary. Excluding the undocumented sources from the primary
   set is a registered choice, made before any Experiment E result.
4. **The ceiling diagnostic is too permissive to establish observability on these data.**
   Absence of evidence is not claimed for any group.
