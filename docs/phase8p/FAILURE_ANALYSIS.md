# Phase 8p: failure taxonomy (Part 12)

**Evidence:**
- ATTACK_OBSERVABILITY.md (Stage 1, EXPLORATORY);
- MODEL_COMPARISON.md and CALIBRATION_STUDY.md (Experiment E, REGISTERED DEVELOPMENT).

Each failure gets its primary supported cause. No single cause explains them all.

| failure | evidence | primary cause | secondary |
|---|---|---|---|
| **NF-CIC 02-22: 19 "web attack" entities never alerted** | not in the official attacker table; 79 % of their windows outside the documented intervals; the labelled flows are 0.6–2 % of the hosts' traffic, or keepalive-like, or the victim's own DHCP | **6. weak or ambiguous labels** | — |
| NF-CIC 02-22 documented web attacker (18.218.115.60) | detected: median recall 0.89 | (no failure) | XSS/SQL injection over port 80 is visible here as volume and novelty, not as payload, which flows cannot see |
| **NF-CIC 02-20 "LOIC-HTTP", 10 documented attackers** | the evaluation holds the onset of the documented DDoS-LOIC-UDP attack (100 % inside 13:13–13:32) under the LOIC-HTTP label; the HTTP flood itself (99.3 % of its flows) is in calibration; separable in-domain on both sides; no arm detects it cross-network; the victim-side model ranks NF-CIC victims below benign | **5. training distribution shift** (the cross-network models do not score this SYN/UDP flood onset as attack) | 6. a family-label mismatch (UDP flood labelled HTTP); 10. aggregation is *not* the cause (the source side is separable in-domain) |
| NF-ToN 192.168.1.37 (documented; 7 % of its flows attack) | weak univariate evidence on both sides (best AUC 0.71); only S1 detects it, at 28 % FPR | **attacks with normal-looking service behaviour on a mixed host** (SMB/445) | 7. threshold: detection only with unacceptable alerts |
| NF-BoT .3/.5/.6/.7 | attack labels on attacked hosts' responses | **6. label semantics** (target-side traffic) | — |
| NF-ToN 192.168.1.193 | infected host's backdoor traffic; 4 of 6 fits | refit instability (Phase 8n) | — |
| **NF-CIC collapse when victim context is added (D2: 0.81 → 0.18)** | context features encode shared-infrastructure fan-in; attack windows are never extreme on it; the direction learned on NF-UNSW/ToN inverts on NF-CIC | **9. a dataset-specific association** of a new feature | refit fragility of single-attacker days (Phase 8n) |
| D3 fusion on NF-BoT (false alerts 5.8 ×) | benign hosts sharing destinations with attacked hosts inherit attack-level victim scores | **attribution through shared destinations** | — |
| D3 fusion on NF-UNSW (recall 0) | hold-out ties at the top victim score → T0 = 1.0 | **registered-design defect** (tie-unsafe empirical-CDF fusion) | 8. a tiny hold-out (443 windows) |
| **Calibration without labels (C1–C3)** | NF-UNSW/NF-ToN recall collapses; C3 restores NF-ToN only at 34 % FPR | **calibration contamination by persistent attackers** | too few independent hold-out hosts (NF-UNSW 21) |
| FPR above α (NF-ToN 16.5 %, NF-BoT 8 %) at C0 | Phase 8o: stale memory plus host turnover (NF-ToN); 2 hosts and 80 blocks (NF-BoT) | 7. threshold miscalibration under shift | — |

**Not observed as a primary cause anywhere:**
- **1. missing observable information.** Every documented miss is separable in-domain. The
  claim is about separability *within* a network (the ceiling can leak host identity), not about
  transferable attack evidence.
- **4. incorrect service context.** The service-only control is weak (macro 0.13), so there is no
  port-label shortcut, and service context did not help either.

**Not testable on these data:** web exploits that change only payload. The one documented
web attacker is detected through flow volume and novelty, and nothing here measures whether
payload-only attacks are visible.
