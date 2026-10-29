# Alert burden on CTU-13 scenario 9 (Phase 8g, post-hoc) [R]

**Scope.**
- Frozen scenario 9 result: 2.69 test hours, device level, `vetted_benign`.
- The published figure is **2,563 alerts/h on unverified background windows**.
- Labels used here: "unverified" means background traffic **without** ground truth. It is a
  triage **burden**, not a false-positive rate.
- Diagnosis on consumed data. Nothing was tuned.

**Script and output.** `scripts/phase8g_post/sc9_diagnostics.py` →
`reports/phase8g_post/sc9_diagnostics.json`. The script first recomputes the published V3
numbers exactly.

## 1. Evidence categories

| category | definition | device windows | sources | alerts | alerts/h | alert rate | on pooled fallback (alerts) |
|---|---|---|---|---|---|---|---|
| confirmed attack | documented initiator, window after its documented infection | 2,708 | 10 | 565 | 210 | 20.9% | 100% |
| verified benign | the 6 documented normal hosts | 803 | 6 | **0** | 0 | 0% | — |
| initiator before infection | initiator window before its documented infection (in the test period) | 15 | 7 | 0 | 0 | 0% | — |
| background, internal | other 147.32.0.0/16 sources | 30,491 | 893 | 181 | 67 | 0.59% | 79% |
| background, external | other IPv4 sources | 499,031 | 217,959 | 6,603 | **2,458** | 1.32% | 98% |
| unclassifiable | key is not an IPv4 address (mostly IPv6) | 1,157 | 40 | 103 | 38 | 8.9% | 100% |
| label-only normal host | 147.32.1.20 (From-Normal in the labels, not in the README design) | 0 | 0 | 0 | — | — | — |

- **Unverified total:** 6,887 alerts, i.e. 2,563/h, from 4,530 sources.
- **Most of it is what a 1% target produces at this scale.**
  - 530,694 unverified windows × 1% / 2.69 h ≈ **1,975 alerts/h**, even if every background
    window were benign.
  - The observed unverified alert rate is 1.30%, i.e. 1.3× target.
  - The burden is driven by **the number of scored entity-windows**: 218k external sources,
    most seen in a few windows. The detector's precision is not established either way.

## 2. Structure of the unverified alerts

| measure | value |
|---|---|
| sources | 4,530; **3,670 (81%) alert once** |
| concentration | top 10 sources 7.1% of alerts; top 100 sources 18.6% |
| top source | 186.198.158.69: 121 alerts (also flagged by the per-entity update rule, V4 analysis §5) |
| incidents (per source; new incident after a > 300 s gap) | 5,655 (2,105/h); median **1 window** per incident |
| deduplication | incident grouping removes 18% of alerts only, because most are isolated single windows; confirmed-attack alerts group 10× better (565 → 55 incidents, median 5 windows) |
| temporal clustering | per minute: mean 42.5, p50 38, p99 133, max 176; Fano factor **9.0** (bursty, not Poisson) |
| score / threshold | median 1.10 (unverified) and 1.09 (attack): most alerts sit just above the threshold |
| model scope | 97.7% of external and 79% of internal background alerts are scored by the **pooled fallback** (no own profile) |
| dominant explanation | unverified: `typical_connection_duration_above_local_baseline` (92% of external alerts). Confirmed attack: `download_volume_above_local_baseline` (96%) |
| flows inside alerted unverified windows | 12,504 flows to 503 destinations. **88% go to internal (147.32.) destinations**: inbound traffic to the university network. Top ports 80/tcp (41%), 12114/udp, 13363/tcp, 443/tcp, 53/udp. 5 flows (3 sources) go to an initiator. |

**Calibration validity.**
- The device threshold was set by transient sources (`tail_fallback_share` 0.97).
- Profile status is `baseline_provisional`.
- Every test segment was `drift_suspected`, so `normality_supported_share` = 0. The product
  never presented a quiet window as normal.

**Telemetry health.**
- The frozen stream reported `ok` but silently dropped 1,039 long-connection records
  ([REAL_DATA_STREAMING_AUDIT.md](REAL_DATA_STREAMING_AUDIT.md)).
- With the exact reference (no records lost), the unverified burden is **2,755/h (+7.5%)**.
  591 device windows made up only of dropped records (mostly long connections) are restored,
  and 547 of them alert.
- Detection is unchanged: 10/10 initiators, recall 0.211. Labelled [R].

## 3. Is it practical?

**No**, as a raw alert stream:
- 2,563 alerts/h is about 43 per minute.
- With incident grouping it is still 2,105/h.
- No human triage at this rate is plausible.

**What would reduce it without discarding evidence.** These are hypotheses for Phase 8h.
None was tested here, and each needs a pre-registered evaluation.
1. **Do not alert on pooled-fallback entities individually.** Aggregate them per destination
   service or per /24. 98% of the external burden comes from sources without an own profile.
2. **Rank, don't threshold.** Most alerts are within 10% of the threshold. A review queue
   ordered by persistence (entities alerting in many windows, like the per-entity update
   rule) would put the 10 bots near the top: they alert in 25% of their windows, while 81% of
   background sources alert once.
3. **Explanation-aware triage.** The dominant explanation differs between attack (download
   volume) and background (connection duration) alerts. That is one scenario and one botnet
   family. It is an observation, not a rule.
4. **Store everything.** Deduplication or ranking should change what an operator sees first,
   not what is kept. Every alert stays in the event store with its explanation and its
   telemetry health.

## 4. Missing evidence

- **No ground truth for background traffic.** CTU-13 "Background" is unlabelled. The 2,563/h
  are neither false nor true alerts.
- **One scenario, one network, one botnet family.** Scenario 10 shares the network and the
  infected hosts.
- The [R] scenario 10 exploratory evaluation (3,700 s lateness) gives 1,475 unverified
  alerts/h. That is not an independent replication.
- **No operator study.** The cost of triaging an alert is unknown.

| finding | status |
|---|---|
| 0 false alerts on verified-benign hosts (803 windows) | **confirmed** (pre-registered V3; Wilson upper bound 0.48%) |
| unverified burden 2,563/h | **confirmed** as a burden figure [R]. Its false-positive share is **not evaluated** (no labels). |
| burden is mostly explained by scale × target FPR | **confirmed** [R] (1,975/h expected at 1%) |
| incident grouping makes it practical | **refuted** [R] (−18% only) |
| pooled-fallback sources dominate the burden | **confirmed** [R] (98% of external alerts) |
