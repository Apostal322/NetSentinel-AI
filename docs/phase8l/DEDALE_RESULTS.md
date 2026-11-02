# Phase 8l DEDALE single-network longitudinal test: confirmatory results

**Date:** 2026-11-02. This was **one run** under the freeze.
- **Freeze:** `DEDALE_FREEZE.md`, committed in `ff4da57`; N7 verified before every step.
- **Authorized by the user:** "download the 28 Stage B members … run dedale_eval_build.py, then
  run dedale_analysis.py --final exactly once … Report the results whatever they are."
- **Source data:** DEDALE V2 (Lanvin & Majorczyk, Inria/DGA, CC BY 4.0,
  https://doi.org/10.57745/Y5JLDG, https://dedale.inria.fr/download.html), tap green_internal.
- **Scope: N = 1.** One emulated enterprise, one generator, one attack campaign. **This result
  does not revise the Phase 8l network-level NO-GO.**

## Steps and integrity

| step | result |
|---|---|
| Stage B download (28 members, 396,251,763 B) | 105.6 s; **28/28** match the publisher's CRC32 and sizes (N10 clear) |
| evaluation build (`dedale_eval_build.py`) | 119 s, peak 1,451 MiB |
| — parsing | 0 unparseable rows of 8.23 M; 0 flows outside their UTC day; 0 dropped at the period edges |
| — calibration windows | the P1x rerun reproduced the frozen Stage A windows **exactly** |
| — evaluation windows | 321,277 |
| — labels | 43 label 1 windows; label 2 on 22 flows (D15). **No labelled flow on an address outside the official script's list** (label-file sanity check: nothing to drop) |
| final analysis (`--final`) | 177.6 s, peak 923 MiB |
| — consistency checks | T0, eligible hosts and calibration-score hash all identical to N8 |
| — exclusions | no host was excluded only by evaluation-period DHCP |

## H1 (primary): **HOLDS**

| | verified-benign windows | hosts | FPR (seed-mean) | n_eff | host bootstrap 95 % | Clopper-Pearson at n_eff | less favourable bounds |
|---|---|---|---|---|---|---|---|
| D15–D28 | 272,806 | 26 | **0.55 %** | 42,311 | 0.50–0.60 % | 0.49–0.62 % | **[0.49 %, 0.62 %]** |

**Readings:**
- **The rule is met:** point FPR 0.55 % ≤ 2 %, and the upper bound 0.62 % ≤ 3 %. N9 was not
  triggered.
- **Per seed:** 0.35 %, 0.58 % and 0.73 %. The host-macro FPR is 0.55 %.
- **The threshold is conservative, not exact.** The realised rate is about half the nominal
  α = 1 %. The budget (2α) holds with a wide margin.

## H2 (secondary): both periods **HOLD**

| period | windows | FPR | bounds | outcome |
|---|---|---|---|---|
| attack, 6–13 Jan | 165,572 | 0.66 % | [0.59 %, 0.74 %] | HOLDS |
| post-attack, 14–19 Jan | 107,234 | 0.39 % | [0.32 %, 0.46 %] | HOLDS |

## H3 (descriptive): no daily overrun

- **Daily FPR** on the 10 working days ranges from 0.07 % (Mon 6 Jan) to 0.92 % (Tue 7 Jan).
- **Overrun tests:** no day comes near a 2α overrun. Every Holm-adjusted p is 1.0, with the
  design effect 3.41 from N8.
- **Trend:** the host-clustered logistic slope is −0.033 per day (SE 0.014, z = −2.37). The false
  alerts drift slightly *down* over the fortnight.
  - This pattern is not monotone: the highest days are 7–10 and 17 January.

## Secondary threshold and sensitivity analyses

| analysis | threshold(s) | FPR | bounds |
|---|---|---|---|
| M2 (PAC at `neff_m3`) | identical to T0 on all seeds | 0.55 % | [0.49 %, 0.62 %] |
| hold-out = last 30 % of active calibration hours (80,664 windows) | 0.724 / 0.702 / 0.677 | **1.07 %** | [0.98 %, 1.17 %] |
| clients 3–4 included (28 hosts) | 0.820 / 0.776 / 0.750 | 0.60 % | [0.54 %, 0.66 %] |
| label-sanity addresses dropped | no address flagged | (same as primary) | |
| secondary population (5 other sources, 1,685 windows), primary T0 | | 0.04 % | [0 %, 0.25 %] |

**Readings:**
- **The conclusion is robust:** every variant stays below 2 % with an upper bound below 3 %.
- **The active-hours hold-out matters.**
  - It puts all of the hold-out on working-hour windows. The thresholds then fall, and the
    realised rate (1.07 %) is close to the nominal 1 %.
  - The primary hold-out's calendar cut (1 January 19:07 onwards) mixes in quieter hours. That
    explains its conservatism.

## Detection (descriptive; no criterion)

**Overall:** 43 attack windows, window recall **7.0 %** (seed-mean). The Wilson interval,
ignoring dependence, is 2.4–18.6 %.

| attack step | windows | recall |
|---|---|---|
| command and control | 33 | 6.1 % |
| collection | 5 | 20 % |
| lateral movement | 3 | 0 % |
| exfiltration | 1 | 67 % (2 of 3 seeds) |
| initial access | 1 | 0 % |
| discovery | 1 | 0 % |

**Entities.** Both compromised clients have at least one alerted attack window on all three
seeds:

| entity | attack windows | first attack window → first alerted one | compromise → first alert on any of its windows |
|---|---|---|---|
| client 2 | 11 | 49.0 h | 4.1–22.5 h |
| client 1 | 32 | 44.5 h | 2.9 h |

- **The detection delays are long.** Neither client's first attack windows alert: client 2's
  infection and reverse shell on 6 January, and client 1's PrintNightmare compromise on
  8 January.
  - Client 2 is first detected on a daily C2 beacon two days later (8 January, 11:00).
  - Client 1 is first detected on the data collection from the DC (10 January, 11:40).
- **"First alert after compromise" is not informative.** The benign base rate is 0.51 false
  alerts per host-hour. On a clean host, the first false alert would be expected within about
  2 working hours. An alert a few hours after compromise is therefore what benign behaviour
  alone would produce.

**Alert burden:**
- **False alerts per day** (seed-mean, 26 hosts, working days): 20 to 251.
- **Benign base rate:** 0.51 false alerts per verified-benign host-hour.
- **Alerts on label-0 windows of the excluded hosts** (status unknown): 139.
- **Precision is very low.** About 3 alerted attack windows against roughly 1,500 false alerts
  over the fortnight, so about 0.2 %.
- **90 % of false alerts are on windows with `new_dst_frac` > 0.** The frozen destination memory
  makes every destination first contacted after calibration count as "new". This is the
  asymmetry the pre-registration stated in advance. It is the dominant false-alert mechanism
  here.

## Conclusions

1. **Temporal validity of the false-alert budget: confirmed, n = 1.**
   - **Result:** on an unseen emulated enterprise, a 1 % conformal threshold calibrated on two
     benign weeks kept the verified-benign FPR at 0.55 % (upper bound 0.62 %) over the
     following two weeks, attack period included.
   - **Robustness:** it holds per period, per seed, under M2, and in every sensitivity analysis.
   - **The out-of-domain scorer did not break the calibration guarantee.** This is the
     project's second fresh-environment confirmation of a calibration-budget claim, after P8-H2,
     and it is still one environment.
2. **Detection at that threshold is poor.**
   - Window recall is 7 %, precision about 0.2 %, and roughly 200 false alerts a day for 26
     clients.
   - The early stealthy steps (initial access, C2, lateral movement) are missed.
   - The fixed-α threshold controls the false-positive *rate*, not the alert *volume*. Most
     false alerts come from the novelty feature over a frozen memory.
   - **The scorer is not a useful APT detector on this network,** consistent with the earlier
     findings that supervised transfer across networks fails.
3. **Limits:**
   - **External validity:** one generator (AURA clones), one tap, no real holidays, one
     campaign, two entities.
   - **Weak independence:** the 26 hosts are clones, so Kish 26 is balanced volume, not
     diversity.
   - **Effective n:** `neff_m3` 42,311 rests on the AR(1) and ICC model, but the bootstrap
     agrees.
   - **The cross-network question stays NO-GO:** this is one unit against the ≥ 15–30 needed.

**Process notes:**
- **Runtimes:** the evaluation build (119 s) and the final run (178 s) each exceeded 2 minutes.
  They ran inside the authorized step; no runtime estimate had been stated for them.
- **No change to any frozen file** was made after `ff4da57`.
