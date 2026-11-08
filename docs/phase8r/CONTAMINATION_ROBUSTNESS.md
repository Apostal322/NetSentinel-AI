# Phase 8r Experiment B: bounded contamination of the trusted set

**Status:** REGISTERED (PREREGISTRATION § 5).
- Sources: `reports/phase8r/experiment_b.json`.
- Base cell: the modest / `random` trusted set of Experiment A, with the same seeds.
- Real calibration-attacker hold-out windows are marked trusted until they form a share c of the
  trusted windows.

**Evaluable domains:** NF-BoT, NF-CIC 02-14, 02-20, 02-22, 03-02, NF-UNSW and NF-ToN. 02-16 and
02-21 have no calibration attackers: NOT EVALUABLE.

**Decision H-B1** (A3's macro recall loss ≤ 0.10 at c = 5 % under every mechanism):
**NOT SUPPORTED.** Five of six mechanisms exceed the limit; only `service_matched` stays within
it.

## Paired macro recall change (contaminated − clean)

| method | mechanism | 1 % | 2 % | 5 % | 10 % | breakdown |
|---|---|---|---|---|---|---|
| A2 | random | −0.094 | −0.118 | −0.195 | −0.211 | 2 % |
| A2 | persistent | −0.086 | −0.110 | −0.170 | −0.183 | 2 % |
| A2 | coordinated | −0.084 | −0.115 | −0.186 | −0.194 | 2 % |
| A2 | burst | −0.093 | −0.128 | −0.194 | −0.211 | 2 % |
| A2 | gradual | −0.080 | −0.127 | −0.176 | −0.194 | 2 % |
| A2 | service_matched | −0.070 | −0.091 | −0.164 | −0.195 | 5 % |
| **A3** | random | −0.008 | −0.033 | **−0.125** | −0.155 | 5 % |
| **A3** | persistent | −0.019 | −0.038 | **−0.119** | −0.137 | 5 % |
| **A3** | coordinated | 0.000 | −0.031 | **−0.117** | −0.141 | 5 % |
| **A3** | burst | −0.011 | −0.024 | **−0.115** | −0.154 | 5 % |
| **A3** | gradual | +0.003 | −0.040 | **−0.102** | −0.135 | 5 % |
| **A3** | service_matched | +0.005 | −0.009 | −0.093 | −0.136 | 10 % |
| A4 | random | −0.087 | −0.106 | −0.175 | −0.175 | 2 % |

## Reading

**What contamination does:**
- It raises the threshold, so FPR falls and recall falls.
- On NF-ToN, contamination at 5 % lowers FPR by 38–49 percentage points. The clean trusted
  threshold was far too low (Experiment A), and a few attack windows move it back towards the
  benign tail. "Robustness" and "calibration" pull against each other there.

**Why A2 and A4 break at 1–2 %:**
- Below 99 trusted windows the conformal rank is the sample maximum. A single attack window
  then sets the threshold.
- A3 is more robust because the screened unvetted windows dilute the trusted set.

**Mechanism matters little:**
- The estimators are time-agnostic, so `burst` and `gradual` differ from `random` only through
  which windows they draw.
- `service_matched` restricts the pool to attack windows that look like the trusted traffic.
  It breaks later (10 %); that its windows score lower is plausible, but it was not measured.

**Comparison with Phase 8q G:** the trusted set inherits the same bounded breakdown as the
label-free estimators (2–5 %). It is far below the real calibration contamination of NF-UNSW,
NF-ToN and NF-BoT (29–92 %). Vetting has to keep the trusted set nearly pure.

## The verdict hinges on NF-ToN (review finding B2)

**On NF-ToN, "5 %" is about 9 %.**
- The injected count is rounded: m = round(c·n/(1 − c)).
- With about 10 trusted windows, "5 %" means one injected window, a realized share of about
  9.1 %.
- At 1 % NF-ToN drops out entirely, so the 1 % macro covers three networks and 2–10 % cover four.
- Realized shares were not recorded by the registered code. This figure is the reviewer's
  recomputation.

**A3 at c = 5 %, paired recall change per network:**

| mechanism | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | macro without NF-ToN |
|---|---|---|---|---|---|
| random | −0.002 | −0.173 | −0.323 | −0.002 | −0.059 |
| persistent | −0.002 | −0.234 | −0.239 | 0.000 | −0.078 |
| coordinated | −0.002 | −0.203 | −0.265 | 0.000 | −0.068 |
| burst | −0.002 | −0.139 | −0.320 | −0.001 | −0.047 |
| gradual | −0.002 | −0.138 | −0.266 | −0.001 | −0.047 |
| service_matched | −0.002 | −0.061 | −0.305 | −0.004 | −0.022 |

**Without NF-ToN, every mechanism would pass H-B1.** The registered verdict stays NOT SUPPORTED.
- It rests on NF-ToN, where the trusted set is about 10 windows and one attack window is about
  9 % of it.
- NF-UNSW alone loses 0.06–0.23 at 5 %.

**In B, hosts with injected windows count as vetted.** Their remaining windows therefore leave
A3's retained pool, which partly offsets the contamination. This was registered, but its size was
not separated.

**The A4 comparison is not fully paired:** its bootstrap seed differs between the clean and
contaminated runs.

## Limits (stated, not hidden)

**At 1 % and 2 % many cells inject zero windows and are skipped** (414 and 293 of 840
domain-fit-draw cells per mechanism).
- 1 % of 11 trusted windows rounds to 0.
- So the 1–2 % columns mostly reflect domains with larger trusted sets (NF-BoT, NF-UNSW).
- The comparison is paired on the same cells, but the networks entering the macro differ by
  column.

**At 5 %, 6 cells per mechanism are skipped** (45 for `service_matched`).

**The clean macro here (A3 0.650) is over the evaluable domains only.** It is not Experiment A's
0.709.
