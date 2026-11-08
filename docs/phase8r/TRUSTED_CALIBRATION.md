# Phase 8r Experiment A: trusted-negative calibration (threshold only)

**Status:** REGISTERED (PREREGISTRATION § 4), registration `fd7affa`, results `a8a6980`.
- Saved scores only (Phase 8o F0: 6 fits, K = 5).
- **Vetting is ORACLE-SIMULATED** from the calibration labels.
- Sources: `scripts/phase8r/experiment_ab.py`, `reports/phase8r/experiment_a.json`.

**Decision H-A1** (A3, modest budget = 10 hosts, `random`, no annotation error):
**NOT SUPPORTED.**

| criterion | value | pass |
|---|---|---|
| (i) gain over A0 ≥ 0.10 | 0.709 − 0.372 = **+0.337** | yes |
| (ii) every network: mean FPR ≤ A1T FPR + 0.02 | NF-CIC 3.7 % vs 3.2 %; NF-ToN 68.9 % vs 18.0 %; NF-BoT 25.7 % vs 9.8 % | **no** |
| (iii) at least half of the oracle-threshold gap (0.285) | 0.337 | yes |
| (iv) every network: p90 FPR ≤ A1T FPR + 0.05 | NF-ToN 80.4 % vs 21.0 %; NF-BoT 35.7 % vs 12.8 % | **no** |

**What happened:** recall rose because the threshold fell far below the benign quantile. The
gain was bought with false alerts, which is what criteria (ii) and (iv) exist to reject.
- Criteria (i) and (iii) pass only because A3's macro (0.709) *exceeds* the oracle-threshold
  ceiling (0.656) by over-alerting. **It is not "gap recovery".**

**Disclosure (review finding B1).** `t0` caps the conformal rank at n, as in Phase 8j/8q. With
fewer than 99 trusted windows, "conformal T0" is therefore the sample maximum, which is
anti-conservative; a strict conformal threshold would be +∞ (no alerts).
- This applies to 100 % of NF-ToN primary draws (median 10 trusted windows) and about 78 % on
  NF-CIC 02-14 and 02-22.
- The registered code was run as written. Treating n < 99 as abstention would make A2–A4 behave
  like A5, which abstains in most small and modest cells (§ 3).

## 1. Main table (macro recall_doc; per network: recall / FPR; 20 draws × 6 fits)

| cell | macro [p10, p90] | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | R₂₀ |
|---|---|---|---|---|---|---|
| A0 unlabelled | 0.372 | 0.503 / 1.2 % | 0.054 / 1.8 % | 0.001 / 0.4 % | 0.930 / 9.6 % | 16.0 |
| A1 full oracle | 0.869 | 0.807 / 1.2 % | 0.835 / 3.6 % | 0.884 / 16.4 % | 0.950 / 8.0 % | 37.0 |
| A1T oracle threshold, unlabelled memory | 0.656 | 0.503 / 1.2 % | 0.549 / 3.6 % | 0.640 / 16.0 % | 0.933 / 7.8 % | 27.3 |
| **A3 modest / random (primary)** | **0.709** [0.681, 0.728] | 0.508 / 3.7 % | 0.438 / 3.6 % | 0.952 / **68.9 %** | 0.937 / **25.7 %** | 28.1 |
| A2 modest / random | 0.682 | 0.504 / 4.1 % | 0.361 / 3.3 % | 0.951 / 67.4 % | 0.911 / 27.3 % | 28.0 |
| A4 modest / random | 0.628 | 0.504 / 4.1 % | 0.226 / 2.8 % | 0.951 / 67.4 % | 0.831 / 25.2 % | 27.0 |
| A5 modest / random | 0.121 (abstains 94 %) | — | — | — | — | 2.1 |

## 2. Why random host vetting fails: representativeness

**The FPR target is window-weighted; vetting samples hosts.**
- NF-ToN:
  - 98 % of its 3,635 benign hold-out hosts have a single hold-out window, and their windows
    score near 0 (99th percentile 0.005, against a benign quantile of 0.44);
  - ten random hosts give about 11 trusted windows, all from near-silent hosts;
  - fewer than 99 trusted windows make the conformal rank the sample maximum, so the threshold
    lands far below the benign tail.
- NF-CIC: 56 % of benign hosts are single-window, and 10 random hosts give about 59 windows.
- A3's screening then removes the heavy benign hosts whose windows exceed the too-low reference,
  so it does not correct this.

**This is the failure of Stage 1's identifying assumption** (the vetted hosts are exchangeable
with the benign *windows*), not a failure of conformal calibration.

**Effort at the modest budget** (means per domain):

| network | hosts vetted | malicious found | trusted windows | trusted host-hours |
|---|---|---|---|---|
| NF-CIC | 10 | 0.06 | 59 | 12 |
| NF-UNSW | 10 | 2.0 | 212 | 8 |
| NF-ToN | 10 | 0.06 | 11 | 10 |
| NF-BoT | 10 | 5.4 | 477 | 52 |

## 3. Secondary results (descriptive; A3 unless stated)

**Budget curve, `random` policy:**

| budget | macro | NF-CIC FPR | NF-ToN FPR | NF-BoT FPR |
|---|---|---|---|---|
| small | 0.738 | 16.8 % | 81.0 % | 37.3 % |
| modest | 0.709 | 3.7 % | 68.9 % | 25.7 % |
| larger | 0.727 | 2.1 % | 48.0 % | 7.8 % (all 7 benign hosts vetted) |

**Policies at the modest budget:**

| policy | macro | NF-CIC FPR | NF-ToN recall / FPR | NF-BoT FPR |
|---|---|---|---|---|
| random | 0.709 | 3.7 % | 0.952 / 68.9 % | 25.7 % |
| diversity | 0.721 | 3.3 % | 0.958 / 68.9 % | 32.5 % |
| temporal_block | 0.688 | 2.8 % | 0.866 / 32.9 % | 15.1 % |
| service_diverse | 0.574 | 3.5 % | 0.610 / 18.8 % | 24.4 % |
| admin_persistent (vetted) | 0.741 | 11.9 % | 0.915 / 30.2 % | 7.8 % |

**`admin_persistent` at the larger budget (vetted): macro 0.658 against A1T's 0.656.**
- It reproduces the oracle threshold on NF-UNSW, NF-ToN and NF-BoT exactly.
- NF-CIC FPR is 3.3 % against 1.2 %.
- **This is EXPLORATORY** (it is not the registered cell). Persistent hosts carry the window mass
  that the FPR target weighs, but on NF-ToN 27 of those 30 hosts are attackers that vetting must
  catch. The modest budget's 10 most persistent NF-ToN hosts include 9 attackers.

**Other cells:**
- **Interval budget (one vetted hour, every active host):** macro 0.700. The best NF-CIC FPR
  among the trusted cells (1.4 %); NF-ToN 39.9 %.
  - **It is not a limited budget:** the hour holds about 3,000 hosts on NF-CIC and about 290 on
    NF-ToN, all of which must be reviewed.
- **Unvetted administrator trust (`naive_T2`):** stays at A0 (0.37–0.39). Trusting persistent
  hosts without review trusts the attackers. On NF-ToN the 10 most persistent hosts include
  9 attackers.
- **Annotation errors:**
  - with `random` selection: little effect, since there are few malicious hosts to mislabel;
  - with `admin_persistent` selection, macro falls 0.741 → 0.600 (e_fb = 0.10) → 0.513
    (e_fb = 0.25), as accepted attackers raise the threshold.
- **A4 (dependence-aware) is uniformly more conservative:** recall falls, mostly on NF-UNSW and
  NF-BoT, and the NF-ToN failure is unchanged.
- **A5:** abstains in 86–100 % of the small and modest cells. At the larger budget it abstains
  on NF-UNSW only (17 trusted host-hour blocks at most).

## 4. Operational evaluation on the Phase 8q audit categories

Alert rate per category, mean over domains, fits and draws:

| category | A1T NF-CIC | primary NF-CIC | A1T NF-ToN | primary NF-ToN | A1T NF-BoT | primary NF-BoT |
|---|---|---|---|---|---|---|
| documented attack | 0.592 | 0.595 | 0.640 | 0.952 | 0.933 | 0.937 |
| documented, family mismatch (02-20) | 0.064 | 0.080 | — | — | — | — |
| documented, outside interval (03-02) | 0.292 | 0.322 | — | — | — | — |
| attacked-host traffic | — | — | 0.224 | 0.967 | 0.184 | 0.278 |
| undocumented source (02-22) | 0.011 | 0.021 | — | — | — | — |
| attacker host, other window | 0.0002 | 0.0016 | 0.033 | 0.787 | 0.245 | 0.388 |
| benign uninvolved | 0.012 | 0.037 | 0.160 | **0.689** | 0.078 | **0.257** |
| benign, involved host | 0.318 | 0.358 | — | — | — | — |

**On NF-ToN, the primary cell alerts on most windows of every category.** Its "recall" carries no
discriminative information there.

## 5. Interpretation

- **Small, realistic, host-sampled trusted-benign sets did not replace the oracle threshold.**
  - They push the threshold below the benign tail wherever hold-out hosts are mostly sparse.
  - Their recall gains come with 3–6× the oracle FPR on NF-ToN and NF-BoT.
- **The window-weighted target needs vetting effort proportional to traffic volume.**
  - In these testbeds the high-volume hosts are largely attackers, so vetting them is exactly
    the expensive part.
- **NF-CIC needs no threshold correction** (A0 = A1T recall 0.503). Its loss is the memory
  (Experiment C).
- **None of this is independent evidence.** These are four consumed development networks.
