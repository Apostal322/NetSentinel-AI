# Phase 8o H2: ensemble size and inference cost

**Status:** REGISTERED DEVELOPMENT (PREREGISTRATION § 5).

**Fits:** F0, 6 fits (fresh r = 6–8, base and stress). A K-ensemble is the mean of members
0 … K − 1, fixed before results.

**Sources:** `reports/phase8o/experiment_d.json` (`H2`) and `reports/phase8o/inference_profile.json`.

## 1. Stability and detection by K

| K | macro recall | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | R₂₀ / U₂₀ | U₁ | U₅₀ | collapses |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 0.599 | 0.515 | 0.542 | 0.584 | 0.754 | 21 / 24 | 6 | 24 | 5 |
| 2 | 0.708 | 0.640 | 0.781 | 0.604 | 0.809 | 34 / 11 | 10 | 21 | 0 |
| 3 | 0.725 | 0.678 | 0.805 | 0.613 | 0.803 | 39 / 6 | 11 | 10 | 0 |
| **5** | **0.762** | 0.680 | 0.835 | 0.659 | 0.873 | 40 / 5 | 9 | 7 | 0 |

**False alerts vary with K, by network:**
- NF-CIC and NF-ToN: within ±9 % (NF-ToN at K = 3: 1,118 vs 1,225).
- NF-UNSW: K = 1 has 367 vs 436 at K = 5 (−16 %).
- NF-BoT: 74 vs 49 (+51 %).

**Exploratory: spread over all C(5, K) member subsets.**

| K | macro recall | U₂₀ | U₁ |
|---|---|---|---|
| 1 | 0.60–0.77 | 13–24 | 6–19 |
| 2 | 0.66–0.80 | 6–18 | — |
| 3 | 0.70–0.80 | 6–18 | — |

The registered prefix (member 0 alone) is the *worst* single member on macro recall. Single-member
quality varies widely.

## 2. Decision: K = 5 retained

- **Δ₂₀ = U₂₀(K=1) − U₂₀(K=5) = 19,** so this definition is informative.
- **Δ₁ = −3, which is not informative.** At the single-window level a single member has *more*
  entities alerted in every fit (R₁ 49 vs 46; N₁ 20 for both). This is consistent with its noisier
  scores putting at least one attack window over T0 by chance (interpretation). It is the weak
  evidence that the ≥ 20 % definition exists to discount.
- **K = 3** keeps the U₂₀ reduction (24 → 6 ≥ 75 % of 19), R₂₀ (39 vs 40) and collapses (0). It
  **fails the recall guardrail** on three networks: NF-UNSW −0.030, NF-ToN −0.046 and NF-BoT −0.070
  (limit −0.02).
- **K = 2** fails the U₂₀, R₂₀ and recall checks.
- **Decision: no nested prefix with K < 5 met the rule, so K = 5 stays.** The frozen M2 is
  unchanged.
- This does not show that 5 members are *necessary*: the K = 3 subsets range 0.70–0.80 in macro
  recall, which brackets K = 5's 0.762.

**M2's benefit over one model, on fresh randomness:**
- **Against the registered prefix** (member 0, which is the worst single member): macro recall
  +0.16, U₂₀ 24 → 5, collapses 5 → 0.
- **Against the average single member,** the fairer contrast (exploratory, post-review): macro
  recall 0.695 → 0.762 (+0.066), and U₂₀ from a mean of 18 (13–24) to 5.
- So the stability benefit is clear. The recall benefit is moderate.
- Here K = 1 is a member, not B0, whose seeds differ.

## 3. Measured inference cost

**Setup** (`scripts/phase8o/profile_inference.py`):
- a fresh child process per K;
- the M2 r0 members (seeds 1000–1004) trained on the NF-CIC target's sources;
- scoring 117,126 NF-CIC 2018-02-21 windows on the i5-6400.

| K | artifact (MB) | load (s) | batch, 2 threads (windows/s) | batch, 1 thread (windows/s) | single window median / p95 (ms) | peak working set (MiB) |
|---|---|---|---|---|---|---|
| 1 | 0.35 | 0.19 | 94,300 | 54,600 | 0.10 / 0.17 | 217 |
| 2 | 0.71 | 0.02 | 55,400 | 28,600 | 0.18 / 0.34 | 213 |
| 3 | 1.06 | 0.03 | 36,000 | 18,700 | 0.27 / 0.57 | 213 |
| 5 | 1.77 | 0.05 | 20,600 | 11,200 | 0.42 / 0.82 | 221 |

- **Scoring time grows linearly with K;** K = 5 is 4.6× K = 1 at 2 threads.
- **Memory is dominated by the interpreter and libraries,** not the models.
- **Cold start is about 7 s of imports** (NumPy, Polars, LightGBM) on this machine. Model loading
  takes under 0.2 s.
- **Feature building is not the bottleneck:** `aggregate` processes about 2.9 M flows/s on one
  NF-CIC slice (250k evaluation flows → 34k windows in 0.09 s). The frozen destination memory of
  that slice holds 4,177 destinations (≈ 0.36 MB).

**Operational reading.** At K = 5 the detector scores about 20,000 device windows per second. A
network with 1,000 active devices produces 33 windows/s at 30 s windows. So **scoring** cost is not
a constraint for this hardware class, which also makes the efficiency motive for a smaller K
marginal.

**Limits of the measurement:**
- one machine and one evaluation day;
- the NF-CIC-target models only;
- batch scoring of precomputed matrices only;
- feature throughput covers `prepare_flows` + `aggregate` on one slice. It excludes the novelty
  memory, the live streaming windower and I/O, none of which is profiled.

The K = 1 load time includes first-file-access cost.
