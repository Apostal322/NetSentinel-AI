# Phase 8l DEDALE N8: calibration-side dependence check

**Date:** 2026-11-02.
- **Under the freeze:** `DEDALE_FREEZE.md`, committed in `ff4da57`; N7 verified before the run.
- **Command:** `dedale_analysis.py --n8`, under `run_capped.py`.
- **Resources:** 255.7 s of processing, peak 748 MiB.
- **What was scored:** calibration windows only. **No evaluation member has been downloaded**,
  so no evaluation window exists.
- **Report:** `reports/phase8l/dedale_n8.json`. Calibration scores are in
  `data/derived/phase8l/dedale/cal_scores.npy`, with their SHA-256 in the report.

## Outcome: **PASS**

| seed | hold-out windows | T0 (rank k = ⌈(n+1)·0.99⌉) | `neff_m3` | M2 threshold |
|---|---|---|---|---|
| 0 | 54,120 | 0.8314 | 16,063 | 0.8314 (= T0) |
| 1 | 54,120 | 0.7866 | **15,721** | 0.7866 (= T0) |
| 2 | 54,120 | 0.7591 | 15,863 | 0.7591 (= T0) |

**Readings:**
- **N8:** the smallest per-seed `neff_m3` is 15,721, which is ≥ 590. That is 27 times the
  claim-rule requirement.
- **Hosts:** the 26 eligible hosts all come from calibration attribution. The two compromised
  clients' MACs are excluded (`00:50:56:00:00:01`, `…:02`).
- **Design effect:** n ÷ `neff_m3` averages **3.41** over seeds. It is used, as registered, to
  deflate the daily overrun tests.
- **M2 equals T0 on every seed.** At this effective n, the PAC rank is not stricter than the
  plain conformal rank.

## What this means

- **Every pre-unblinding gate has passed** (N1–N8). The thresholds are now fixed.
- **The scores are out of domain.** The DEDALE T0s (0.76–0.83) sit well above the source models'
  own benign 99th percentile on the development data (0.47–0.49). The scorer finds this
  emulated enterprise unusual. That is expected for a scorer that never saw DEDALE, and it is
  what the test is about: whether the *calibrated* threshold holds.
- **The remaining step is the single confirmatory run.** It needs the Stage B download
  (396.3 MB, evaluation days D15–D28). Nothing about the evaluation period has been computed.
- **Process note.** The N8 run took 255.7 s, against my estimate of about 1 minute per seed for
  scoring. The bulk was LightGBM prediction on 316,903 windows × 3 models, plus loading.
- **The Phase 8l network-level NO-GO is unchanged.**
