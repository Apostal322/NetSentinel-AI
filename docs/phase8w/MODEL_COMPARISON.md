# Phase 8w model comparison: raw, signed and unsigned network-relative features

**Status.** Registered screening on development data (consumed networks), two paired seeds.
No arm passed, so the registered rule stopped the campaign at 24 fits. Nothing here is a
supported positive result; the per-network effects are two-seed observations.

Sources: `reports/phase8w/evaluation_screening.json` (registered; hash in `.sha256`),
`fit_ledger.json`, `posthoc_{entities,shortcut,scale}.json` (exploratory).

## 1. What was run

| item | value |
|---|---|
| arms | `R0` raw (null control), `S` signed z, `A` unsigned \|z\|; 12 columns each |
| folds | leave-one-network-out, 4 fits per arm and seed |
| seeds | 1060, 1061 |
| registered fits | **24 of 48 approved**; 219 s of fitting; peak resident memory 1.2 GiB (1.55 GiB for the process tree) |
| diagnostic fits | 3 small network classifiers (§ 7) |
| recipe | the frozen M2 member: LightGBM, 200 trees, 15 leaves, learning rate 0.05, subsample and colsample 0.8, network- and class-balanced weights, 50k cap per source domain |
| model hashes | one SHA-256 per fit in the ledger and in `data/derived/phase8w/manifests/` |

## 2. Null control (G0)

- The `R0` refit through the Phase 8w driver equals the saved Phase 8o member **exactly** in all
  8 fits (largest score difference 0.0; partial AUC identical in all nine domains).
- The pipeline effect is therefore zero. Every difference below is a representation or
  reference effect.

## 3. Registered result: unlabelled target reference (`Z1`, deployable)

Exact partial AUC at FPR ≤ 1 %, mean of two seeds; NF-CIC / NF-UNSW / NF-ToN / NF-BoT.

| arm | partial AUC | macro | hard networks | recall at retrospective 1 % FPR | ROC-AUC |
|---|---|---|---|---|---|
| `R0` raw | 0.388 / 0.008 / 0.006 / 0.580 | 0.245 | 0.007 | 0.435 / 0.020 / 0.015 / 0.580 | 0.71 / 0.92 / 0.83 / 0.94 |
| `S` signed | 0.296 / 0.049 / 0.001 / 0.313 | 0.164 | 0.025 | 0.341 / 0.085 / 0.001 / 0.314 | 0.69 / 0.47 / 0.38 / 0.44 |
| `A` unsigned | 0.269 / **0.532** / 0.000 / 0.088 | 0.222 | 0.266 | 0.416 / **0.657** / 0.000 / 0.089 | 0.88 / 0.97 / 0.55 / 0.27 |

**Paired differences against `R0` (seed 1060, seed 1061):**

| arm | Δ hard networks | Δ macro | ranking criteria | guardrails |
|---|---|---|---|---|
| `S` | +0.013, +0.023 | −0.102, −0.060 | fail (macro) | fail |
| `A` | +0.238, +0.280 | −0.047, +0.000 | **fail (macro)** | **fail** |

**Why `A` fails the guardrails:**

| guardrail | result |
|---|---|
| recall at 1 % FPR per network | NF-BoT −0.49 (limit −0.10) |
| as-calibrated FPR | NF-ToN +8.6 points (limit +1); NF-BoT +33 points (limit +6) |
| as-calibrated macro recall | −0.28 (limit −0.03) |
| each hard network not worse | NF-ToN −0.006 |
| entities missed as calibrated | 8 → 9 (within the limit) |

**Registered decision:** no arm selected; no replication; G1, G3 and G4 NOT SUPPORTED;
DEVELOPMENT NO-GO.

## 4. What the two seeds show per network (exploratory)

- **NF-UNSW: a large ranking gain, consistent with the direction hypothesis.** Partial AUC
  0.008 → 0.53 and recall at 1 % FPR 0.02 → 0.66, in both seeds. The signed arm, with the same
  reference, reaches 0.05. `A` − `S` on NF-UNSW is +0.45 and +0.52. Caveats: the arm was designed
  after a no-fit look at these evaluation labels; the network has 4 attacker hosts in one
  capture; the gain moves between 0.27 and 0.57 with the reference draw (CONTAMINATION_ROBUSTNESS
  § 3); and it does not reach the operating point (§ 6).
- **NF-BoT: collapse.** 0.58 → 0.09, ROC-AUC 0.27 (worse than chance). Its unlabelled history is
  62 % attack windows, so "far from the reference" means "benign" there.
- **NF-ToN: nothing.** Partial AUC 0.000 under every reference; ROC-AUC falls from 0.83 to 0.55.
- **NF-CIC: mixed by day**, net loss −0.12:

| day | `R0` | `S` | `A` |
|---|---|---|---|
| 02-14 | 0.902 | 0.854 | 0.434 |
| 02-16 | 0.394 | 0.903 | 0.908 |
| 02-20 | 0.056 | 0.016 | 0.270 |
| 02-21 | 0.976 | 0.000 | 0.000 |
| 02-22, 03-02 | 0.000 | 0.000 | 0.000 |

  Both relative arms lose 02-21 completely and gain 02-16. Phase 8h saw the same kind of
  day-level collapse.

## 5. Other reference scenarios (same boosters; not deployable unless stated)

Never compare rows across blocks as if they were one experiment: each block gives the target a
different amount of information.

| scenario | kind | `S` partial AUC (macro) | `A` partial AUC (macro) |
|---|---|---|---|
| `Z0` | zero-shot | 0.225 / 0.000 / 0.001 / 0.239 (0.116) | 0.137 / 0.003 / 0.002 / 0.852 (0.249) |
| `Z1` | unsupervised target-adaptive | 0.296 / 0.049 / 0.001 / 0.313 (0.164) | 0.269 / 0.532 / 0.000 / 0.088 (0.222) |
| `Z2` | simulated perfect review, 800 windows | 0.225 / 0.027 / 0.001 / 0.516 (0.192) | 0.336 / 0.359 / 0.000 / 0.323 (0.255) |
| `Z3` | oracle-assisted | 0.293 / 0.030 / 0.001 / 0.267 (0.147) | 0.269 / 0.415 / 0.000 / 0.197 (0.220) |
| `T` | oracle-assisted, label-benign (Phase 8h) | 0.242 / 0.028 / 0.003 / 0.199 (0.118) | 0.244 / 0.406 / 0.000 / 0.412 (0.266) |

`R0` for reference: 0.388 / 0.008 / 0.006 / 0.580 (0.245).

- **The NF-UNSW gain needs a target reference.** Zero-shot (`Z0`) gives 0.003.
- **An oracle reference does not rescue the candidate.** Under `Z3` the macro mean is 0.220,
  below `R0`; NF-BoT stays at 0.20 and NF-ToN at 0.000. The failure is therefore not only
  contamination.
- **`T` and `Z3` are not comparable as "cleaning".** `T` covers the hold-out period and uses
  evaluation labels for host cleaning (IDENTIFIABILITY § 1), so NF-BoT's 0.41 under `T` against
  0.20 under `Z3` mixes a different period with a different cleaning rule.
- **`Z0` is dominated by NF-CIC days** (11 of 12 source domains for NF-UNSW and NF-ToN).
- **Signed vs unsigned:** `A` − `S` macro is +0.06 (`Z1`), +0.07 (`Z3`) and +0.15 (`T`), carried
  almost entirely by NF-UNSW. NF-CIC changes sign between seeds, and NF-BoT's difference depends
  on the reference (negative under `Z1`, positive under `T`).
- **`S` reproduces Phase 8h's failure** under the audited labels, the exact metric, a null
  control and two seeds: macro −0.08 against `R0` under `Z1`, −0.13 under `T`.

## 6. Operations and entities

**As calibrated (CAL_T), mean of two seeds, `Z1`.** The reference is label-free, but the
threshold is **label-assisted**: it is the rank of the label-benign hold-out scores. False alerts
per hour count audited-benign windows only.

| arm | realised FPR | recall | false alerts per hour | median detection delay (min) |
|---|---|---|---|---|
| `R0` | 1.3 % / 3.7 % / 15.1 % / 12.8 % | 0.435 / 0.609 / 0.533 / 0.938 | 318 / 50 / 16 / 0.2 | 15.6 / 0.9 / 5.5 / 0.0 |
| `S` | 1.8 % / 2.3 % / 13.3 % / 28.1 % | 0.462 / 0.113 / 0.130 / 0.376 | 448 / 32 / 14 / 0.4 | 1.0 / 1.0 / 17.9 / 0.2 |
| `A` | 2.1 % / 0.0 % / 23.7 % / 46.0 % | 0.642 / 0.106 / 0.355 / 0.288 | 524 / 0.3 / 24 / 0.7 | 0.9 / 3.5 / 1.0 / 0.2 |

- **The NF-UNSW ranking gain does not reach the operating point.** As calibrated, `A` raises
  almost no alert on NF-UNSW (FPR 0.0 %, recall 0.11 against 0.61 for `R0`). Its hold-out has 623
  windows, 29 % from attacker hosts.
- No arm reaches 1 % realised FPR on NF-ToN or NF-BoT, as in Phases 8s–8v.
- NF-CIC false alerts rise from 318 to 524 per hour.

**Documented attacker entities (48 with ≥ 5 positive windows; `posthoc_entities.json`):**

| arm, `Z1` | missed as calibrated | R₂₀ as calibrated | missed at retrospective 1 % FPR | R₂₀ at retrospective 1 % FPR |
|---|---|---|---|---|
| `R0` | 8, 8 | 25, 28 | 14, 13 | 15, 16 |
| `S` | 10, 19 | 25, 20 | 30, 34 | 10, 6 |
| `A` | 9, 9 | 31, 31 | **32, 28** | 10, 16 |

- At the strict budget `A` loses 16–19 entities and gains 1. In seed 1060 the losses are 10 on
  NF-CIC 02-21, 4 on 02-20, 1 on 03-02 and 4 on NF-ToN.
- The registered entity guardrail uses the as-calibrated count and passes (8 → 9). The
  retrospective count is reported here because it is much worse.

**Label-free threshold and total alert volume (review checks; `posthoc_review.json`; seeds 1060, 1061):**

| arm | `cal_U` recall (threshold from every hold-out window) | all alerts per hour at CAL_T, including windows outside the audited population |
|---|---|---|
| `R0` | 0.36, 0.51 / 0.06, 0.06 / 0.00, 0.00 / 0.93, 0.93 | 335, 395 / 379, 283 / 72, 77 / 4, 4 |
| `A` | 0.64, 0.64 / 0.06, 0.04 / 0.36, 0.36 / 0.27, 0.30 | 555, 603 / 59, 39 / 92, 91 / 2, 2 |

- Without labels for the threshold, neither arm detects NF-UNSW (recall 0.04–0.06).
- 73 % of NF-ToN's evaluation windows are outside the audited population; alerts on them are not
  in the false-alert figures above. Total alert rates there are 72–92 per hour.

## 6a. How much single hosts decide the metric (review finding B1; exploratory)

Exact partial AUC with and without the one benign host that holds most of the top benign scores:

| network | arm | all benign hosts (1060, 1061) | without that host | the host |
|---|---|---|---|---|
| NF-BoT | `R0` | 0.671, 0.489 | 0.944, 0.946 | `192.168.100.46`: every window of the benign tail (8 benign hosts, 620 windows, budget 6) |
| NF-BoT | `A` | 0.128, 0.048 | 0.252, 0.288 | a different single host |
| NF-ToN | `R0` | 0.008, 0.003 | 0.085, 0.018 | `0.0.0.0`: 73 % of the benign tail |
| NF-ToN | `A` | 0.000, 0.000 | 0.038, 0.004 | `0.0.0.0`: 99 % of the benign tail |

- **On NF-BoT and NF-ToN the primary metric is decided by one benign host each.** A macro mean
  gives each network a quarter of the weight, so macro differences are largely single-host
  effects. `0.0.0.0` on NF-ToN is not a real host.
- The ordering of the arms does not change: without those hosts `A` is still far below `R0` on
  NF-BoT and below it on NF-ToN.
- **The "1 % budget" is often not reached.** Tie blocks make the realised false alerts at the
  retrospective threshold much lower than the budget in several cells: NF-BoT 0–2 of a budget of
  6 in every arm; NF-ToN `A` 6 of 74; NF-UNSW `A` 87 of 119 (seed 1060).

## 7. Domain shortcut (exploratory; `posthoc_shortcut.json`)

Benign evaluation windows, up to 2,000 per domain, `Z1` references; a small LightGBM names the
network (majority share 72 %).

| representation | network classifier accuracy | mean pairwise KS between networks |
|---|---|---|
| raw | 97.7 % | 0.52 |
| signed z | 100.0 % | 0.49 |
| unsigned \|z\| | 99.96 % | 0.51 |

- **Per-network normalisation does not make networks look alike.** Each network keeps a
  fingerprint in its floored scales and discrete values, and the relative representations are
  at least as identifiable as the raw one.
- Lower identifiability was not the goal, and none was achieved.

## 8. Mechanism (exploratory; `posthoc_scale.json`)

Median |z| over the four volume features on evaluation windows:

| domain | reference | scale of `log_flows` | attack | benign | benign windows clipped at 10 on any feature |
|---|---|---|---|---|---|
| NF-CIC 02-14 | `Z1` | 0.60 | 3.84 | 0.67 | 1 % |
| NF-UNSW | `Z1` | 0.48 | 3.52 | 0.58 | 12 % |
| NF-ToN | `Z1` | 2.00 | 1.35 | 0.43 | 46 % |
| NF-ToN | `T` | 0.25 (floored) | 10.0 | 2.77 | 64 % |
| NF-BoT | `Z1` | 0.34 | 7.76 | 6.02 | 97 % |
| NF-BoT | `Z3` | 0.25 (floored) | 0.96 | 0.91 | 9 % |

- **A deviation is not a common unit across networks.** Its size depends on how spread out the
  reference population is. NF-CIC and NF-UNSW have unimodal benign traffic and attacks sit 3–4
  scale units out. NF-ToN's history is bimodal, its scale is four times wider, and its attacks
  sit 1.35 units out, inside what the model learned as benign.
- **Floors and clipping carry much of the signal.** With a tight reference (floored scale 0.25)
  most windows hit the ±10 clip, attack or not.
- **Feature use barely changes:** `new_dst_frac`, `log_pkts` and `log_flows` lead in all three
  arms (gain shares 0.31 / 0.22 / 0.12 raw; 0.22 / 0.15 / 0.16 unsigned).

## 9. Limits

- Two seeds, four networks from two institutions, 48 entities; NF-UNSW's effect rests on 4
  attacker hosts. No interval is reported.
- **Two seeds fix the sign per network, not the macro effect.** The five saved members' macro
  partial AUC has SD 0.0145; NF-CIC days are all-or-nothing between seeds (02-16 under `R0`:
  0.035 and 0.754).
- **The reference draw is a second source of noise, larger than the seed** on NF-UNSW.
- The registered entity guardrail (as calibrated) did not see the loss at the strict budget; a
  future registration should add one there, a relative false-alert limit and a per-day FPR limit
  (NF-CIC 02-21: 1.2–1.7 % → 4.0 % realised FPR under `A`).
- The candidate was chosen after a no-fit view of these networks' evaluation labels.
- Source references are label-benign; the deployable target reference is unlabelled.
- The five-member ensemble comparison needs five seeds and was not run.
