# Phase 8v Stages 2–3: baseline reference, attack observability and exploratory learnability

**Status: EXPLORATORY.**
- Development labels are used descriptively (V2 documented attackers vs historical benign;
  Phase 8q audit).
- These results informed which candidates were registered. Registered results on the same four
  networks are development evidence only.

**Sources:**
- `scripts/phase8v/baseline_reference.py` → `reports/phase8v/baseline_reference.json`;
- `scripts/phase8v/learnability.py` → `reports/phase8v/learnability.json`.

**Diagnostic fits:** 48 small LightGBM fits (100 trees, ≤ 30k rows), 39 s in total, plus a 24 s
library warm-up. They are not registered fits.

## 1. Baseline reference (saved scores, exact partial AUC)

| reference | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | macro |
|---|---|---|---|---|---|
| frozen M2 ensemble, recall at retrospective 1 % FPR | 0.500 | 0.023 | 0.007 | 0.571 | **0.275** |
| frozen M2 ensemble, exact partial AUC (FPR ≤ 1 %) | 0.437 | 0.012 | 0.003 | 0.571 | 0.255 |
| member seed 1060, exact partial AUC | 0.330 | 0.006 | 0.008 | 0.671 | 0.254 |
| member seed 1061 | 0.446 | 0.010 | 0.003 | 0.489 | 0.237 |
| member seed 1062 | 0.481 | 0.010 | 0.006 | 0.505 | 0.251 |

- **The recall values reproduce Phase 8t exactly** (0.500 / 0.023 / 0.007 / 0.571; macro 0.275).
- The frozen models were not refitted. Phase 8u showed that a refit of the member recipe equals
  the saved member bit for bit.

## 2. The decisive observation: the same feature points in opposite directions

**Univariate ROC-AUC, attack vs benign evaluation windows** (0.5 = no information; above 0.5 =
higher in attack windows):

| feature | NF-CIC | NF-UNSW | NF-ToN | NF-BoT | reading |
|---|---|---|---|---|---|
| `log_flows` (original) | 0.86 | **0.13** | 0.95 | 0.97 | attackers send *more* flows on three networks and *fewer* on NF-UNSW |
| `log_pkts` (original) | 0.96 | **0.14** | 0.97 | 0.81 | same inversion |
| `log_up_bytes` (original) | 0.96 | 0.25 | 0.96 | 0.35 | conflict |
| `log_down_bytes` (original) | 0.81 | 0.15 | 0.97 | 0.13 | conflict |
| `med_log_dur` (original) | 0.65 | 0.79 | 0.61 | 0.33 | conflict |
| `mean_log_pkts` (new) | 0.84 | 0.17 | 0.93 | 0.09 | conflict |
| `active_sec_frac` (new) | 0.84 | 0.27 | 0.95 | 0.91 | conflict |
| `gap_cv` (new) | 0.65 | **0.07** | 0.90 | 0.99 | the strongest NF-UNSW separator, inverted |
| `tiny_flow_frac` (new) | 0.30 | 0.84 | 0.14 | 0.53 | conflict |

**17 of the 30 features conflict:** at least one network at ≥ 0.6 and another at ≤ 0.4. That
covers 8 of the 12 original features and 9 of the 18 new ones.

**Consistent direction on at least three networks, with none opposed:**

| feature | NF-CIC | NF-UNSW | NF-ToN | NF-BoT |
|---|---|---|---|---|
| `no_reply_frac` (original) | 0.45 | 0.78 | 0.63 | 0.69 |
| `peak_sec_share` (new, TIME) | 0.16 | 0.45 | 0.08 | 0.12 |
| `active_prev4` (new, TIME) | 0.71 | 0.53 | 0.82 | 0.74 |
| `cli_fin_frac` (new, BIDIR) | 0.80 | 0.71 | 0.67 | 0.51 |
| `retrans_frac` (audited out) | 0.50 | 0.67 | 0.86 | 0.60 |

None of them separates NF-UNSW strongly.

## 3. Within-network learnability (diagnostic fits; test half only)

**Chronological split** of the evaluation period: train on the first half, test on the second.
Each cell is exact partial AUC / recall at 1 % FPR:

| network | F0 (12 original) | + FLOW | + TIME | + BIDIR | + ALL |
|---|---|---|---|---|---|
| NF-UNSW | **0.991 / 0.996** | 0.992 / 0.997 | 0.994 / 1.000 | 0.990 / 0.997 | 0.996 / 1.000 |
| NF-ToN | 0.127 / 0.189 | 0.149 / 0.182 | 0.102 / 0.172 | 0.174 / 0.232 | **0.238 / 0.308** |
| NF-BoT | 0.957 / 0.982 | 0.954 / 0.980 | 0.939 / 0.939 | 0.954 / 0.962 | 0.943 / 0.943 |
| NF-CIC 03-02 | 1.000 / 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

Other NF-CIC days have too few attack windows in one half.

**Host-grouped split** (2 folds of hosts; domains with ≥ 4 attacker hosts), partial AUC:

| domain | F0 | + ALL |
|---|---|---|
| NF-ToN | 0.785 | 0.894 |
| NF-BoT | 0.942 | 0.961 |
| NF-CIC 02-20 | 0.972 | 0.975 |
| NF-CIC 02-21 | 0.999 | 1.000 |
| NF-CIC 03-02 | 0.903 | 0.948 |

These are in-network ceilings. Attack hosts recur across the chronological halves, so they can
reflect host-specific behaviour.

## 4. Which explanation applies where

| network | cross-network recall at 1 % FPR | in-network with the 12 features | best-supported explanation |
|---|---|---|---|
| **NF-UNSW** | 0.023 | 0.996 | **cross-domain shift, not information loss.** The 12 features separate its attacks almost perfectly in-network. Transfer fails because its attackers are *quieter* than its benign hosts, the opposite of every source network |
| **NF-ToN** | 0.007 | 0.19 (chronological); 0.90 (host-grouped) | **mixed.** Its attacks change over time (a model of its own first half misses most of the second), and the enriched features add in-network information (0.127 → 0.238). Some information loss, plus shift within and between networks |
| NF-CIC | 0.500 | ≈ 1.0 | shift between networks and memory contamination (Phases 8q–8t); no in-network information loss shown |
| NF-BoT | 0.571 | 0.94–0.98 | the benign tail is a handful of windows (Phase 8u); no information loss shown |

**Information loss is supported only on NF-ToN,** and only in-network, by single diagnostic fits.

**Observability limitation is not supported anywhere.** Every network is learnable from flow
windows in-network, though NF-ToN only partly across time.

## 5. Shortcut diagnostics

**Domain-origin classifier** (4 networks, benign windows only; chance 0.25):

| features | accuracy |
|---|---|
| F0 (12 original) | 0.961 |
| F0 + FLOW | 0.969 |
| F0 + TIME | 0.964 |
| F0 + BIDIR | 0.970 |
| F0 + ALL | 0.977 |
| FLOW only | 0.942 |
| TIME only | 0.887 |
| BIDIR only | 0.909 |

**Every representation identifies the network almost perfectly, the original one included.** The
enriched features neither create nor remove this fingerprint.

**Benign shift per feature** (mean pairwise |2·AUC − 1| between networks' benign windows):
- largest: `mean_log_pkts` 0.78, `mean_log_fwd_iat` 0.73, `log_up_bytes` 0.72;
- smallest: `syn_only_frac` 0.10, `srv_rst_frac` 0.13, `new_dst_frac` 0.13, `no_reply_frac` 0.22,
  `d_log_flows` 0.24.

**Missingness is itself network-dependent.** `gap_cv` is missing for 8 % of benign NF-UNSW
windows and 30 % of NF-ToN's; `mean_log_fwd_iat` for 4 % and 55 %.

## 6. Per attack family (best single feature)

- **NF-UNSW:** 28 label combinations (with ≥ 20 windows) of the same four attacker hosts. For 23
  of them the best new feature is `gap_cv`, at AUC 0.01–0.11: attack windows have a much lower
  flow-gap variation than benign ones. `log_flows` sits at about 0.10.
- **NF-ToN:**
  - `password` and `xss` (5,050 windows) separate by volume (AUC 1.0);
  - `backdoor`, `mitm` and `ransomware` (548 windows) are only moderately separable by any
    single feature (best original 0.70–0.79; best new 0.78–0.87, direction-agnostic).
- **NF-BoT `theft` (45 windows):** separable both by an original feature (`log_up_bytes` 0.08,
  inverted relative to the DoS families) and by `gap_cv` (0.97).
- **NF-CIC:** every family has a near-perfect original feature in-network.

## 7. Decisions taken from this stage

1. **Proceed with a registered tabular comparison** of the three families. It is cheap, and
   NF-ToN shows in-network information beyond the 12 features.
2. **Add one candidate that answers the dominant finding:** source-side invariant-direction
   selection (`INV`). It drops every column whose direction conflicts between the *source*
   networks of a fit, using training rows only.
3. **No sequence model (G4: NOT ATTEMPTED).** Within-window ordering features (TIME) added no
   in-network information (NF-ToN 0.127 → 0.102; NF-BoT 0.957 → 0.939). Nothing here justifies
   revisiting GRU/TCN.
4. **Two features are removed from the registered families on the label-free audit:**
   `retrans_frac` and `mean_log_fwd_iat` (TELEMETRY_AUDIT § 4).
