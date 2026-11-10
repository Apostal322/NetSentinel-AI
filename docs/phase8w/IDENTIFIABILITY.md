# Phase 8w: information scenarios and identifiability

**Question.** What can a target-network reference estimate without labels, and what can it not?

## 1. Scenarios

Each scenario is a different amount of information about the target network. Results are
reported one block per scenario and are never pooled.

| id | kind | target reference fitted on | deployable? |
|---|---|---|---|
| `Z0` | zero-shot | nothing from the target: the element-wise median of the source domains' references | yes |
| `Z1` | unsupervised target-adaptive | every unlabelled calibration window before the hold-out cut | yes, given a history period |
| `Z2` | weakly supervised target-adaptive | 800 of those windows drawn uniformly, kept if a **perfect simulated reviewer** (the window label) calls them benign | simulated only; not real analyst evidence |
| `Z3` | oracle-assisted | those windows without any that contain a labelled attack flow | **no**: diagnostic upper reference |
| `T` | oracle-assisted | the label-benign calibration windows, as in Phase 8h: the **whole** calibration period including the hold-out, with attacking hosts removed using calibration **and evaluation** labels | no |

**Timeline for every scenario:** reference period → threshold hold-out (last 30 % of calibration
slots) → evaluation. A `Z0`–`Z3` reference never sees a hold-out or evaluation window (tested: a
fitted reference is not changed by scoring). **`T` is the exception** (corrected after the
independent review, finding A1): it covers the hold-out too (81 % of its NF-BoT windows) and its
host cleaning reads evaluation labels. It is a historical comparison, never a deployable result.

**Source domains** always use their own label-benign calibration windows. Those are training
labels, legitimately available for a source network.

## 2. What an unlabelled history identifies

The median of an unlabelled period is the centre of the **observed mixture**, not of benign
traffic. Two different worlds can produce the same observations (unit test
`test_unlabelled_mixture_does_not_identify_the_benign_reference`):

| world | benign population | attack population | observed distribution | benign median |
|---|---|---|---|---|
| A | half quiet hosts, half busy hosts | none | bimodal | between the modes |
| B | quiet hosts only | busy attackers, half of the traffic | **the same** | the quiet mode |

No estimator can tell A from B without outside information. So:

- **`Z1` is a "distance from what this network usually looks like" reference.** It equals the
  benign reference only if attack traffic is a minority *and* does not sit where the benign
  median would flip.
- **The median's 50 % breakdown point is not a guarantee.** It protects against a minority of
  arbitrary outliers around a unimodal benign population. With a bimodal benign population, a
  small attack share on one mode moves the median to the other mode.

## 3. What the development networks show (label diagnostic; `reports/phase8w/references.json`)

Reference period = unlabelled calibration windows before the hold-out cut.

| domain | reference windows | attack-window share | attacker-host share | largest \|Z1 − Z3\| location shift (Z3 scale units) |
|---|---|---|---|---|
| NF-CIC, six days | 65,516–97,818 | 0.2–1.1 % | 0.2–9.5 % | ≤ 0.07 |
| NF-UNSW | 14,371 | 5.3 % | 5.3 % | 0.09 |
| NF-ToN | 49,901 | 13.6 % | 54.8 % | **17.4** (`log_down_bytes`) |
| NF-BoT | 2,307 | **62.0 %** | **92.3 %** | **46.7** (`med_log_dur`); 11.0 (`log_flows`) |

- **NF-CIC and NF-UNSW:** the unlabelled reference is practically the oracle reference.
- **NF-ToN:** 13.6 % attack windows are enough to move one reference by 17 scale units. Its
  benign download volume is bimodal (the oracle median is 0 with a floored scale), which is the
  case in § 2.
- **NF-BoT:** attack traffic is the majority of the history. The "reference" is the attack. A
  benign reference is **not identifiable** from this history, and only 876 label-benign windows
  exist before the cut.
- **Host-level cleaning is not available on NF-BoT:** removing every attacking host leaves 178
  windows, below the 200-window minimum (`insufficient_history`; never substituted).

**Consequence.** `Z1` is deployable on all four networks but estimates a benign reference on
only two. Results under `Z1` on NF-ToN and NF-BoT measure "deviation from a contaminated
normal", and are reported as such.

## 4. No-fit direction diagnostic (exploratory; uses evaluation labels of consumed networks)

Univariate AUC of each feature on the audited evaluation windows, mean per network. A feature
*conflicts* if two networks sit on opposite sides of 0.5 by at least 0.1 (the Phase 8v rule).

| representation | conflicting features (of 12) | features with AUC ≥ 0.6 on all four networks |
|---|---|---|
| raw value (= signed z inside a network) | 8 | none |
| \|z\|, label-benign reference `T` | 5 | `log_flows`, `log_down_bytes`, `log_pkts` |
| \|z\|, unlabelled history `Z1` | 7 | `log_flows`, `log_pkts` |
| \|z\|, simulated review `Z2` | 6 | `log_flows`, `log_pkts` |
| \|z\|, oracle `Z3` | 7 | `log_flows`, `log_pkts` |
| \|z\| per host, unlabelled history | 3 | none |

`log_flows`, raw vs unsigned (`Z1`): 0.86 / 0.13 / 0.95 / 0.97 → 0.81 / 0.85 / 0.94 / 0.91
(NF-CIC / NF-UNSW / NF-ToN / NF-BoT).

- **The unsigned deviation removes the volume-direction conflict in this univariate view.**
  NF-UNSW's quiet attackers and the other networks' loud ones both sit far from their network's
  normal. Seven of 12 features still conflict under `Z1` (8 raw).
- **It does not remove every conflict.** Destination counts and the fraction features still
  disagree, and NF-BoT's contaminated reference inverts two features (`log_down_bytes` 0.14,
  `upload_share` 0.18).
- **This is a univariate, in-sample view.** It motivated the candidate; it is not evidence that
  a transferred model improves. That is the registered experiment.

## 5. Context-conditioned references (why no context arm is fitted)

Own-host references need ≥ 30 reference windows; other windows fall back to the network
reference.

| network | evaluation windows with an own-host reference | attacker hosts with an own reference | `log_flows` AUC, network → own-host \|z\| |
|---|---|---|---|
| NF-CIC | 57–66 % | 17 of 30 | 0.81 → 0.82 |
| NF-UNSW | 96 % | 4 of 4 | 0.85 → **0.55** |
| NF-ToN | 87 % | 9 of 10 | 0.94 → **0.48** |
| NF-BoT | 92 % | 4 of 4 | 0.91 → 0.97 |

- On the two hard networks the attackers are **persistent hosts with their own history**. A
  per-host unlabelled reference learns the attack as that host's normal and the volume signal
  disappears.
- A deployable per-host reference would need the host's history to be benign, which is the
  unidentifiable quantity of § 2 at a finer grain with fewer windows.
- Service- or protocol-conditioned references were tested in Phase 8u (`C1`) without a
  hard-network gain.

**Decision:** no context-conditioned arm is fitted in this phase. Gate G2 is registered as NOT
EVALUABLE; the table above is its only evidence and it is exploratory.
