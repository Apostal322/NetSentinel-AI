# Phase 8t pre-registration: operational objective and the oracle-feasibility gate

**Registered:** 2026-11-09, before any oracle outcome was computed.

**Seen before registration:**
- the Phase 8s results;
- one structural count (§ 3): on every domain, no evaluation host has both documented-attack and
  benign windows.

**Code:**
- `scripts/phase8t/oracle_feasibility.py`;
- `scripts/phase8t/threshold_oracles.py` (pure functions);
- `tests/unit/test_phase8t.py`.

**Scores:** the saved Phase 8o F0 scores of the frozen M2 construction (6 fits, K = 5). No model
is fitted.

## 1. Operational objective (Stage 2)

| item | definition |
|---|---|
| prediction unit | a (source host, 30 s) window, as in Phase 8i |
| eligible benign population | Phase 8q categories `benign_uninvolved` + `benign_involved_host` (dataset-labelled benign; **not verified**) of the domain's evaluation period |
| eligible attack population | V2 documented attackers (`documented_attack`, `documented_family_mismatch`, `documented_outside_interval`) |
| excluded from both | `attacked_host_traffic`, `undocumented_source`, `attacker_host_other_window`, ambiguous; reported separately, never counted as benign |
| primary metric | **window-weighted benign FPR at the nominal α = 1 %** and documented-attack window recall at that budget |
| false-alert budget | B = ⌊α · N_benign⌋ benign windows alerted per domain evaluation period. Every method is compared at **the same B** |
| secondary | R₂₀ / R₅₀ entities, entities missed entirely, detection delay (first alerted positive window minus first positive window, per entity), false alerts per hour, host concentration (top host's share of false alerts) |
| active host | a host with at least one window in the period |
| deduplication | none: a window is the unit, and per-host concentration is reported instead |
| abstention | none in the oracle: every window is decided |
| missing telemetry | windows exist only where flows exist; silent hosts are not scored |

**The global 1 % FPR and per-host FPR are different objectives.**
- A method that equalises per-host FPR can raise total false alerts, because high-volume hosts hold
  most windows.
- **Primary is global;** per-host concentration is secondary.
- **The 1 % target is not relaxed.** Phase 8s's "T + 2 pp" guardrail compared methods against an
  oracle threshold; it was never the operating target.

## 2. Score states

| state | scores | role |
|---|---|---|
| **S_U (deployable memory)** | `s_ev_u`: destination memory frozen at the midpoint, unlabelled | **primary** |
| S_P (memory oracle) | `s_ev`: P1x memory | diagnostic only. It asks whether the information would exist with a clean memory |

## 3. A structural fact that limits per-host oracles

On all 9 domains, **no evaluation host has both documented-attack and benign windows.**
- The Phase 8i benign set excludes every window of any attacking host.
- Therefore:
  - **O1, an unconstrained per-host threshold,** reaches recall 1 at zero false alerts by setting
    attacker hosts to −∞ and benign hosts to +∞. This is pure memorisation of host identity
    against labels, and is stated analytically, not computed as an "upper bound".
  - **O4, per-host thresholds for hosts with ≥ 100 calibration windows,** is the same
    memorisation, restricted to hosts with history. It is computed only to count how much recall
    that channel carries and how many free parameters it needs.
- **Within-host benign/attack separation is not measurable on this benchmark.**

## 4. Oracle comparisons (retrospective; development data; NOT deployable)

All use evaluation labels to choose thresholds, at budget B per domain:

| id | thresholds | free parameters |
|---|---|---|
| **O0** | one global threshold: the (B + 1)-th largest benign score; alert if s > t | 1 |
| **O2** | one threshold per **calibration-activity group** of the window's host, using the host's window count in the unlabelled calibration period (label-free, known at deployment): new (0), low (1–9), mid (10–99), high (≥ 100). The total false alerts are allocated across groups to maximise detected windows (exact dynamic programme) | 4 |
| **O3** | one threshold per **window service profile** (UDP share > 0.5 × destination ports in {1}, {2–5}, {> 5}), same allocation | 6 |
| O4 | per-host thresholds for hosts with ≥ 100 calibration windows, plus O0 for the rest (memorisation channel; see § 3) | eligible hosts + 1 |

**Guarded versions (O2g, O3g):** a group with fewer than 100 benign windows in the period gets no
free threshold and uses O0's. Without this, a group holding attack windows and almost no benign
ones could be set to −∞ at zero cost, which is memorisation through group composition.

**The registered constrained oracle is O2g and O3g.** O2 and O3 (unguarded) are reported as more
flexible references.

**Temporal fragility:**
- thresholds are chosen on the first half of the evaluation period (by window index), using
  first-half labels at budget ⌊α · N_benign,first⌋;
- they are applied to the second half;
- the result is compared with the second-half O0 chosen on the second half itself.

## 5. Gate G1: oracle feasibility (decides Stage 4)

**Computed on S_U. G1 PASSES if all three hold for the better of O2g and O3g:**
1. macro (over networks) recall gain over O0 ≥ 0.05;
2. mean R₂₀ gain over O0 ≥ 3 entities (the sum over domains, averaged over fits);
3. the gain survives the temporal holdout: the first-half-selected group thresholds keep ≥ 50 % of
   the second-half recall gain over the first-half-selected O0 applied to the second half. If the
   second half has no positives on a network, that network is excluded from criterion 3 and this
   is reported.

**If G1 fails:**
- the conditional-calibration hypothesis has **no demonstrated development-level opportunity
  under the current score representation**;
- deployable candidates M1–M4 and the hierarchical model are **not run**;
- the phase proceeds to the model-limit analysis (§ 6).

**If G1 passes:** deployable candidates are registered in an amendment **before** they are
evaluated.

## 6. Model-limit analysis (runs in either case; descriptive)

Per network, both score states:
- O0 recall at 1 % FPR;
- normalised partial AUC over FPR ∈ [0, 1 %];
- the share of documented entities whose highest-scoring window exceeds O0's threshold (entity
  separability at 1 %).

## 7. Statistics

- **Units:** 4 networks (2 institutions), 9 domains, 48 documented entities, 6 correlated fits.
- **Means over fits,** then domains within a network, then a macro over networks. Fit spread is
  reported.
- **No window-level bootstrap.** An entity-cluster bootstrap over domains is reported for the O2g
  and O3g gains.
- **Every oracle number is retrospective,** chosen with the evaluation labels it is scored on.
