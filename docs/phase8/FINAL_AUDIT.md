# Phase 8 final audit (2026-10-21)

Scope: Phase 8 missions A-J. Development record: [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md).
Pre-registration: [RESEARCH_PLAN.md](RESEARCH_PLAN.md).
Confirmatory results: [CONFIRMATORY_RESULTS.md](CONFIRMATORY_RESULTS.md).

## Mission status

| Mission | Delivered | Evidence | Open |
|---|---|---|---|
| A. Zero-friction demo | `netsentinel demo`: offline, about 1 min, < 1 GB | `tests/integration/test_demo.py` | none |
| B. Temporal models | robust-z, guarded EWMA, lag-IForest, GRU, TCN; causal (tests); latency, memory, training cost measured | 8B log; H1a supported, H1b refuted | none of them is adopted; robust-z stays |
| C. Streaming | `netsentinel monitor` (opt-in, read-only), watermark/lateness, deduplication, skew guard, bounded buffer, replay equivalence | `tests/integration/test_streaming.py`, `test_monitor_cli.py`; H6, H7 supported | no rotation handling for Zeek log files (follow mode reads one file) |
| D. Incidents | grouping, stable IDs, timestamps, counts, evidence, severity, threat status, versions, lifecycle (incl. insufficient_evidence), store, API, dashboard; evaluation | `tests/unit/test_incidents.py`; 8C eval; H3 refuted | severity/ranking of isolated single-window incidents (see below) |
| E. App intelligence | class-consistency abstention (OOD by transport/port profile), port/ML disagreement, unknown protocols; port-only / ML-only / hybrid / +abstention compared | 8D: adopted by a pre-declared rule | H5 not testable on 49-1; the port table beats ML across datasets |
| F. Robust local normality | sample size, time of day, drift, contamination, safe updates | 8F; update gate v2 | gate catches 7/12 short bursts (tuned on dev data) |
| G. Dashboard and API | the six sections plus existing pages; incident filtering/paging; `/baseline`; uncertainty field | AppTest, TestClient | dashboard status changes are unauthenticated (localhost only) |
| H. Docker CI with a model | demo artifacts built on the runner and mounted read-only; ready, schema, safe defaults, incidents, auth, tampering, cleanup | `.github/workflows/ci.yml` | passes in CI (run for `3e2d9d4`); the first attempt expected 401 where an unset admin token correctly gives 403 |
| I. Performance | 24.8k records/s, 2.99 GB peak on 5.4M records; per-scorer latency | H7, 8B tables | single machine |
| J. Research plan before testing | frozen, pushed `d838738`, dry runs on inspected data, corrections recorded before reading 49-1 | git history | none |

## Integrity checks

- **Fresh data was fresh.** 49-1's contents were first read by the frozen script.
  - Before that, only its size and SHA-256 were looked at.
  - The download's preview command (`head -c 700`) wrote the first bytes to a log, which were
    not read; only the size and hash lines were extracted from it.
  - The dry runs used the inspected scenarios 3-1 and CTU-Normal-22.
- **Spent test sets** (CIC, NF final) were not used.
- **Exploratory vs confirmatory** results are separated in every document.
  - Development choices (selection rule 8B, adoption rule 8D, gate factor 8F) were written
    down before the respective runs.
  - Exception: the gate factor 2.0 was chosen after seeing the 1.5x results on the same data.
    It is labelled unvalidated.
- **Negative results are reported:**
  - temporal models do not win;
  - H1b and H3 were refuted;
  - the rate-only update gate missed every injected burst;
  - the port table beats ML across datasets;
  - 60 s lateness would drop up to 20% of Zeek records.
- **No generalisation claim** from one capture.

## Product findings to act on

1. **Incident ranking.** Isolated single-window false alerts become `medium` incidents (9 of
   10 on 49-1). Proposed fix, not implemented, needs development evidence: rank by
   `n_windows` and duration as well, and mark single-window incidents below 2x the threshold
   as `low` / `insufficient_evidence`.
2. **Contaminated calibration remains undetectable** when the attacker dominates the
   calibration period (49-1 unlabelled: recall < 0.02). Neither temporal adaptation nor the
   gate helps here; only vetting does.
3. **Protocol identification across networks:** the port table alone is more reliable than
   the ML model (UNSW 0.990 vs 0.779 accepted accuracy). Consider making port-first the
   default and ML a fallback for non-standard ports.

## Release decision: v0.8.0, not a v1.0 release candidate

A v1.0 RC is **not justified** yet:
- (Resolved since: the CI security job was red on certifi GHSA-6q48-6c7w-9gw2 and nine
  Pillow advisories of 2026-10-20. Fixed by certifi 2026.10.19 and Pillow 13.0.0 (a uv
  override of streamlit's pillow<13 cap). All CI jobs are green on `f02917a`.)
- H3 (the incident layer's analyst benefit) was refuted on the only fresh capture.
- Confirmatory evidence is one capture.

Criteria proposed for 1.0-rc1:
- all CI jobs green (met on `f02917a`), and the Pillow override removed once streamlit allows Pillow 13;
- the incident-ranking fix, validated on development data and on a new fresh capture;
- at least one additional fresh capture with a pre-registered replication of H2;
- Zeek log rotation in `monitor`.
