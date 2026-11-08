# Phase 8s gap register

Written 2026-11-09.

**Starting point:**
- `main` = `origin/main` = `bb9c9f2`, with a clean tree and no tags.
- The machine was heavily shared: other projects' RL training and three pytest runs were active,
  with 0.2–0.6 GB of RAM free.

| ID | gap | evidence | severity | investigation | acceptance | status |
|---|---|---|---|---|---|---|
| S0.1 | **The full suite was not re-run after the Phase 8r M3 fix** | Phase 8r report | high | full detached run on `bb9c9f2`, JUnit | 0 failed, 0 errors | **closed**: 419 passed, 0 failed, 0 errors, 0 skipped, 2 deselected, 1,750 s (`reports/phase8s/junit_phase8r_closure_bb9c9f2.xml`) |
| S0.2 | **CI status of `bb9c9f2` unknown** (`gh` absent) | — | medium | public REST API: runs for the head SHA, jobs and steps | documented | **closed**: run 42521466177 (push), `test`, `docker` and `security` all succeeded. The workflow triggers on every push and pull request, with no path or branch filters. There is no configuration defect |
| S0.3 | **The Phase 8r report says "not pushed"** | report text | low | addendum | historical text kept | **closed** (addendum) |
| S0.4 | lint, format and dependency gate | — | — | ruff check, `ruff format --check`, `check_dependency_exceptions.py`, `uv lock --check` | clean | **closed**: all clean (470 files) |
| S1.1 | **Host-sampled vetting is not window-representative** (Phase 8r) | NF-ToN: 98 % of benign hosts are single-window | high | Poisson probability designs with known π, Hájek weighting | H1 | open |
| S1.2 | **How much tail evidence exists?** | — | high | Stage 3 (SAMPLING_ESTIMAND) | per-network tail-host counts | **done**: NF-CIC's tail sits on 85–140 effective hosts; NF-UNSW, NF-ToN and NF-BoT on 1–3 hosts |
| S1.3 | **Biased acquisition needs design-based correction** | — | medium | C0 vs C1 (H3), C3 abstention | H3 | open |
| S1.4 | **Reviewer error and missing-not-at-random review** | — | medium | R1 and R2 reviewers (H4) | H4 | open |
| S1.5 | **Calibration freshness** | Phase 8o: FPR rises with memory age | medium | E0–E3 (H5) | H5 | open |
| S1.6 | **Memory contamination** (NF-CIC 02-22, 03-02) | Phase 8r C | high | out of scope: no memory candidate | — | **carried** (stays a limitation) |
| S1.7 | **No independent network** | Phase 8o, 8r | high | — | — | **NOT READY** (carried) |
