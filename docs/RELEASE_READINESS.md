# Release-readiness audit (v0.7.0, 2026-10-20)

Scope: whether the repository can be published as a credible ML engineering portfolio
project. It is **not** an assessment of production fitness: NetSentinel AI is a research
prototype and a local, detection-only analysis tool.

Legend:
- **Verified**: executed and checked in this phase, evidence named.
- **Unverified**: present but not executed here.
- **Blocked**: cannot be executed in this environment.
- **Incomplete**: known gap.

## Verification matrix

| Area | Status | Evidence |
|---|---|---|
| Clean installation from the lockfile (fresh clone, base deps + `dashboard` extra) | **Verified** | `reports/phase7/release_validation.txt` (`scripts/release/validate_release.sh`) |
| CI `test` job commands (ruff check, ruff format --check, pytest) on the fresh clone | **Verified locally**: 114 passed, 1 skipped (torch-only), 1 deselected | same |
| Full suite in the development environment (incl. torch extra) | **Verified**: all default tests pass | development log / this phase's commits |
| CLI: `--help`, `calibrate` (+ `--activate`, registry), `calibration list`, `analyze` (PCAP) | **Verified** on a synthetic capture in the fresh clone; on real CTU-26 in development | release validation; `reports/phase7/ctu26_*.json` |
| PCAP / Zeek processing | **Verified**: real CTU-26 PCAP vs its Zeek log (Phase 5), 13 CTU and 9 IoT-23 Zeek logs | `reports/audit/pcap_vs_zeek.json` |
| Model, calibration and classifier loading, plus integrity refusal | **Verified**: tests (tamper, schema, missing) and real artifacts | unit/integration tests |
| API | **Verified**: TestClient integration tests and a real `netsentinel serve` process (`/health`, `/ready`, `/events`, `/predict/flow`) | release validation |
| Dashboard | **Verified**: Streamlit AppTest renders all 7 pages (a bug was found and fixed), plus a manual browser check on real events | `tests/integration/test_dashboard.py` |
| Event storage (flows + behaviour windows, migration, retention) | **Verified** (tests; real CTU-26 run) | integration tests |
| Safe supervised-threat default | **Verified** (16 policy tests; CTU-26: 102 -> 0 false `suspicious`) | `docs/phase7/RELIABILITY.md` P1 |
| Docker image build / container smoke test | **Verified in CI** (GitHub-hosted runner): image builds, `--help` runs, API `/health` 200 and `/ready` 503 without a bundle. Not run locally (no Docker on the development machine) | CI run 39480870143, job `docker` |
| GitHub Actions run | **Verified**: all three jobs passed on the first push (commit a1a8a35) | https://github.com/Apostal322/NetSentinel-AI/actions/runs/39480870143 |
| Dependency vulnerability scan (pip-audit) and secret scan (gitleaks) | **Verified in CI** (job `security` passed); manual history scan (below) also clean | same run |
| Live capture / streaming | **Incomplete** (not implemented, by design) | — |

## Independent audit findings (Phase 7)

| # | Severity | Finding | Resolution |
|---|---|---|---|
| R1 | High (fixed) | Supervised verdicts were authoritative on unverified networks (lenient domain check v1; API `/predict/*` with no check at all) | Default `unverified` policy everywhere; domain check v2; regression tests |
| R2 | High (fixed) | Calibration FPR promise not met (Phase 6 H1) | Diagnosed as small-sample threshold noise; diagnostics, `baseline_provisional`, cross-fitted thresholds; recall trade-off documented |
| R3 | High (fixed) | App classifier confidently wrong under shift, never abstained | Port-evidence policy with explicit conflict abstention, selected on development data |
| R4 | Medium (fixed) | Dashboard Network-behaviour page crashed on real stores (SQLite 0/1 used as a boolean mask) | Fixed; AppTest regression test |
| R5 | Medium (fixed) | CI would have dropped the dashboard extra on `uv run` | All CI and validation steps use `--extra dashboard` |
| R6 | Medium (fixed) | Unlabelled-calibration domain checks resolved to `unsupported` instead of `unverified` | Fixed; test |
| R7 | Medium (fixed) | Phase 6 scripts would silently change results under the new default threshold method | Pinned to `split`; Phase 6 result files restored after an accidental overwrite |
| R8 | Medium (open) | `netsentinel replay` / `/replay/*` still uses supervised verdicts directly | By design it replays the bundle's own training-domain data; documented |
| R9 | Low (open) | One transient full-suite stall was not reproducible | Recorded; full suite re-run clean several times |
| R10 | Info | Commits carry the author identity configured in git (name and e-mail) | Not rewritten (history preserved); publishing makes it public |

## Data leakage, schema, scores and privacy

- **Leakage.** Causal windows (tested). Consumed test partitions excluded from Phase 6–7
  development (per-day 78% guard). Policy selection used NF development data only. CTU and
  IoT-23 results after Phase 6 are labelled exploratory or descriptive.
- **Schemas.** Every artifact type is hash- and schema-version-checked. Phase 6 classifier
  artifacts (1.0.0) still load. Behaviour artifacts moved to 1.1.0, and older ones must be
  recalibrated, with a clear error.
- **Scores.** `anomaly_score` is a percentile, labelled `normalized_non_probability`.
  `app_confidence` is labelled uncalibrated. Supervised probabilities are isotonic on
  training-domain validation data only.
- **Privacy.** No payloads stored. Device addresses appear in behaviour-window keys and in
  `model_scope`. Retention purge covers both tables. No datasets, captures, models or event
  stores are in git.

## Pre-publication history scan

Performed over all commits (`git log --all -p`):
- no tokens, API keys or private keys (GitHub, AWS, Slack or generic `key/secret/password=`
  patterns);
- no data, model, database, pickle or capture files ever committed;
- largest blob `uv.lock` (0.6 MB); `.git` is 3.4 MB;
- no local user paths in tracked files;
- `.claude/` (local tool config) is git-ignored.

## Remaining work

1. Run the Docker image with a mounted bundle (CI smoke-tests it without one).
2. A genuinely untouched evaluation capture for any new confirmatory claim.
3. Paired PCAP + nProbe captures to verify field-level NetFlow compatibility.
4. Behaviour baselines conditioned on the ML application class; live capture mode.
