# NetSentinel AI

Global rules (approval gates, RAM limits, Colab thresholds) are in `~/.claude/CLAUDE.md`. This file covers only this project.

## Commands
- `uv run pytest`: CPU tests (always run after code changes; < 1 min). `-m data` runs tests on the real dataset.
- `uv run netsentinel --help`: all pipeline stages.
- `uv run ruff check . && uv run ruff format .`
- NetFlow v3: `uv run python scripts/download_nf_v3.py`, `uv run netsentinel data ingest-nf <name>`,
  `uv run netsentinel features build --schema nf --interim ... --out ...` (feature sets `nf_*`).
- Capture analysis: `uv run netsentinel analyze <pcap|conn.log> --bundle models/<id>`.
- Batches: `scripts/run_batch_v{1..4}.py` (each item a separate process; need approval when
  > 2 min / > 2 GB); aggregate with `scripts/aggregate_*.py`; audits in `scripts/audit/`.

## Protected data
- Test splits: IDS2018 CIC test used once for runs pre-registered in
  `docs/experiments/test_preregistration.md`. NetFlow test (rows that are test under both the
  episode and chronological protocols) used once on 2026-10-20 for the runs pre-registered in
  `docs/experiments/final_preregistration_nf.md`; markers in `reports/final/` block reruns.
  Both test sets are now spent: never select or tune anything on them. A new model choice needs
  a new untouched evaluation set and a new written pre-registration.
- The episode split's phase depends on the seed (`splits._episodic`); a project-wide
  "untouched" partition must be computed under every seed used.

## Conventions
- Stages are separate processes (8 GB RAM). Use Polars lazy/streaming for anything touching full days.
- Feature columns are declared in `src/netsentinel/features/` with a schema version. Change the list → bump the version.
- Absolute timestamps, IPs, ports-as-identifiers and `row_id` are never model features.
- Preprocessing is fit on the train split only. The test split is read only by `evaluate --final`.
- Every experiment goes through `ledger.Run`. Every reported number in docs must link to a run id.
- Results are labelled measured / estimated / illustrative / pending. Subset runs say so.
