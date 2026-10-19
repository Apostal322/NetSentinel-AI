# NetSentinel AI

Global rules (approval gates, RAM limits, Colab thresholds) are in `~/.claude/CLAUDE.md`. This file covers only this project.

## Commands
- `uv run pytest`: CPU tests (always run after code changes; < 1 min). `-m data` runs tests on the real dataset.
- `uv run netsentinel --help`: all pipeline stages.
- `uv run ruff check . && uv run ruff format .`

## Conventions
- Stages are separate processes (8 GB RAM). Use Polars lazy/streaming for anything touching full days.
- Feature columns are declared in `src/netsentinel/features/` with a schema version. Change the list → bump the version.
- Absolute timestamps, IPs, ports-as-identifiers and `row_id` are never model features.
- Preprocessing is fit on the train split only. The test split is read only by `evaluate --final`.
- Every experiment goes through `ledger.Run`. Every reported number in docs must link to a run id.
- Results are labelled measured / estimated / illustrative / pending. Subset runs say so.
