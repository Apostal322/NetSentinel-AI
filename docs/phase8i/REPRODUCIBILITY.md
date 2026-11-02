# Phase 8i reproducibility

**Environment:** the project uv environment (`uv.lock`; Python 3.12, LightGBM, scikit-learn,
polars). All runs are CPU-only. Every command runs from the repository root with
`UV_CACHE_DIR=$USERPROFILE/.uv/cache`, `UV_PYTHON_INSTALL_DIR=$USERPROFILE/.uv/python` and
`PYTHONIOENCODING=utf-8`. A memory watchdog (`scripts/phase8i/watchdog.ps1`, 3.4 GB) runs
alongside.

## 1. Data

```bash
uv run python scripts/download_nf_v3.py configs/datasets/nf_v3_phase8i.yaml
```

```bash
uv run netsentinel data verify --manifest configs/datasets/nf_v3_phase8i.yaml
```

```bash
uv run python -c "import sys; from netsentinel.cli import main; sys.exit(main(['data','ingest-nf','nf-ton-iot-v3']))"
```

The NF-CIC-IDS2018-v3 and NF-UNSW-NB15-v3 ingests are the Phase 4 ones
(`docs/datasets/nf_v3.md`). The archive hashes are in [DATASET_AUDIT.md](DATASET_AUDIT.md).

## 2. Windows

```bash
uv run python scripts/phase8i/build_windows.py nfunsw
```

```bash
uv run python scripts/phase8i/build_windows.py nfcic
```

```bash
uv run python scripts/phase8i/build_windows.py nfton
```

Outputs go to `data/derived/phase8i/<network>/<domain>/` (git-ignored). Counts are in
`reports/phase8i/windows_<network>.json`.

**Consistency check:** the NF-UNSW build reproduces the Phase 8b windows exactly:
1,829,313 flows, 16,028 evaluation windows, 14,057 clean calibration windows, and 4,091
attack windows from 4 attackers.

## 3. Development experiments [E]

```bash
uv run python scripts/phase8i/exp_a.py
```

```bash
uv run python scripts/phase8i/exp_c.py
```

```bash
uv run python scripts/phase8i/exp_b.py
```

```bash
uv run python scripts/phase8i/analyze.py
```

- Experiment B reads Experiment A's saved A1 scores, so run A before B.
- Each result file is written atomically (`.partial`, then renamed), so a crash never leaves a
  file that looks complete.
- Each file records its runtime and peak RSS.

Exploratory analyses run after the development batch:

```bash
uv run python scripts/phase8i/label_audit.py
```

```bash
uv run python scripts/phase8i/attribution.py --seeds 0,1
```

## 4. Confirmatory run (already consumed; do not rerun for model choice)

The exact commands are in [FREEZE.md](FREEZE.md), and `reports/phase8i/logs/confirm8i.sh`
runs them in order. Results are in `reports/phase8i/confirm/`, with verdicts in
`verdicts.json`. The post-hoc diagnostic, run after the verdicts, is:

```bash
uv run python scripts/phase8i/posthoc_n4.py
```

**Commits:**
- pre-registration `86b7daa`;
- amendment A2 `5794364`, amendment A3 `0871e64`;
- development results and A4 `559b4e2`;
- freeze `5db0c6f`;
- confirmatory results `0176269`.

## 5. Determinism

- **Seeds:** LightGBM `random_state` = seed with `n_jobs = 2`. Label draws use
  `np.random.default_rng(1_000_003 * draw + Ka (+7 for the single-entity variant))`. Negative
  subsampling uses `default_rng(seed)`.
- **Known nondeterminism:** LightGBM multithreaded histogram construction can differ in the
  last bits across machines. Results are compared at three decimals.
