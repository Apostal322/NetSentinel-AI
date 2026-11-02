# Phase 8i freeze: protocol, code and choices before N4 (NF-BoT-IoT-v3) is opened

**Frozen:** 2026-11-02. **Code commit:** `559b4e2`.
- Pre-registration including amendments A1–A4: [PREREGISTRATION.md](PREREGISTRATION.md).
- The confirmatory verdict code is `scripts/phase8i/confirm_analyze.py`, written and dry-run
  on a development stand-in before this freeze.

## Choices made by the registered development rules

Source: `reports/phase8i/analysis.json` and `reports/phase8i/freeze.json`.

| hypothesis | choice | development basis [E] |
|---|---|---|
| I1 | **A4** (continued boosting) | highest median operational recall at Ka = 25 over the 3 networks (0.805; A5 0.781, A3 0.466), median FPR 1.3% ≤ 2%. On NF-ToN-IoT its FPR was about 10%. |
| I2 | **τ = 0.7009482465833334** (S_score) | 60% coverage on 118 development blocks; S_score block AUC 0.72 (domain-bootstrap 95% CI 0.54–0.92) |
| I3 | **C1_k2** | the less negative of C1_k2 (−0.065) and C2 (−0.112) against B-raw; both lose ≤ 0.002 within-network. **No representation improved on development**, so the prior for I3 is low. |

## Confirmatory commands (run once, in this order)

```bash
uv run python -c "import sys; from netsentinel.cli import main; sys.exit(main(['data','ingest-nf','nf-bot-iot-v3']))"
```

```bash
uv run python scripts/phase8i/build_windows.py nfbot --protected-confirm
```

```bash
uv run python scripts/phase8i/exp_a.py --confirm --out reports/phase8i/confirm/exp_a
```

```bash
uv run python scripts/phase8i/exp_c.py --confirm --part cross --out reports/phase8i/confirm/exp_c
```

```bash
uv run python scripts/phase8i/exp_b.py --confirm --tau 0.7009482465833334 --out reports/phase8i/confirm/exp_b
```

```bash
uv run python scripts/phase8i/confirm_analyze.py
```

- **Results are kept regardless of outcome.** No method, threshold or criterion may change
  after N4 is opened.
- **If a step crashes:** fix the crash only (no change to methods, thresholds or criteria),
  record it in AUDIT_TRAIL.md, and rerun the same command.
