# Phase 6 development log

## 2026-10-20

- **6A audit.**
  - Baseline: default test suite green (190 s), `ruff check` clean.
  - CI defect found: `ruff format --check` failed on 6 files written in Phase 5. Fixed by
    formatting them (plus one E731 lambda turned into a def).
- **Independent data** (user-authorised download, about 77 MB):
  - CTU-Normal-20..25, 27..32 Zeek conn logs;
  - 9 IoT-23 labelled conn logs.
  - SHA-256 hashes: `reports/audit/phase6_external_data_sha256.txt`.
- **Composition:**
  - Most CTU-Normal captures are the same lab host (10.0.2.15) as CTU-26, so they are a
    different day but the same environment.
  - CTU-Normal-21 and -22 are a different network (192.168.1.x).
  - IoT-23 20-1, 21-1, 42-1 and 44-1 are mostly benign with rare C&C.
  - IoT-23 3-1, 8-1 and 34-1 are dominated by malicious traffic.
  - IoT-23 data lines separate the last three fields by spaces, not tabs, and need a
    dedicated loader.
- **Plan and frozen hypotheses:** `docs/phase6/IMPLEMENTATION_PLAN.md`.
