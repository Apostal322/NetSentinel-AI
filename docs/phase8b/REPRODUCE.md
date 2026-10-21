# Reproducing Phase 8b

Requirements: the repository's uv environment with the `torch` extra (CPU is enough), about
1.5 GB RAM, and the data below in the git-ignored `data/` folder.

1. **Development data** (already used in Phases 6-8; see `docs/datasets/README.md`):
   - `data/raw/iot23/<9 scenarios>/conn.log.labeled`;
   - `data/raw/ctu_normal/CTU-Normal-*/conn.log` and `data/raw/ctu_normal_26/bro/conn.log`;
   - `data/interim/nf_unsw_nb15_v3/*.parquet` (`netsentinel data ingest-nf`).
2. **Development comparison and incident study** (exploratory; about 4 min plus 1 min). These
   write `reports/phase8b/dev_compare.json` and `incident_rules.json`, and cache windows in
   `data/derived/phase8b/`:

   ```bash
   uv run --extra torch python scripts/phase8b/dev_compare.py
   uv run python scripts/phase8b/incident_rules.py
   ```

3. **Fresh captures.** Download each into its own folder and check its SHA-256 against
   `docs/phase8b/DEVELOPMENT_LOG.md`:

   ```bash
   curl -fL -o data/raw/iot23_fresh/CTU-IoT-Malware-Capture-1-1/conn.log.labeled https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled
   ```

4. **Confirmatory run**, exactly as frozen (step 2 must have run first, so LightGBM's
   development training windows exist):

   ```bash
   uv run --extra torch python scripts/phase8b/confirm.py reports/phase8b/confirm_1-1.json CTU-IoT-Malware-Capture-1-1=data/raw/iot23_fresh/CTU-IoT-Malware-Capture-1-1/conn.log.labeled
   ```

All randomness is seeded (LightGBM seed 0, bootstrap seed 0, torch seed 0), so results should
reproduce to floating-point tolerance on the same library versions (`uv.lock`).
