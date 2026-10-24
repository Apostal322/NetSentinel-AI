# Pre-registration template (NetSentinel AI)

Copy this file to `docs/<phase>/PREREGISTRATION_<name>.md`. Fill in every field and commit it
**before** the evaluation data is downloaded, opened or parsed. Leave nothing as "TBD". The
evidence standard is in [EVALUATION_METHODOLOGY.md](EVALUATION_METHODOLOGY.md).

## 0. Identity
- Title:
- Author(s):
- Date:
- Commit SHA of the frozen code (scripts and `src/`):
- Hypothesis IDs (as recorded in docs/HYPOTHESIS_LEDGER.md):

## 1. Data
- Dataset / capture, official source and licence:
- Expected size and SHA-256, recorded on download:
- Why it is fresh: never used for any choice. Check it against the consumed list.
- Known label scheme. Directionality, time bounds and roles are audited **after** the run,
  following LABEL_PROVENANCE.md:
- Exclusions decided in advance (files, hosts, time ranges):
- Protocol deviations allowed without re-registration: none, or list them.

## 2. Unit, level and populations
- Metric level (EVALUATION_METHODOLOGY.md §1):
- Entity key and window length:
- Populations reported (local, external_transient, external_profiled, global, service):
- Calibration / evaluation split rule:

## 3. Policies
- Primary policy (frozen name and parameters):
- Baselines: the never-alert policy and the deployed policy, both required:
- Secondary policies, if any. These are exploratory and cannot carry the claim:

## 4. Metrics and decision rule
- Primary metric and its direction:
- Success criterion. A number, and how the interval must relate to it:
- Burden criterion: FA/h per population, with its budget:
- Coverage criterion, if anything abstains:
- What counts as failure, and how failure is reported:

## 5. Uncertainty
- Bootstrap block length and expected number of blocks: ≥ 10 blocks, or label the interval
  descriptive.
- Resamples and seed:
- Entity-level intervals: Wilson. Counts only below 5 positive entities.

## 6. Compute and safety
- Expected runtime and peak memory (machine limits: < 3.5 GB RAM):
- Approvals needed (downloads, long runs):
- Detection only: no blocking or traffic modification.

## 7. After the run
- Results file paths:
- Mark the data as consumed in the hypothesis ledger.
- Post-hoc analyses must be labelled **[R]**. They never change the recorded verdict.
