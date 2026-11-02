# Phase 8k freeze candidate

**This is not `FREEZE.md`.** It does not unlock `confirm_analysis.py --confirm`. It records the
exact code and protocol that the confirmatory run must use.

`FREEZE.md` is written only after the authorized steps 5–7 of PREREGISTRATION.md section 8:
- the probes and the F0 feasibility gate;
- the source models;
- the confirmation downloads.

It must repeat these hashes unchanged and add:
- the mapping code;
- the source-model files;
- the archive hashes;
- the unit → family file.

**Code and protocol commit:** `7164e0d` (2026-11-02). The working tree matched this commit when
the hashes were taken. Files have LF line endings (`.gitattributes`: `eol=lf`), so the on-disk
SHA-256 is the same on every checkout.

| file | SHA-256 (on-disk bytes) | git blob (12 chars) |
|---|---|---|
| `scripts/phase8k/confirm_analysis.py` | `ca2d566aafc90ce08ea354ba842d32e9ad70d4f1e36b88c29df1dfe0715a02cc` | `f625dceaeed8` |
| `scripts/phase8j/dev_compare.py` | `95e4c6f10454f3903ac901822f697770756aa61da71245c2ad5a89876a5ec8df` | `04163de90474` |
| `scripts/phase8j/threshold_stats.py` | `a20ca26dfe0c94c989a2abadc29ac62410e3647919a18d34534af40bca561f9e` | `2b4034f20f91` |
| `scripts/phase8j/dev_scores.py` | `4dd7408dd890311d933216dc803a3c8d73dafc5191b21ae13fb6387059adeda6` | `1bd9ed045ede` |
| `scripts/phase8j/build_p1x.py` | `3d7c657e23410aa0f930f26d115a17bffbd27efd6f225a24f262994566e04c55` | `8fa5b6bd464c` |
| `scripts/phase8j/leakage_audit.py` | `bebdb058728ff64acbcea56e285716b2216f181db5c8b1b46eb420a3c60624d7` | `1a60f33032cf` |
| `scripts/phase8i/calibration_audit.py` | `7c59943710c0f5d4c7a8301d76881b666a40fc0bd368eb748930a9e31fc5f21b` | `4b38ed5b6007` |
| `scripts/phase8i/common.py` | `90aa27d49167f3eab06563cfdac2318d4ccff0bc5a1ac8d9ccb88f9d2e157ce5` | `93742502ae7d` |
| `scripts/phase8i/build_windows.py` | `2d41787965debad4d7f450bfba7fb0905daf63021a08debaacfac1ccf13b9a4c` | `f5dce470d6e2` |
| `scripts/phase8b/harness.py` | `4e381019c776d5c2a1a10956ffe65d9c3b813b98bc53ad2460ec184ad73b5888` | `fe88b98dac4d` |
| `scripts/phase8b/scorers.py` | `af01e63fbcc3da5fb4c2813974546c266432ba75fc0e643ac4a261c9f05f85f0` | `921d90e49abf` |
| `scripts/phase8h/lodo.py` | `a1c340a3a53922d9d9b87f0a66b2773f54f2ebf2bfabcc9a25baedf8971fbb76` | `5a01acbd21b7` |
| `src/netsentinel/behavior/windows.py` | `3886d8afb6fcf36bb4edb289bd9debef0caa6219e4b9f234b5d1c33c7a01d900` | `ea96153508e5` |
| `src/netsentinel/behavior/profile.py` | `11bf5220f7ab9c2651c8dfd6e97846df75b70b9d15a9611d09eb1c43e62c720a` | `5b9a71d9f749` |
| `docs/phase8k/PREREGISTRATION.md` | `647d588c420792d326f357cdd9d6d2c6ff3ac8a4a861185bedf899b7b6b89cc6` | `27f48b15dafb` |

**Frozen parameters** (in the code above):
- α = 0.01, tolerance 2α;
- M1 thresholds: 199 sessions, 10 effective hosts, 25% top share, grouped exceedance ≤ 2α;
- PAC: ε = 2α, δ = 0.05, ≥ 10 hosts;
- seeds {0, 1, 2}, with acceptance by ≥ 2 of 3;
- adequacy: ≥ 200 verified-benign windows;
- attack entities: ≥ 5 attack windows;
- bootstrap: 2,000 draws, analysis RNG seed 8;
- criteria (a)–(f) and gates E1–E3 as in PREREGISTRATION.md section 6.

**Verification before the protected run:**
- `sha256sum` of every file above must match this table.
- `confirm_analysis.py` itself refuses `--confirm` unless `FREEZE.md` contains its SHA-256.
