# Phase 8l DEDALE freeze

**Frozen on 2026-11-02 at commit `912786f9057ef3f147e0c3dc610c0f7168d00b91`** (the code state). This file is committed on top.

- **What the freeze binds.** Every file below is verified before each run (N7,
  `dedale_fetch.freeze_ok`), line by line with LF-normalised SHA-256. Tracked files must also
  be unchanged from HEAD.
- **What has been seen so far:**
  - calibration counts only. The Stage A gate passed: 26 eligible hosts, Kish 26.0, top share
    4 %, 54,120 hold-out windows;
  - no DEDALE window had been scored when this file was committed.
- **Next, in order:**
  1. `dedale_analysis.py --n8`, on calibration scores only;
  2. if N8 passes and the user authorizes it, the Stage B download (396.3 MB),
     `dedale_eval_build.py`, and **one** run of `dedale_analysis.py --final`.
- **If N8 fails,** the study ends NOT EVALUABLE and Stage B is never downloaded.

## Pre-registration

```
d40586b84ebf1c8b131f313cc5c5c27e782e27ff86f339b33452fb2277dcbf12  docs/phase8l/DEDALE_PREREGISTRATION.md
```

## Analysis, adapter and tooling (Phase 8l)

```
20b1f7fc135e019d01fb7b21a8ac41617e63d710fbe850c609570c58d15e3632  scripts/phase8l/dedale_analysis.py
d45c4aa3f1432bce057a4246fe46c0aac909c3c29eff83e4f447975c94108345  scripts/phase8l/dedale_eval_build.py
8a255da3e7941401ac14752d30be16471891f840c25164550dd9869eb5759221  scripts/phase8l/dedale_fetch.py
c85e2afa6ec3d282c3269627f0598a9140f55cb56f727f5fa2c4c9e5c36da755  scripts/phase8l/dedale_stage_a.py
9b32a3fa7663b3b1fb21640d2f14a8c9c33ca76d082b731137b87eae184a7c78  scripts/phase8l/dedale_source_models.py
7ac51267b4e2ef5b51ab400c9e15cb103be0e5d6df4d8ca3865bcbc49c01a227  scripts/phase8l/dedale_zip_index.py
```

## Registered building blocks (unchanged)

```
3d7c657e23410aa0f930f26d115a17bffbd27efd6f225a24f262994566e04c55  scripts/phase8j/build_p1x.py
a20ca26dfe0c94c989a2abadc29ac62410e3647919a18d34534af40bca561f9e  scripts/phase8j/threshold_stats.py
2d41787965debad4d7f450bfba7fb0905daf63021a08debaacfac1ccf13b9a4c  scripts/phase8i/build_windows.py
90aa27d49167f3eab06563cfdac2318d4ccff0bc5a1ac8d9ccb88f9d2e157ce5  scripts/phase8i/common.py
7c59943710c0f5d4c7a8301d76881b666a40fc0bd368eb748930a9e31fc5f21b  scripts/phase8i/calibration_audit.py
af01e63fbcc3da5fb4c2813974546c266432ba75fc0e643ac4a261c9f05f85f0  scripts/phase8b/scorers.py
22302b94ec8da20615172536d9870a3e363d2ff751dbb0a46b6df29f1ff9a617  scripts/phase8b/harness.py
d54d0eeb48d4ac966b330f6a152ac2afa9dc9d10cb3e29acbc68f88beea283df  scripts/phase6/eval_nf_dev.py
4e3b9df125964685d44a458e049e71252bc90463c1832cf30d82b376dbbec8b8  src/netsentinel/behavior/windows.py
```

## Reports the runs read

```
0e80fdfa8dc72b4ebb6f3a25c0dd962630fc27c6570d47006a31ce3009f84a22  reports/phase8l/dedale_manifest.json
841a86ef9054d4994ef78df2a9c3e3ad6e89116aabb529b002d7f5b9e4059861  reports/phase8l/dedale_fetch_stageA.json
7a6c4483df48305be2740f97b262435d705cd4501fd66e254873dbdcb32f82d4  reports/phase8l/dedale_stage_a.json
3ac6e9a22bea4297780adb1939080536f353f50ac009f413fa3c7711ecfd11f0  reports/phase8l/dedale_source_models.json
```

## Source models and Stage A derived data (git-ignored; hash only)

```
901dc758498f523ac8c17a45ad5f510b47490f01466e7d26d789c84c5a5894c0  data/derived/phase8l/dedale/models/b_raw_seed0.txt
90d39ea2d44bc0c30ebbce37a0b4e2a91d3bbf930640185400fec52bbe0d1925  data/derived/phase8l/dedale/models/b_raw_seed1.txt
e1801b0bcf68a20e4ffcb9f6e8065c0c1809c3ff280da65f9ecfefb15385f51c  data/derived/phase8l/dedale/models/b_raw_seed2.txt
6afa05e97d4acab24a933c2c085f672601fbde81fc52c05402b9262e2cf7c38f  data/derived/phase8l/dedale/cal_p1x.parquet
200f668c5020a646769641ccc8a7f3801608769c7f90b7d0a5f9b3103290784a  data/raw/dedale/green_internal/D01_2024-12-23_conn_labeled.csv.gz
2da421bf0b2b7e36d66804de13038585ceb6d68aeba83628be5d878fdc040b89  data/raw/dedale/green_internal/D01_2024-12-23_dhcp.log.gz
f5abe7d95d9011ca6a0be6a47ef698713e7407073d8350b29296bf2ce004bfe5  data/raw/dedale/green_internal/D02_2024-12-24_conn_labeled.csv.gz
90e1849d5d8490487317595b3e7b37ecbd821a1f6ad78ed61966001d41831aac  data/raw/dedale/green_internal/D02_2024-12-24_dhcp.log.gz
c5ad8689f05a73564759a81637ebd0f5f397e1f2100fb622f4895229f1d816d0  data/raw/dedale/green_internal/D03_2024-12-25_conn_labeled.csv.gz
d6a9474f9f729e7e58cda767ca93bc956ee53f54272efd5be0e39d96ae2e9a93  data/raw/dedale/green_internal/D03_2024-12-25_dhcp.log.gz
fe663271e1b3b9042e47f98a5f4647b45a9a35aaaf9e24eb787b6eb2aa95f7dd  data/raw/dedale/green_internal/D04_2024-12-26_conn_labeled.csv.gz
a22281a392d983c60e7c8df56fe0a6b9cd96bd80fddc5c166fd1adb18bd3c616  data/raw/dedale/green_internal/D04_2024-12-26_dhcp.log.gz
23a46da53b0612c3b604012abdcaeef6e718acc2c8a040313873fa67944d2f3f  data/raw/dedale/green_internal/D05_2024-12-27_conn_labeled.csv.gz
ad056b3615e1e558e8d3cc5b49aa14c16ba99917dcc1f97b47375f90ed2b2da6  data/raw/dedale/green_internal/D05_2024-12-27_dhcp.log.gz
a5ff4abcac038a14dd85721d37846bc0625eee1e1bb6c1ec40d9fe1d387f2a0d  data/raw/dedale/green_internal/D06_2024-12-28_conn_labeled.csv.gz
69de9520e94b55b435d63dd5228b899462e6b25009a37e66e0cf7ea348c82600  data/raw/dedale/green_internal/D06_2024-12-28_dhcp.log.gz
506f71e25f906c73595a7f1844c9c49ebae30cfe69b14ad5cc3db5c05ae3e6e0  data/raw/dedale/green_internal/D07_2024-12-29_conn_labeled.csv.gz
db5c30de0c03c36561a9baeb4d00425445b2d45a26252459bb72f00712f8342a  data/raw/dedale/green_internal/D07_2024-12-29_dhcp.log.gz
15648ca87ef275876aa06a5f3f1302173b7b6c293c68e9410c300f210bac22d9  data/raw/dedale/green_internal/D08_2024-12-30_conn_labeled.csv.gz
6780f3fa5952bf94fa983ba2c42a533cff45e283a68723963fdf823eb6168052  data/raw/dedale/green_internal/D08_2024-12-30_dhcp.log.gz
db1b85a42cfa62360c60fe2281dacbd458cb46007aea8203266d9b4a1dab43d2  data/raw/dedale/green_internal/D09_2024-12-31_conn_labeled.csv.gz
4349f640b4a8b1aa12d4ea33a6fa4cc3e4ab6288e90ada47445d37573709fd95  data/raw/dedale/green_internal/D09_2024-12-31_dhcp.log.gz
894c38dc5725cf62a4dce5246bcb6069774305c54ab5acbd7a509f1d4bd04a57  data/raw/dedale/green_internal/D10_2025-01-01_conn_labeled.csv.gz
849bf31c11226f8593d7938f89f7105983e0ec7d23f2ca7d829e745f9b4d8860  data/raw/dedale/green_internal/D10_2025-01-01_dhcp.log.gz
c65aa4cf4faa57f849eedce1eca6d61f0a0c0c91c5fa24a60360d4d20a152d51  data/raw/dedale/green_internal/D11_2025-01-02_conn_labeled.csv.gz
cbeadb2b0b0617a8eac8d09c6b157c78a1d785936a3fefbb2f66f0e081a5268c  data/raw/dedale/green_internal/D11_2025-01-02_dhcp.log.gz
598bedcbe76bac83646f6885cd1fdee7e7b680a25c3538f986c48900ce960f3a  data/raw/dedale/green_internal/D12_2025-01-03_conn_labeled.csv.gz
2395df501464378dd97205e9b254bd4b9d46f9a08ed700728f7f6ce5825c1bf1  data/raw/dedale/green_internal/D12_2025-01-03_dhcp.log.gz
3b27bdde379e3dd2728589c994f6572a47737d99ebe598a1589e8f3e0e14bf4c  data/raw/dedale/green_internal/D13_2025-01-04_conn_labeled.csv.gz
a52233ca5bacfe1c62307ff319d5e6cf57ec7883e197dc6ecd4e4243c11f3021  data/raw/dedale/green_internal/D13_2025-01-04_dhcp.log.gz
3136a173df5767961b675ccbdcd192eb4e32c0c06f254f158ec8a1bd28400fb0  data/raw/dedale/green_internal/D14_2025-01-05_conn_labeled.csv.gz
37afa850e8ec1bb5539b6ed397401c9b27354fb8573524114e73386290fb6b69  data/raw/dedale/green_internal/D14_2025-01-05_dhcp.log.gz
```
