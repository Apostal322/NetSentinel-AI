"""Correction batch v3 (approved 2026-10-19) following docs/audit/validity_audit_2026-10-19.md.

O   Open-set with behaviour-defined hold-out groups (twins held out together) and label
    cleaning v2: 6 groups x {flow, flow_ctx} x seeds {42, 1, 2, 3, 4}
C1  Context scale ablation, in-distribution binary: {flow_ctx_inv, flow_ctx_abs} x 5 seeds
C2  Context scale ablation, open-set: flow_ctx_inv x 5 seeds
Validation only; the test split is not used.

Usage: uv run python scripts/run_batch_v3.py [--only NAME ...] [--dry-run]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_batch_v1 import run  # noqa: E402

GROUPS = {
    "port21_failed_conn": ["ftp_bruteforce", "dos_slowhttptest"],
    "ssh_bruteforce": ["ssh_bruteforce"],
    "dos_http": ["dos_goldeneye", "dos_hulk", "dos_slowloris"],
    "ddos": ["ddos_loic_http", "ddos_loic_udp", "ddos_hoic"],
    "web_attack": ["web_bruteforce", "web_xss", "web_sql_injection"],
    "botnet": ["bot"],
}
SEEDS = (42, 1, 2, 3, 4)
COMMON = ["--set", "data.clean_labels=2", "--set", f"holdout_groups={json.dumps(GROUPS)}"]
OS = ["netsentinel", "train", "openset"]
BATCH = [
    *[(f"O_{fs}_s{s}", [*OS, *COMMON, "--set", f"seed={s}", "--set", f"feature_set={fs}",
                        "--set", f"experiment=v3_openset_{fs}_s{s}"])
      for fs in ("flow", "flow_ctx") for s in SEEDS],
    *[(f"C1_{fs}_s{s}", ["netsentinel", "train", "baseline", "--set", "data.clean_labels=2",
                         "--set", f"seed={s}", "--set", f"feature_set={fs}",
                         "--set", "models=[lightgbm]", "--set", f"experiment=v3_binary_{fs}_s{s}"])
      for fs in ("flow_ctx_inv", "flow_ctx_abs") for s in SEEDS],
    *[(f"C2_flow_ctx_inv_s{s}", [*OS, *COMMON, "--set", f"seed={s}", "--set",
                                 "feature_set=flow_ctx_inv",
                                 "--set", f"experiment=v3_openset_flow_ctx_inv_s{s}"])
      for s in SEEDS],
]  # fmt: skip

if __name__ == "__main__":
    sys.exit(run(BATCH, "v3"))
