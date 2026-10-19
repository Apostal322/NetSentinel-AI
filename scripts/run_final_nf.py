"""Final NF-v3 evaluation (Mission 5): runs the procedures frozen in
docs/experiments/final_preregistration_nf.md on the intersection test partition. One-shot:
each experiment refuses to run again once reports/final/<experiment>.json exists.

Usage: uv run --extra torch python scripts/run_final_nf.py [--only NAME ...] [--dry-run]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_batch_v1 import run  # noqa: E402
from run_batch_v5 import D  # noqa: E402

EPISODE = {"protocol": "episode", "block_minutes": 30, "purge_seconds": 150,
           "fractions": [0.6, 0.2, 0.2]}  # fmt: skip


def item(src, tgt, fs, seed):
    return ["netsentinel", "train", "adapt", "--set", f"source={json.dumps(D[src])}",
            "--set", f"target={json.dumps(D[tgt])}", "--set", f"feature_set={fs}",
            "--set", f"seed={seed}", "--set", f"experiment=final_{src}2{tgt}_{fs}_s{seed}",
            "--set", "evaluation=final_test", "--set", "noshortcut_view=true",
            "--set", f"final_episode_split={json.dumps(EPISODE)}",
            "--set", "calibration_sizes=[1000,10000,50000]"]  # fmt: skip


SETTINGS = (("unsw", "unsw", "nf_flow_ctx"), ("ids", "ids", "nf_flow_ctx"),
            ("ids", "unsw", "nf_flow_ctx"), ("ids", "unsw", "nf_portable_ctx"),
            ("unsw", "ids", "nf_flow_ctx"))  # fmt: skip
BATCH = [(f"F_{s}2{t}_{fs}_s{seed}", item(s, t, fs, seed))
         for s, t, fs in SETTINGS for seed in (42, 1, 2)]  # fmt: skip

if __name__ == "__main__":
    sys.exit(run(BATCH, "final_nf"))
