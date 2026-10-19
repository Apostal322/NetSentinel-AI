"""Experiment batch v2 (approved 2026-10-19): variance and temporal open-set.

A   GRU vs MLP, leave-one-family-out (seed 42)
B1  LightGBM binary, flow / flow_noshortcut / flow_ctx, seeds 1-4 (seed 42 = batch v1)
B2  LightGBM leave-one-family-out, flow / flow_ctx, seeds 1-4
B3  GRU vs MLP on seen attacks, seeds 1-4
Each seed changes the model seed AND the split seed (benign block phase of the episode split).
Validation only; the locked test split is not used.

Usage: uv run --extra torch python scripts/run_batch_v2.py [--only NAME ...] [--dry-run]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_batch_v1 import run  # noqa: E402

FAMILIES = ("bruteforce", "dos", "ddos", "web_attack", "botnet")
SEEDS = (1, 2, 3, 4)
T = ["netsentinel", "train", "temporal"]
BATCH = [
    *[(f"A_temporal_openset_{f}", [*T, "--set", f"temporal.holdout_family={f}",
                                   "--set", "experiment=temporal_openset"])
      for f in FAMILIES],
    *[(f"B1_{fs}_s{s}", ["netsentinel", "train", "baseline", "--set", f"seed={s}",
                         "--set", f"feature_set={fs}", "--set", "models=[lightgbm]",
                         "--set", f"experiment=seeds_binary_{fs}_s{s}"])
      for fs in ("flow", "flow_noshortcut", "flow_ctx") for s in SEEDS],
    *[(f"B2_{fs}_s{s}", ["netsentinel", "train", "openset", "--set", f"seed={s}",
                         "--set", f"feature_set={fs}",
                         "--set", f"experiment=seeds_openset_{fs}_s{s}"])
      for fs in ("flow", "flow_ctx") for s in SEEDS],
    *[(f"B3_temporal_s{s}", [*T, "--set", f"seed={s}", "--set", f"experiment=seeds_temporal_s{s}"])
      for s in SEEDS],
]  # fmt: skip

if __name__ == "__main__":
    sys.exit(run(BATCH, "v2"))
