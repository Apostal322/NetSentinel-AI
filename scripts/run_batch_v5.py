"""Batch v5: Mission 2 (label-free adaptation) and Mission 3 (normal-behaviour modelling).
VALIDATION / chronological evaluation splits only; test partitions untouched.

A  Adaptation source -> target (training/adapt.py; calibration sizes 100/1k/10k/50k, clean and
   unlabelled pools): IDS2018 -> UNSW with nf_flow_ctx and nf_portable_ctx, UNSW -> IDS2018
   with nf_flow_ctx; seeds 42, 1, 2.
B  Normal modelling inside one network (source = target, chronological target split, sizes
   10k / 50k): NF-UNSW, NF-IDS2018 (nf_flow_ctx) and CIC-IDS2018 (flow_ctx); seeds 42, 1, 2.

Usage: uv run --extra torch python scripts/run_batch_v5.py [--only NAME ...] [--dry-run]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_batch_v1 import run  # noqa: E402

D = {
    "ids": {"processed_dir": "data/processed/nf_cicids2018_v3", "drop_labels": ["infiltration"],
            "clean_labels": 2},
    "unsw": {"processed_dir": "data/processed/nf_unsw_nb15_v3", "drop_labels": [],
             "clean_labels": 0},
    "cic": {"processed_dir": "data/processed/ids2018_v1", "drop_labels": ["infiltration"],
            "clean_labels": 2},
}  # fmt: skip
A = ["netsentinel", "train", "adapt"]


def item(src, tgt, fs, seed, extra=()):
    return [*A, "--set", f"source={json.dumps(D[src])}", "--set", f"target={json.dumps(D[tgt])}",
            "--set", f"feature_set={fs}", "--set", f"seed={seed}",
            "--set", f"experiment=v5_{src}2{tgt}_{fs}_s{seed}", *extra]  # fmt: skip


SEEDS = (42, 1, 2)
BATCH = [
    *[(f"A_ids2unsw_{fs}_s{s}", item("ids", "unsw", fs, s))
      for fs in ("nf_flow_ctx", "nf_portable_ctx") for s in SEEDS],
    *[(f"A_unsw2ids_nf_flow_ctx_s{s}", item("unsw", "ids", "nf_flow_ctx", s)) for s in SEEDS],
    *[(f"B_{d}_{fs}_s{s}", item(d, d, fs, s, ("--set", "calibration_sizes=[10000,50000]")))
      for d, fs in (("unsw", "nf_flow_ctx"), ("ids", "nf_flow_ctx"), ("cic", "flow_ctx"))
      for s in SEEDS],
]  # fmt: skip

if __name__ == "__main__":
    sys.exit(run(BATCH, "v5"))
