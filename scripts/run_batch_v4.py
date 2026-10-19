"""Batch v4 (NetFlow v3, identical nProbe features in both datasets). VALIDATION only.

N1  In-domain retraining on NF-UNSW-NB15-v3: LightGBM x 5 feature sets x 5 seeds (+ dummy,
    logistic regression on nf_flow, seed 42).
N2  In-domain retraining on NF-CSE-CIC-IDS2018-v3 (same; infiltration dropped, cleaning v2) -
    the same 2018 traffic as the CIC CSVs through a different flow extractor.
N3  Transfer IDS2018 -> UNSW and UNSW -> IDS2018: 5 feature sets x 3 seeds.
N4  Open-set replication on NF-IDS2018 with the behaviour-defined groups: 3 sets x 3 seeds.
N5  Portable model + anomaly detector for the PCAP/Zeek application (nf_portable_ctx).

Usage: uv run python scripts/run_batch_v4.py [--only NAME ...] [--dry-run]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_batch_v1 import run  # noqa: E402
from run_batch_v3 import GROUPS  # noqa: E402

UNSW = [
    "--set",
    "data.processed_dir=data/processed/nf_unsw_nb15_v3",
    "--set",
    "data.drop_labels=[]",
    "--set",
    "data.clean_labels=0",
]
IDS = [
    "--set",
    "data.processed_dir=data/processed/nf_cicids2018_v3",
    "--set",
    "data.drop_labels=[infiltration]",
    "--set",
    "data.clean_labels=2",
]
SETS = ("nf_flow", "nf_flow_noshortcut", "nf_flow_ctx", "nf_portable", "nf_portable_ctx")
B = ["netsentinel", "train", "baseline"]
SRC = {
    "ids": {
        "processed_dir": "data/processed/nf_cicids2018_v3",
        "drop_labels": ["infiltration"],
        "clean_labels": 2,
    },
    "unsw": {
        "processed_dir": "data/processed/nf_unsw_nb15_v3",
        "drop_labels": [],
        "clean_labels": 0,
    },
}
BATCH = [
    ("N1_unsw_baselines", [*B, *UNSW, "--set", "feature_set=nf_flow",
                           "--set", "models=[dummy,logreg]", "--set", "experiment=nf_unsw_baselines"]),
    *[(f"N1_unsw_{fs}_s{s}", [*B, *UNSW, "--set", f"feature_set={fs}", "--set", f"seed={s}",
                              "--set", "models=[lightgbm]", "--set", f"experiment=nf_unsw_{fs}_s{s}"])
      for fs in SETS for s in (42, 1, 2, 3, 4)],
    ("N2_ids_baselines", [*B, *IDS, "--set", "feature_set=nf_flow",
                          "--set", "models=[dummy,logreg]", "--set", "experiment=nf_ids_baselines"]),
    *[(f"N2_ids_{fs}_s{s}", [*B, *IDS, "--set", f"feature_set={fs}", "--set", f"seed={s}",
                             "--set", "models=[lightgbm]", "--set", f"experiment=nf_ids_{fs}_s{s}"])
      for fs in SETS for s in (42, 1, 2, 3, 4)],
    *[(f"N3_{a}2{b}_{fs}_s{s}", ["netsentinel", "train", "transfer",
                                 "--set", f"source={json.dumps(SRC[a])}",
                                 "--set", f"target={json.dumps(SRC[b])}",
                                 "--set", f"feature_set={fs}", "--set", f"seed={s}",
                                 "--set", f"experiment=nf_transfer_{a}2{b}_{fs}_s{s}"])
      for a, b in (("ids", "unsw"), ("unsw", "ids")) for fs in SETS for s in (42, 1, 2)],
    *[(f"N4_ids_openset_{fs}_s{s}", ["netsentinel", "train", "openset", *IDS,
                                     "--set", f"holdout_groups={json.dumps(GROUPS)}",
                                     "--set", f"feature_set={fs}", "--set", f"seed={s}",
                                     "--set", "anomaly={kind: iforest, conditioned: false}",
                                     "--set", f"experiment=nf_ids_openset_{fs}_s{s}"])
      for fs in ("nf_flow", "nf_flow_ctx", "nf_portable_ctx") for s in (42, 1, 2)],
    ("N5_app_threat", [*B, *IDS, "--set", "feature_set=nf_portable_ctx",
                       "--set", "models=[lightgbm]", "--set", "experiment=app_threat_nf_portable_ctx"]),
    ("N5_app_anomaly", ["netsentinel", "train", "anomaly", *IDS,
                        "--set", "feature_set=nf_portable_ctx",
                        "--set", "experiment=app_anomaly_nf_portable_ctx"]),
]  # fmt: skip

if __name__ == "__main__":
    sys.exit(run(BATCH, "v4"))
