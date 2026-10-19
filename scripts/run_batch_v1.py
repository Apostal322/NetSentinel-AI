"""Experiment batch v1 (Phases C-E): every experiment runs in its OWN process, sequentially
(8 GB RAM rule), with wall time and peak memory recorded to runs/batch_v1.jsonl.

Usage: uv run python scripts/run_batch_v1.py [--only NAME ...] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

B = ["netsentinel", "train", "baseline"]
BASE5 = "models=[dummy,logreg,random_forest,hist_gb,lightgbm]"
TWO = "models=[logreg,lightgbm]"
BATCH: list[tuple[str, list[str]]] = [
    # Experiment 1: binary baselines, default feature set and leakage-aware split.
    ("E1_binary_flow", [*B, "--set", BASE5,
                        "--set", "model_params={random_forest: {n_estimators: 100}}"]),
    # Feature ablations (H1/H3 and shortcut check).
    *[(f"E1_binary_{fs}", [*B, "--set", f"feature_set={fs}", "--set", TWO,
                           "--set", f"experiment=baseline_binary_{fs}"])
      for fs in ("flow_noshortcut", "flow_port", "flow_ctx5", "flow_ctx", "ctx_only")],
    # H5: naive random and random-block splits vs the episode protocol.
    *[(f"H5_{proto}_{fs}", [*B, "--set", f"split.protocol={proto}", "--set", f"feature_set={fs}",
                            "--set", "models=[lightgbm]",
                            "--set", f"experiment=h5_{proto}_{fs}"]
       + (["--set", "split.block_minutes=15", "--set", "split.purge_seconds=150"]
          if proto == "blocked" else []))
      for proto in ("random", "blocked") for fs in ("flow", "flow_ctx")],
    # Experiment 5: attack type (merged label) and family, multiclass.
    *[(f"E5_{task}_{fs}", [*B, "--set", f"task={task}", "--set", f"feature_set={fs}",
                           "--set", "models=[lightgbm]",
                           "--set", f"experiment=multiclass_{task}_{fs}"])
      for task in ("label", "family") for fs in ("flow", "flow_ctx")],
    # Experiment 3 / H2: anomaly, global vs service-conditioned.
    *[(f"E3_anomaly_{fs}", ["netsentinel", "train", "anomaly", "--set", f"feature_set={fs}",
                            "--set", f"experiment=anomaly_{fs}"])
      for fs in ("flow", "flow_ctx")],
    # Experiment 6 / H4: leave-one-family-out.
    *[(f"E6_openset_{fs}", ["netsentinel", "train", "openset", "--set", f"feature_set={fs}",
                            "--set", f"experiment=openset_{fs}"])
      for fs in ("flow", "flow_ctx")],
]  # fmt: skip


def main() -> int:
    return run(BATCH, "v1")


def run(batch: list[tuple[str, list[str]]], tag: str) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    log_dir = Path(f"runs/batch_{tag}_logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    ledger = Path(f"runs/batch_{tag}.jsonl")
    for name, cmd in batch:
        if args.only and name not in args.only:
            continue
        print(f"[{time.strftime('%H:%M:%S')}] {name}: {' '.join(cmd)}", flush=True)
        if args.dry_run:
            continue
        t0 = time.time()
        with (log_dir / f"{name}.log").open("w", encoding="utf-8") as fh:
            proc = subprocess.Popen(
                [sys.executable, "-m", "netsentinel.cli", *cmd[1:]], stdout=fh, stderr=fh
            )
            code = proc.wait()
        # The child logs its own peak (the venv python.exe on Windows is a launcher process).
        found = re.findall(r"peak_rss_mb=([\d.]+)", (log_dir / f"{name}.log").read_text("utf-8"))
        peak = float(found[-1]) if found else None
        rec = {"name": name, "exit": code, "seconds": round(time.time() - t0, 1),
               "peak_rss_mb": round(peak, 1) if peak else None,
               "log": str(log_dir / f"{name}.log")}  # fmt: skip
        with ledger.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(f"    -> exit={code} {rec['seconds']}s peak_rss={rec['peak_rss_mb']} MB", flush=True)
        if code != 0:
            print("    stopping batch on failure", flush=True)
            return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
