"""Run ledger: one folder per run (config, environment, metrics, artifacts) plus an
append-only `runs/ledger.csv` for comparing runs at a glance."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata as md
import json
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

TRACKED_PACKAGES = [
    "numpy",
    "pandas",
    "polars",
    "pyarrow",
    "scikit-learn",
    "lightgbm",
    "pandera",
    "torch",
]


def git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        sha = out.stdout.strip() or "no-git"
        return f"{sha}-dirty" if dirty and sha != "no-git" else sha
    except (OSError, subprocess.SubprocessError):
        return "no-git"


def package_versions() -> dict[str, str]:
    found = {}
    for name in TRACKED_PACKAGES:
        try:
            found[name] = md.version(name)
        except md.PackageNotFoundError:
            pass
    return found


def file_sha256(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


class Run:
    """One experiment run: `run = Run(cfg, "lgbm"); run.log_metrics({...}); run.finish()`."""

    def __init__(self, cfg: dict[str, Any], name: str | None = None):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.name = name or cfg.get("experiment", "run")
        self.id = f"{stamp}_{self.name}"
        self.root = Path(cfg.get("runs_dir", "runs"))
        self.dir = self.root / self.id
        suffix = 1
        while self.dir.exists():  # two runs in the same second
            self.dir = self.root / f"{self.id}-{suffix}"
            suffix += 1
        self.id = self.dir.name
        self.dir.mkdir(parents=True)
        self.cfg = cfg
        self.metrics: dict[str, float] = {}
        (self.dir / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), "utf-8")
        self.env = {
            "git": git_sha(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "packages": package_versions(),
        }
        (self.dir / "env.json").write_text(json.dumps(self.env, indent=2), "utf-8")

    def log_metrics(self, metrics: dict[str, float], prefix: str = "") -> None:
        for key, value in metrics.items():
            self.metrics[f"{prefix}{key}"] = float(value)

    def save_json(self, name: str, obj: Any) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(obj, indent=2, default=str), "utf-8")
        return path

    def finish(self, notes: str = "") -> Path:
        self.save_json("metrics.json", self.metrics)
        row = {
            "run_id": self.id,
            "git": self.env["git"],
            "experiment": self.cfg.get("experiment", ""),
            "model": self.name,
            "seed": self.cfg.get("seed", ""),
            "metrics": json.dumps(self.metrics, sort_keys=True),
            "notes": notes,
        }
        ledger = self.root / "ledger.csv"
        new = not ledger.exists()
        with ledger.open("a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(row))
            if new:
                writer.writeheader()
            writer.writerow(row)
        return self.dir
