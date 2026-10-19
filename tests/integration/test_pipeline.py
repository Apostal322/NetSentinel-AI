"""End-to-end on SYNTHETIC flows: ingest -> build -> train baseline -> final evaluation.
Numbers produced here say nothing about real performance; only the plumbing is under test."""

from datetime import datetime, timedelta

import numpy as np
import pytest
import yaml

from netsentinel.cli import main
from tests.conftest import write_synthetic_ids2018_csv


def _synthetic_day(day: datetime, n: int, seed: int) -> list[dict]:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        t = day + timedelta(seconds=int(i * 3 * 3600 / n))
        attack = (i // 150) % 4 == 1  # bursts that recur over the day
        rows.append(
            {
                "Dst Port": 80 if attack else int(rng.choice([443, 53, 80, 8080])),
                "Protocol": 6,
                "Timestamp": t.strftime("%d/%m/%Y %H:%M:%S"),
                "Flow Duration": int(rng.integers(100, 2_000_000)),
                "Tot Fwd Pkts": int(rng.integers(30, 60) if attack else rng.integers(1, 20)),
                "Tot Bwd Pkts": int(rng.integers(0, 3) if attack else rng.integers(1, 20)),
                "TotLen Fwd Pkts": float(rng.integers(0, 3000)),
                "TotLen Bwd Pkts": float(rng.integers(0, 3000)),
                "SYN Flag Cnt": int(attack),
                "Flow Byts/s": "Infinity" if i % 97 == 0 else float(rng.random() * 1e4),
                "Label": "DoS attacks-Hulk" if attack else "Benign",
            }
        )
    return rows


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    raw = tmp_path / "data/raw/ids"
    raw.mkdir(parents=True)
    files = []
    for k, d in enumerate([datetime(2018, 2, 14, 9), datetime(2018, 2, 15, 9)]):
        name = f"day{k}.csv"
        write_synthetic_ids2018_csv(raw / name, _synthetic_day(d, 1200, k))
        files.append({"name": name, "day": d.strftime("%Y-%m-%d"), "size": 0, "etag": "x"})
    (tmp_path / "manifest.yaml").write_text(
        yaml.safe_dump({"name": "synthetic", "version": "t", "base_url": "http://invalid/",
                        "local_dir": "data/raw/ids", "files": files}),
        encoding="utf-8",
    )  # fmt: skip
    cfg = yaml.safe_load(open("configs/experiments/baseline_binary.yaml", encoding="utf-8"))
    cfg.update(models=["dummy", "logreg", "lightgbm"], runs_dir=str(tmp_path / "runs"))
    cfg["data"]["processed_dir"] = str(tmp_path / "processed")
    cfg["split"].update(block_minutes=10, purge_seconds=30)
    cfg["target_fpr"] = 0.01
    cfg["model_params"] = {"lightgbm": {"n_estimators": 30, "num_leaves": 15}}
    (tmp_path / "exp.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_end_to_end(workspace, capsys, monkeypatch):
    assert main(["data", "ingest", "--manifest", "manifest.yaml", "--out", "interim"]) == 0
    assert main(["features", "build", "--interim", "interim", "--out", "processed",
                 "--benign-per-day", "500", "--attack-cap", "200"]) == 0  # fmt: skip
    capsys.readouterr()
    assert main(["train", "baseline", "--config", "exp.yaml"]) == 0
    run_ids = capsys.readouterr().out.split()
    assert len(run_ids) == 3
    lgbm = workspace / "runs" / run_ids[-1]
    for f in (
        "model.joblib",
        "metrics.json",
        "split.parquet",
        "leakage_report.json",
        "error_analysis_val.json",
        "feature_importance.json",
        "env.json",
    ):
        assert (lgbm / f).exists(), f  # fmt: skip
    assert main(["evaluate", "--run", str(lgbm), "--final"]) == 0
    assert (lgbm / "test_metrics.json").exists()
    # The test split may only be used once per run.
    assert main(["evaluate", "--run", str(lgbm), "--final"]) == 2
