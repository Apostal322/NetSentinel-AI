"""Temporal trainer on SYNTHETIC flows (CPU): normal and leave-one-family-out modes.
Checks plumbing and the open-set protocol, not model quality."""

import json
from datetime import datetime

import pytest
import yaml

pytest.importorskip("torch")

from netsentinel.cli import main  # noqa: E402
from tests.conftest import write_synthetic_ids2018_csv  # noqa: E402
from tests.integration.test_pipeline import _synthetic_day  # noqa: E402


@pytest.fixture
def temporal_ws(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    raw.mkdir()
    files = []
    for k, (d, label, port) in enumerate([
        (datetime(2018, 2, 14, 9), "DoS attacks-Hulk", 80),
        (datetime(2018, 2, 15, 9), "SSH-Bruteforce", 22),
    ]):  # fmt: skip
        rows = _synthetic_day(d, 1200, k)
        for r in rows:
            if r["Label"] != "Benign":
                r["Label"], r["Dst Port"] = label, port
        write_synthetic_ids2018_csv(raw / f"d{k}.csv", rows)
        files.append({"name": f"d{k}.csv", "day": d.strftime("%Y-%m-%d"), "size": 0, "etag": "x"})
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(
        {"name": "s", "version": "t", "base_url": "http://invalid/", "local_dir": "raw",
         "files": files}))  # fmt: skip
    cfg = yaml.safe_load(open("configs/experiments/temporal.yaml", encoding="utf-8"))
    cfg["data"].update(
        processed_dir=str(tmp_path / "processed"), interim_dir=str(tmp_path / "interim")
    )
    cfg["split"].update(block_minutes=10, purge_seconds=30)
    cfg["temporal"].update(length=4, max_epochs=2, gpu=False, batch_size=128)
    cfg.update(runs_dir=str(tmp_path / "runs"), target_fpr=0.01)
    (tmp_path / "t.yaml").write_text(yaml.safe_dump(cfg))
    monkeypatch.chdir(tmp_path)
    assert main(["data", "ingest", "--manifest", "m.yaml", "--out", "interim"]) == 0
    assert main(["features", "build", "--interim", "interim", "--out", "processed",
                 "--benign-per-day", "500", "--attack-cap", "200"]) == 0  # fmt: skip
    return tmp_path


@pytest.mark.slow  # ~90 s on CPU; run with `pytest -m slow`
def test_temporal_normal_and_holdout(temporal_ws, capsys):
    capsys.readouterr()
    assert main(["train", "temporal", "--config", "t.yaml"]) == 0
    assert len(capsys.readouterr().out.split()) == 2  # mlp + gru
    assert main(["train", "temporal", "--config", "t.yaml",
                 "--set", "temporal.holdout_family=bruteforce"]) == 0  # fmt: skip
    run_ids = capsys.readouterr().out.split()
    assert all(r.endswith("_without_bruteforce") for r in run_ids)
    m = json.loads((temporal_ws / "runs" / run_ids[-1] / "metrics.json").read_text())
    assert m["unseen_rows"] > 0
    assert 0 <= m["supervised_recall"] <= 1 and 0 <= m["supervised_benign_val_fpr"] <= 1
