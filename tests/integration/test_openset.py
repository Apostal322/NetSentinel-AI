"""Open-set protocol on SYNTHETIC flows: held-out group labels never reach training."""

import json
from datetime import datetime

import pytest
import yaml

from netsentinel.cli import main
from tests.conftest import write_synthetic_ids2018_csv
from tests.integration.test_pipeline import _synthetic_day


@pytest.fixture
def ws(tmp_path, monkeypatch):
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
    cfg = yaml.safe_load(open("configs/experiments/openset.yaml", encoding="utf-8"))
    cfg["data"].update(processed_dir=str(tmp_path / "processed"), clean_labels=2)
    cfg["split"].update(block_minutes=10, purge_seconds=30)
    cfg.update(runs_dir=str(tmp_path / "runs"), target_fpr=0.01, max_benign_train_rows=500,
               holdout_groups={"ssh_only": ["ssh_bruteforce"]},
               model_params={"n_estimators": 20, "num_leaves": 7})  # fmt: skip
    (tmp_path / "o.yaml").write_text(yaml.safe_dump(cfg))
    monkeypatch.chdir(tmp_path)
    assert main(["data", "ingest", "--manifest", "m.yaml", "--out", "interim"]) == 0
    assert main(["features", "build", "--interim", "interim", "--out", "processed",
                 "--benign-per-day", "500", "--attack-cap", "200"]) == 0  # fmt: skip
    return tmp_path


def test_holdout_group_is_excluded_and_evaluated(ws, capsys):
    capsys.readouterr()
    assert main(["train", "openset", "--config", "o.yaml"]) == 0
    run_id = capsys.readouterr().out.split()[-1]
    run = ws / "runs" / run_id
    assert run_id.endswith("_without_ssh_only")
    assert json.loads((run / "holdout_group.json").read_text()) == {
        "name": "ssh_only", "labels": ["ssh_bruteforce"]}  # fmt: skip
    per_label = json.loads((run / "per_label_unseen.json").read_text())
    assert {r["label"] for r in per_label} == {"ssh_bruteforce"}
    m = json.loads((run / "metrics.json").read_text())
    assert m["unseen_rows"] > 0 and 0 <= m["supervised_recall"] <= 1
