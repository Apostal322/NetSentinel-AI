"""Full offline application path on SYNTHETIC data (no real-world claims):
NF-v3 zip -> ingest -> build (nf schema) -> portable model + anomaly -> bundle ->
analyze a PCAP and a Zeek conn.log -> events; and the /analyze upload endpoint."""

import hashlib
import json
import zipfile
from datetime import datetime, timedelta

import numpy as np
import pytest
import yaml
from fastapi.testclient import TestClient

from netsentinel.cli import main
from tests.unit.test_telemetry import SESSION, ZEEK_TSV, write_pcap

NF_HEADER = ("FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,"
             "IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,L7_PROTO,IN_BYTES,IN_PKTS,OUT_BYTES,OUT_PKTS,"
             "TCP_FLAGS,CLIENT_TCP_FLAGS,SERVER_TCP_FLAGS,FLOW_DURATION_MILLISECONDS,MIN_TTL,"
             "MAX_TTL,Label,Attack")  # fmt: skip


def _nf_rows(day: datetime, n: int, seed: int) -> list[str]:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        t = int((day + timedelta(seconds=i * 7200 / n)).timestamp() * 1000)
        attack = (i // 40) % 3 == 1  # bursts every ~10 min so every time segment has attacks
        if attack:  # SSH brute force: many short flows, client SYN+ACK+PSH, small replies
            vals = (t, t + 50, "10.9.9.9", 40000 + i % 1000, "10.0.0.5", 22, 6, 92,
                    int(rng.integers(300, 600)), int(rng.integers(8, 14)), 200, 6, 27, 26, 25,
                    50, 64, 64, 1, "brute_force")  # fmt: skip
        else:
            port = int(rng.choice([443, 53, 80]))
            vals = (t, t + int(rng.integers(5, 5000)), f"10.0.1.{i % 200}", 50000 + i % 9000,
                    "93.184.216.34", port, 17 if port == 53 else 6, 7,
                    int(rng.integers(100, 9000)), int(rng.integers(1, 30)),
                    int(rng.integers(100, 90000)), int(rng.integers(1, 60)),
                    0 if port == 53 else 27, 0 if port == 53 else 27, 0 if port == 53 else 27,
                    int(rng.integers(5, 5000)), 60, 64, 0, "Benign")  # fmt: skip
        rows.append(",".join(map(str, vals)))
    return rows


@pytest.fixture
def app_ws(tmp_path, monkeypatch):
    rows = _nf_rows(datetime(2018, 2, 14, 13, 0), 1500, 0) + _nf_rows(datetime(2018, 2, 15, 13, 0),
                                                                     1500, 1)  # fmt: skip
    csv = (NF_HEADER + "\n" + "\n".join(rows) + "\n").encode()
    with zipfile.ZipFile(tmp_path / "nf.zip", "w") as z:
        z.writestr("bag/data/NF-x.csv", csv)
        z.writestr("bag/manifest-sha1.txt", f"{hashlib.sha1(csv).hexdigest()} data/NF-x.csv\n")
    (tmp_path / "ingest.yaml").write_text(yaml.safe_dump({"datasets": {"syn": {
        "archive": str(tmp_path / "nf.zip"), "out_dir": str(tmp_path / "interim"),
        "utc_offset_hours": -4, "family_map": {"brute_force": "bruteforce"}}}}))  # fmt: skip
    base = yaml.safe_load(open("configs/experiments/baseline_binary.yaml", encoding="utf-8"))
    base.update(feature_set="nf_portable_ctx", models=["lightgbm"], target_fpr=0.01,
                runs_dir=str(tmp_path / "runs"), experiment="syn_nf",
                model_params={"lightgbm": {"n_estimators": 30, "num_leaves": 15}})  # fmt: skip
    base["data"].update(processed_dir=str(tmp_path / "processed"), drop_labels=[])
    base["split"].update(block_minutes=10, purge_seconds=30)
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(base))
    an = {**base, "experiment": "syn_nf_an", "max_benign_train_rows": 2000,
          "variants": [{"kind": "iforest", "conditioned": False}]}  # fmt: skip
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(an))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_transfer_between_two_nf_datasets(app_ws, capsys):
    """Source and target are two independently generated synthetic NF datasets."""
    for name, seed0 in (("src", 0), ("tgt", 7)):
        rows = _nf_rows(datetime(2018, 2, 14, 13), 1500, seed0) + _nf_rows(
            datetime(2018, 2, 15, 13), 1500, seed0 + 1)  # fmt: skip
        csv = (NF_HEADER + "\n" + "\n".join(rows) + "\n").encode()
        with zipfile.ZipFile(app_ws / f"{name}.zip", "w") as z:
            z.writestr("bag/data/NF-x.csv", csv)
        cfg = {"datasets": {name: {"archive": str(app_ws / f"{name}.zip"),
                                   "out_dir": str(app_ws / f"i_{name}"), "utc_offset_hours": 0,
                                   "family_map": {"brute_force": "bruteforce"}}}}  # fmt: skip
        (app_ws / f"{name}.yaml").write_text(yaml.safe_dump(cfg))
        assert main(["data", "ingest-nf", name, "--config", f"{name}.yaml"]) == 0
        build = ["features", "build", "--interim", f"i_{name}", "--out", f"p_{name}",
                 "--schema", "nf", "--benign-per-day", "1000", "--attack-cap", "400"]  # fmt: skip
        assert main(build) == 0
    t = yaml.safe_load(open("b.yaml"))
    t.update(experiment="syn_transfer", feature_set="nf_portable", target_fpr=0.01,
             model_params={"n_estimators": 20, "num_leaves": 7},
             source={"processed_dir": "p_src", "drop_labels": [], "clean_labels": 0},
             target={"processed_dir": "p_tgt", "drop_labels": [], "clean_labels": 0})  # fmt: skip
    (app_ws / "t.yaml").write_text(yaml.safe_dump(t))
    capsys.readouterr()
    assert main(["train", "transfer", "--config", "t.yaml"]) == 0
    run = app_ws / "runs" / capsys.readouterr().out.split()[-1]
    m = json.loads((run / "metrics.json").read_text())
    for k in ("source_val/pr_auc", "target_val/pr_auc", "target_val/recall", "target_val/fpr",
              "target_val_oracle/recall"):  # fmt: skip
        assert k in m, sorted(m)
        assert 0 <= m[k] <= 1, k


def test_offline_app_end_to_end(app_ws, capsys, monkeypatch):
    assert main(["data", "ingest-nf", "syn", "--config", "ingest.yaml"]) == 0
    build = ["features", "build", "--interim", "interim", "--out", "processed", "--schema", "nf",
             "--benign-per-day", "1000", "--attack-cap", "400"]  # fmt: skip
    assert main(build) == 0
    capsys.readouterr()
    assert main(["train", "baseline", "--config", "b.yaml"]) == 0
    threat = capsys.readouterr().out.split()[-1]
    assert main(["train", "anomaly", "--config", "a.yaml"]) == 0
    anomaly = capsys.readouterr().out.split()[-1]
    assert main(["bundle", "build", "--threat-run", f"runs/{threat}", "--anomaly-run",
                 f"runs/{anomaly}", "--out", "models"]) == 0  # fmt: skip
    bundle = capsys.readouterr().out.strip().splitlines()[-1]
    manifest = json.loads(open(f"{bundle}/manifest.json").read())
    assert manifest["feature_schema_version"] == "nf-1.0.0"

    pcap = write_pcap(app_ws / "s.pcap", SESSION)
    assert main(["analyze", str(pcap), "--bundle", bundle, "--utc-offset", "-4",
                 "--events-db", "ev.sqlite", "--out", "pcap.json"]) == 0  # fmt: skip
    s = json.loads((app_ws / "pcap.json").read_text())
    assert s["kind"] == "pcap" and s["flows"] == 2 and s["parse"]["parsed"] == 8
    assert sum(s["verdicts"].values()) == 2
    conn = app_ws / "conn.log"
    conn.write_text(ZEEK_TSV, encoding="utf-8")
    assert main(["analyze", str(conn), "--bundle", bundle, "--events-db", "ev.sqlite",
                 "--out", "zeek.json"]) == 0  # fmt: skip
    z = json.loads((app_ws / "zeek.json").read_text())
    assert z["kind"] == "zeek" and z["flows"] == 2

    from netsentinel.api.app import Settings, create_app

    monkeypatch.setenv("NETSENTINEL_ADMIN_TOKEN", "tok-abc")
    client = TestClient(create_app(Settings(bundle_dir=bundle, events_db=app_ws / "ev.sqlite",
                                            max_upload_bytes=4096)))  # fmt: skip
    hdr = {"x-admin-token": "tok-abc"}
    files = {"file": ("s.pcap", pcap.read_bytes(), "application/octet-stream")}
    assert client.post("/analyze", files=files).status_code == 401
    r = client.post("/analyze", files=files, headers=hdr, params={"utc_offset": -4})
    assert r.status_code == 200 and r.json()["flows"] == 2 and r.json()["source"] == "s.pcap"
    big = {"file": ("big.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 10_000, "application/octet-stream")}
    assert client.post("/analyze", files=big, headers=hdr).status_code == 413
    junk = {"file": ("x.bin", b"\x00\x01garbage", "application/octet-stream")}
    assert client.post("/analyze", files=junk, headers=hdr).status_code in (200, 422)
    srcs = {e["source"] for e in client.get("/events", params={"limit": 50}).json()}
    assert {"pcap:s.pcap", "zeek:conn.log"} <= srcs
