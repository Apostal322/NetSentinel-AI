"""Serving path on SYNTHETIC data: train -> bundle -> engine -> replay -> event store -> API.
Verifies plumbing, contracts and safety checks; says nothing about real detection quality."""

import json
import shutil

import pytest
import yaml
from fastapi.testclient import TestClient

from netsentinel.cli import main
from tests.integration.test_pipeline import workspace  # noqa: F401 - pytest fixture


@pytest.fixture
def trained(workspace, capsys):  # noqa: F811
    assert main(["data", "ingest", "--manifest", "manifest.yaml", "--out", "interim"]) == 0
    assert main(["features", "build", "--interim", "interim", "--out", "processed",
                 "--benign-per-day", "500", "--attack-cap", "200"]) == 0  # fmt: skip
    exp = yaml.safe_load((workspace / "exp.yaml").read_text())
    exp.update(models=["lightgbm"])
    (workspace / "exp.yaml").write_text(yaml.safe_dump(exp))
    an = {**exp, "experiment": "anomaly", "max_benign_train_rows": 2000,
          "variants": [{"kind": "iforest", "conditioned": False}], "target_fpr": 0.05}  # fmt: skip
    (workspace / "an.yaml").write_text(yaml.safe_dump(an))
    capsys.readouterr()
    assert main(["train", "baseline", "--config", "exp.yaml"]) == 0
    threat = capsys.readouterr().out.split()[-1]
    assert main(["train", "anomaly", "--config", "an.yaml"]) == 0
    anomaly = capsys.readouterr().out.split()[-1]
    assert main(["bundle", "build", "--threat-run", f"runs/{threat}", "--anomaly-run",
                 f"runs/{anomaly}", "--out", "models"]) == 0  # fmt: skip
    bundle = capsys.readouterr().out.strip().splitlines()[-1]
    return workspace, bundle


def test_bundle_replay_store_and_api(trained, monkeypatch):
    ws, bundle = trained
    from netsentinel.api.app import Settings, create_app
    from netsentinel.inference.engine import Engine
    from netsentinel.storage.events import EventStore
    from netsentinel.streaming.replay import ReplayConfig, Replayer

    engine = Engine(bundle)
    store = EventStore(ws / "events.sqlite")
    status = Replayer(engine, store).run(ReplayConfig(path="interim/2018-02-14.parquet",
                                                      max_events=300, batch_size=100))  # fmt: skip
    assert status.state == "finished" and status.processed == 300
    # Replaying again is idempotent (deterministic observation ids).
    Replayer(engine, store).run(ReplayConfig(path="interim/2018-02-14.parquet", max_events=300))
    assert sum(store.summary()["counts"].values()) == 300
    ev = store.query(limit=5)[0]
    assert ev["model_versions"]["bundle"] == engine.bundle_id
    assert 0 <= ev["anomaly"]["score"] <= 100
    assert ev["threat"]["probability"] is None or 0 <= ev["threat"]["probability"] <= 1
    assert ev["anomaly"]["calibrated_probability"] is False

    monkeypatch.setenv("NETSENTINEL_ADMIN_TOKEN", "test-token-123")
    client = TestClient(create_app(Settings(bundle_dir=bundle, events_db=ws / "events.sqlite",
                                            replay_dir=ws / "interim")))  # fmt: skip
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").status_code == 200
    assert client.get("/models").json()["bundle_id"] == engine.bundle_id
    flow = {"timestamp": "2018-02-14T10:00:00", "dst_port": 80, "protocol": 6,
            "flow_duration": 1000, "features": {"tot_fwd_pkts": 40, "tot_bwd_pkts": 0}}  # fmt: skip
    r = client.post("/predict/flow", json=flow)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] in {"benign", "unusual", "suspicious", "attack"}
    assert "fwd_pkt_len_max" in body["missing_features"]  # not supplied -> reported
    # Validation: unknown fields, bad ports and oversized batches are rejected.
    assert client.post("/predict/flow", json={**flow, "evil": 1}).status_code == 422
    assert client.post("/predict/flow", json={**flow, "dst_port": 70000}).status_code == 422
    assert client.post("/predict/batch", json={"flows": [flow] * 1001}).status_code == 422
    assert len(client.post("/predict/batch", json={"flows": [flow] * 3}).json()) == 3
    assert client.get("/events", params={"limit": 2}).status_code == 200
    assert client.get("/events", params={"verdict": "nonsense"}).status_code == 422
    assert client.get("/events/does-not-exist").status_code == 404
    assert client.get(f"/events/{ev['observation_id']}").status_code == 200
    # Admin: replay requires the token and only accepts ingested days.
    assert client.post("/replay/start", json={"day": "2018-02-14"}).status_code == 401
    hdr = {"x-admin-token": "test-token-123"}
    assert client.post("/replay/start", json={"day": "../../etc"}, headers=hdr).status_code == 422
    assert client.post("/replay/start", json={"day": "2019-01-01"}, headers=hdr).status_code == 404


def test_tampered_bundle_is_refused(trained, tmp_path):
    _, bundle = trained
    from netsentinel.inference.bundle import load_bundle

    copy = tmp_path / "b"
    shutil.copytree(bundle, copy)
    with (copy / "bundle.joblib").open("ab") as fh:
        fh.write(b"tamper")
    with pytest.raises(RuntimeError, match="hash mismatch"):
        load_bundle(copy)
    manifest = json.loads((copy / "manifest.json").read_text())
    assert manifest["feature_schema_version"]
