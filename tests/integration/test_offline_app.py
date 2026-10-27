"""Full offline application path on SYNTHETIC data (no real-world claims):
NF-v3 zip -> ingest -> build (nf schema) -> portable model + anomaly -> bundle ->
analyze a PCAP and a Zeek conn.log -> events; and the /analyze upload endpoint."""

import hashlib
import json
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

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


def test_adapt_stage_on_synthetic_domains(app_ws, capsys):
    """Label-free adaptation protocol runs end to end; outputs are well-formed."""
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
    repo = Path(__file__).resolve().parents[2]
    cfg = yaml.safe_load((repo / "configs/experiments/adapt_nf.yaml").read_text(encoding="utf-8"))
    cfg.update(runs_dir=str(app_ws / "runs"), target_fpr=0.01, calibration_sizes=[100, 300],
               detectors=["robust_z", "iforest"], feature_set="nf_portable_ctx",
               model_params={"n_estimators": 20, "num_leaves": 7},
               source={"processed_dir": "p_src", "drop_labels": [], "clean_labels": 0},
               target={"processed_dir": "p_tgt", "drop_labels": [], "clean_labels": 0})  # fmt: skip
    cfg["source_split"].update(block_minutes=10, purge_seconds=30)
    cfg["target_split"].update(purge_seconds=30)
    (app_ws / "ad.yaml").write_text(yaml.safe_dump(cfg))
    capsys.readouterr()
    assert main(["train", "adapt", "--config", "ad.yaml"]) == 0
    run = app_ws / "runs" / capsys.readouterr().out.split()[-1]
    res = json.loads((run / "adapt_results.json").read_text())
    assert set(res["calibration"]) == {"clean_100", "clean_300", "unlabelled_100", "unlabelled_300"}
    clean = res["calibration"]["clean_300"]
    assert clean["contamination"] == 0.0  # clean pool contains benign rows only
    for meth in ("source_model_target_threshold", "normalized_target_threshold",
                 "target_iforest_all", "target_robust_z_ctx"):  # fmt: skip
        assert 0 <= clean[meth]["fpr"] <= 1 and 0 <= clean[meth]["recall"] <= 1


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
    # inference fallback: no calibration / classifier loaded -> explicit statuses
    assert s["behavior_status"] == {"not_calibrated": 2} and s["app_status"] == {"no_classifier": 2}
    # Phase 8e: without a calibration a quiet flow is never "normal"
    # (1 of 10 packets in the fixture is a truncated IPv4 packet -> degraded telemetry)
    assert s["normality_supported_share"] == 0 and s["telemetry_health"] == "parse_errors"
    assert "normal_valid_baseline" not in s["assessment_states"]
    assert main(["analyze", str(pcap), "--bundle", bundle, "--calibration", "missing-dir"]) == 2
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

    # ---- Phase 6: local calibration + application classifier + evidence-aware verdicts
    zeek_long(app_ws / "cal.log", hours=2.0, seed=1)
    zeek_long(app_ws / "mon.log", hours=1.0, seed=2, start=1_600_007_200, scan_at=1800)
    assert (
        main(["calibrate", "cal.log", "--mode", "vetted_benign", "--out", "cal"]) == 2
    )  # no assert
    capsys.readouterr()
    assert main(["calibrate", "cal.log", "--mode", "vetted_benign", "--assert-benign",
                 "--bundle", bundle, "--out", "cal"]) == 0  # fmt: skip
    cal_dir = capsys.readouterr().out.strip().splitlines()[-1]
    cal_mf = json.loads(open(f"{cal_dir}/manifest.json").read())
    assert cal_mf["status"] == "baseline_ready" and cal_mf["mode"] == "vetted_benign"
    assert "supported" in cal_mf["threat_model_domain_check"]
    app_dir = tiny_classifier(app_ws / "appintel")
    args = ["analyze", "mon.log", "--bundle", bundle, "--calibration", cal_dir, "--appid",
            str(app_dir), "--events-db", "ev.sqlite", "--out", "mon.json"]  # fmt: skip
    assert main(args) == 0
    m = json.loads((app_ws / "mon.json").read_text())
    assert m["flows"] > 100 and set(m["behavior_status"]) <= {"normal", "anomalous",
                                                              "insufficient_history"}  # fmt: skip
    assert m["behavior_windows"]["device"]["anomalous"] >= 1  # the injected scan
    assert m["assessment_states"].get("anomalous_behavior", 0) >= 1
    assert "calibration_validity_shadow" not in m  # Phase 8f shift test is opt-in only
    assert main([*args[:-1], "mon_shadow.json", "--validity-shadow"]) == 0
    ms = json.loads((app_ws / "mon_shadow.json").read_text())
    assert ms["calibration_validity_shadow"]["adopted"] is False
    assert ms["verdicts"] == m["verdicts"] and ms["assessment_states"] == m["assessment_states"]
    assert sum(m["assessment_states"].values()) == m["flows"]
    assert m["threat_mode"] == "unverified_domain"  # Phase 7 default: never escalate
    assert m["threat_policy"] == "unverified" and "suspicious" not in m["verdicts"]
    assert set(m["app_status"]) <= {"predicted", "low_confidence", "out_of_distribution",
                                    "missing_features", "unsupported_protocol"}  # fmt: skip
    top = m["top_behavior_anomalies"][0]
    assert top["behavior"]["anomaly_score_type"] == "normalized_non_probability"
    assert top["behavior"]["window_end"] is not None
    assert top["application"]["application_identity"] is None
    assert top["verdict"] in ("unusual", "suspicious", "attack")
    # an anomaly alone never yields 'suspicious'
    for ev in m["top_behavior_anomalies"]:
        if ev["threat_status"] in ("unverified_domain", "unsupported_domain", "no_evidence"):
            assert ev["verdict"] == "unusual"
    assert main(["analyze", "mon.log", "--bundle", bundle, "--calibration", cal_dir,
                 "--threat-policy", "unsupported", "--out", "mon2.json"]) == 0  # fmt: skip
    m2 = json.loads((app_ws / "mon2.json").read_text())
    assert set(m2["threat_status"]) == {"unsupported_domain"}
    assert "suspicious" not in m2["verdicts"] and "attack" not in m2["verdicts"]
    from netsentinel.storage.events import EventStore

    beh = EventStore(app_ws / "ev.sqlite").behavior(anomalous_only=True)
    assert beh and all(b["anomalous"] for b in beh)
    api = TestClient(create_app(Settings(bundle_dir=bundle, events_db=app_ws / "ev.sqlite",
                                         calibration_dir=cal_dir, appid_dir=app_dir)))  # fmt: skip
    mods = api.get("/models").json()
    assert mods["calibration"]["calibration_id"] in cal_dir
    from netsentinel.appintel.model import APP_SCHEMA_VERSION

    assert mods["application_classifier"]["schema_version"] == APP_SCHEMA_VERSION
    b = api.get("/behavior", params={"anomalous_only": True, "level": "device"}).json()
    assert b and b[0]["level"] == "device"
    assert api.get("/behavior", params={"level": "nonsense"}).status_code == 422
    r = api.post("/analyze", files={"file": ("m.log", (app_ws / "mon.log").read_bytes())},
                 headers=hdr)  # fmt: skip
    assert r.status_code == 200 and r.json()["behavior_windows"]["device"]["anomalous"] >= 1
    # cold start: too little history -> insufficient_data, never 'benign'
    zeek_long(app_ws / "short.log", hours=0.1, seed=3)
    assert main(["calibrate", "short.log", "--out", "cal"]) == 0
    short_dir = capsys.readouterr().out.strip().splitlines()[-1]
    assert main(["analyze", "mon.log", "--bundle", bundle, "--calibration", short_dir,
                 "--threat-policy", "unsupported", "--out", "mon3.json"]) == 0  # fmt: skip
    m3 = json.loads((app_ws / "mon3.json").read_text())
    assert set(m3["verdicts"]) == {"insufficient_data"}
    # corrupted calibration is refused
    with open(f"{cal_dir}/profile.joblib", "ab") as fh:
        fh.write(b"x")
    assert main(["analyze", "mon.log", "--bundle", bundle, "--calibration", cal_dir]) == 2
    bad = TestClient(create_app(Settings(bundle_dir=bundle, events_db=app_ws / "ev.sqlite",
                                         calibration_dir=cal_dir)))  # fmt: skip
    assert bad.get("/ready").status_code == 503  # corrupted calibration is not served


def zeek_long(
    path: Path, hours: float, seed: int, start: int = 1_600_000_000, scan_at: int | None = None
) -> Path:
    """Synthetic Zeek conn.log: 3 hosts doing web/DNS; optional 60 s port scan from host 1."""
    rng = np.random.default_rng(seed)
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
              "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "history",
              "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]  # fmt: skip
    head = "#separator \\x09\n#fields\t" + "\t".join(fields) + "\n"
    rows = []
    services = [(443, "tcp", "ssl"), (53, "udp", "dns"), (80, "tcp", "http")]
    for t in range(0, int(hours * 3600), 2):
        port, proto, svc = services[rng.choice(3, p=[0.6, 0.3, 0.1])]
        host = f"10.0.0.{rng.integers(1, 4)}"
        rows.append([f"{start + t + rng.uniform(0, 2):.3f}", f"C{t}", host,
                     str(40000 + t % 20000), f"93.184.216.{rng.integers(1, 20)}", str(port), proto,
                     svc, f"{rng.uniform(0.01, 3):.3f}", "300", "5000", "SF", "ShADadFf", "6",
                     "620", "8", "5400"])  # fmt: skip
    if scan_at is not None:
        for i in range(800):
            rows.append([f"{start + scan_at + i * 0.075:.3f}", f"S{i}", "10.0.0.1", "50000",
                         f"172.16.{i // 200}.{i % 200}", str(1000 + i), "tcp", "-", "0.0", "0",
                         "0", "S0", "S", "1", "60", "0", "0"])  # fmt: skip
    body = "\n".join("\t".join(r) for r in rows)
    path.write_text(head + body + "\n", encoding="utf-8")
    return path


def tiny_classifier(out: Path) -> Path:
    """A small AppClassifier artifact trained on synthetic portable features (software test
    only - says nothing about real classification quality)."""
    from lightgbm import LGBMClassifier

    from netsentinel.appintel.model import AppClassifier, save_classifier
    from netsentinel.features.nf_schema import NF_PORTABLE_COLUMNS

    feats = [*NF_PORTABLE_COLUMNS, "proto_tcp", "proto_udp", "proto_other", "port_class"]
    rng = np.random.default_rng(0)
    X = rng.random((300, len(feats))).astype(np.float32) * 1000  # noqa: N806
    y = np.array(["dns", "tls", "http"])[rng.integers(0, 3, 300)]
    m = LGBMClassifier(n_estimators=10, num_leaves=7, verbose=-1).fit(X, y)
    clf = AppClassifier(model=m, features=feats, classes=[str(c) for c in m.classes_],
                        feature_set="portable", confidence_threshold=0.5,
                        ood_low=np.zeros(len(feats)),
                        ood_high=np.full(len(feats), 1e9))  # fmt: skip
    return save_classifier(clf, out)


def test_appid_stage_on_synthetic_flows(app_ws, capsys):
    """Application identification runs end to end on benign flows; test rows are excluded."""
    l7 = {"443": "91", "53": "5", "80": "7"}
    rows = []
    for day, seed in ((datetime(2018, 2, 14, 13), 3), (datetime(2018, 2, 15, 13), 4)):
        for r in _nf_rows(day, 1500, seed):
            f = r.split(",")
            f[7] = l7.get(f[5], f[7])
            rows.append(",".join(f))
    csv = (NF_HEADER + "\n" + "\n".join(rows) + "\n").encode()
    with zipfile.ZipFile(app_ws / "ap.zip", "w") as z:
        z.writestr("bag/data/NF-x.csv", csv)
    cfg = {"datasets": {"ap": {"archive": str(app_ws / "ap.zip"), "out_dir": "i_ap",
                               "utc_offset_hours": 0,
                               "family_map": {"brute_force": "bruteforce"}}}}  # fmt: skip
    (app_ws / "ap.yaml").write_text(yaml.safe_dump(cfg))
    assert main(["data", "ingest-nf", "ap", "--config", "ap.yaml"]) == 0
    assert main(["features", "build", "--interim", "i_ap", "--out", "p_ap", "--schema", "nf",
                 "--benign-per-day", "1000", "--attack-cap", "400"]) == 0  # fmt: skip
    repo = Path(__file__).resolve().parents[2]
    cfg = yaml.safe_load((repo / "configs/experiments/appid_nf.yaml").read_text(encoding="utf-8"))
    cfg.update(runs_dir=str(app_ws / "runs"), max_rows=5000,
               lightgbm_params={"n_estimators": 20, "num_leaves": 7},
               datasets={"ap": {"processed_dir": "p_ap", "interim_dir": "i_ap",
                                "drop_labels": [], "clean_labels": 0}})  # fmt: skip
    cfg["split"].update(block_minutes=10, purge_seconds=30)
    (app_ws / "appid.yaml").write_text(yaml.safe_dump(cfg))
    capsys.readouterr()
    assert main(["train", "appid", "--config", "appid.yaml"]) == 0
    run = app_ws / "runs" / capsys.readouterr().out.split()[-1]
    res = json.loads((run / "appid_results.json").read_text())["datasets"]["ap"]
    assert set(res["classes"]) == {"dns", "http", "tls"}
    assert res["rows"]["val_a"] > 0 and res["rows"]["val_b"] > 0
    assert res["models"]["port_lookup"]["accuracy"] == 1.0  # L7 is a function of the port here
    for m in ("majority", "port_lookup", "lgbm_shape_noport", "lgbm_shape_portclass"):
        assert 0 <= res["models"][m]["macro_f1"] <= 1
    assert "selective" in res["models"]["lgbm_shape_noport"]


def test_adapt_final_mode_is_one_shot(app_ws, capsys):
    """Final-test mode evaluates chronological-test rows that are also episode-test rows, adds
    block-bootstrap CIs, and refuses a second run of the same experiment."""
    rows = _nf_rows(datetime(2018, 2, 14, 13), 1500, 11) + _nf_rows(datetime(2018, 2, 15, 13),
                                                                   1500, 12)  # fmt: skip
    csv = (NF_HEADER + "\n" + "\n".join(rows) + "\n").encode()
    with zipfile.ZipFile(app_ws / "f.zip", "w") as z:
        z.writestr("bag/data/NF-x.csv", csv)
    (app_ws / "f.yaml").write_text(yaml.safe_dump({"datasets": {"f": {
        "archive": str(app_ws / "f.zip"), "out_dir": "i_f", "utc_offset_hours": 0,
        "family_map": {"brute_force": "bruteforce"}}}}))  # fmt: skip
    assert main(["data", "ingest-nf", "f", "--config", "f.yaml"]) == 0
    assert main(["features", "build", "--interim", "i_f", "--out", "p_f", "--schema", "nf",
                 "--benign-per-day", "1000", "--attack-cap", "400"]) == 0  # fmt: skip
    repo = Path(__file__).resolve().parents[2]
    cfg = yaml.safe_load((repo / "configs/experiments/adapt_nf.yaml").read_text(encoding="utf-8"))
    ds = {"processed_dir": "p_f", "drop_labels": [], "clean_labels": 0}
    cfg.update(runs_dir=str(app_ws / "runs"), target_fpr=0.01, calibration_sizes=[300],
               detectors=["robust_z"], feature_set="nf_portable_ctx", source=ds, target=ds,
               model_params={"n_estimators": 20, "num_leaves": 7}, evaluation="final_test",
               final_dir=str(app_ws / "final"), noshortcut_view=True, experiment="fin")  # fmt: skip
    cfg["source_split"].update(block_minutes=10, purge_seconds=30)
    cfg["target_split"].update(purge_seconds=30)
    cfg["final_episode_split"] = dict(cfg["source_split"])
    (app_ws / "fin.yaml").write_text(yaml.safe_dump(cfg))
    assert main(["train", "adapt", "--config", "fin.yaml"]) == 0
    res = json.loads((app_ws / "final" / "fin.json").read_text())
    assert res["evaluation"] == "final_test" and res["eval_rows"] > 0
    assert len(res["source_only"]["recall_ci95"]) == 2
    before = (app_ws / "final" / "fin.json").read_bytes()
    assert main(["train", "adapt", "--config", "fin.yaml"]) == 2  # refused: already run
    assert (app_ws / "final" / "fin.json").read_bytes() == before
