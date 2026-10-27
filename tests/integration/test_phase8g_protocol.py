"""Phase 8g frozen CTU-13 evaluation code (scripts/phase8g) on SYNTHETIC Zeek data only: the
registered split and calibration exclusion, design-based truth, the time-alignment guard, the
frozen-code guard and the label blinding of the provenance audit (docs/phase8f/PREREG_CTU13.md)."""

import copy
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8g"))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "phase8g" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


W = _load("windows")
E = _load("evaluate")
P = _load("provenance_audit")

T0 = 1_313_575_261  # 2011-08-17T10:01:01Z
BENIGN = ["147.32.84.170", "147.32.84.134", "147.32.84.164"]
BACKGROUND = ["147.32.85.10", "147.32.85.11", "147.32.85.12"]
INIT = {"vm0": "147.32.84.165", "vm1": "147.32.84.191", "vm2": "147.32.84.192"}
INFECTED = {"vm0": T0 + 2 * 3600, "vm1": T0 + 3 * 3600, "vm2": T0 + 3 * 3600 + 600}  # vm0 < cut
FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts",
          "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]  # fmt: skip


def iso(t):
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def synthetic_conn_log(path: Path, hours=6.0, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    hosts = BENIGN + BACKGROUND + list(INIT.values())
    for i, t in enumerate(range(0, int(hours * 3600), 2)):
        h = hosts[rng.integers(len(hosts))]
        rows.append([f"{T0 + t + rng.uniform(0, 2):.3f}", f"C{i}", h, str(40000 + i % 20000),
                     f"93.184.216.{rng.integers(1, 30)}", "443", "tcp", "ssl",
                     f"{rng.uniform(0.1, 3):.3f}", "300", "5000", "SF", "ShADadFf", "6", "620",
                     "8", "5400"])  # fmt: skip
        if t % 60 == 0:  # background host contacting an initiator (excluded from calibration)
            rows.append([f"{T0 + t + 0.5:.3f}", f"B{i}", BACKGROUND[0], "51000", INIT["vm1"],
                         "445", "tcp", "-", "0.1", "60", "60", "SF", "ShAF", "2", "140", "2",
                         "140"])  # fmt: skip
    for name, ip in INIT.items():  # scans from the documented infection time
        start = INFECTED[name]
        for j in range(0, int(T0 + hours * 3600 - start), 1):
            rows.append([f"{start + j + 0.25:.3f}", f"S{name}{j}", ip, "50000",
                         f"172.16.{j % 250}.{(j // 250) % 250}", str(1000 + j % 5000), "tcp", "-",
                         "0.0", "0", "0", "S0", "S", "1", "60", "0", "0"])  # fmt: skip
    rows.sort(key=lambda r: float(r[0]))
    head = "#separator \\x09\n#fields\t" + "\t".join(FIELDS) + "\n"
    path.write_text(head + "\n".join("\t".join(r) for r in rows) + "\n", encoding="utf-8")


def synthetic_binetflow(path: Path):
    lines = ["StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,"
             "TotBytes,SrcBytes,Label"]  # fmt: skip
    for name, ip in INIT.items():
        if name == "vm2":
            continue  # documented initiator without From-Botnet flows -> must be reported
        lines.append(f"2011/08/17 14:30:00.0,0.1,tcp,{ip},50000,->,172.16.0.1,1000,S_,0,0,1,60,60,"
                     "flow=From-Botnet-V50-1-TCP-Attempt")  # fmt: skip
    lines.append(
        "2011/08/17 14:30:01.0,0.1,tcp,147.32.99.99,1,->,1.2.3.4,80,S_,0,0,1,60,60,"
        "flow=From-Botnet-V50-2-TCP"
    )  # an undocumented botnet source
    lines.append(f"2011/08/17 12:30:00.0,0.1,tcp,{BENIGN[0]},1,->,1.2.3.4,443,FSA,0,0,8,900,300,"
                 "flow=From-Normal-V50-Stribrek")  # fmt: skip
    lines.append("2011/08/17 12:30:00.0,0.1,udp,147.32.85.10,1,<->,1.2.3.4,53,CON,0,0,2,90,45,"
                 "flow=Background-UDP-Established")  # fmt: skip
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture(scope="module")
def ws(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("p8g")
    sid = "SYNTH-Capture-1"
    (tmp / "raw" / sid).mkdir(parents=True)
    synthetic_conn_log(tmp / "raw" / sid / "conn.log")
    synthetic_binetflow(tmp / "raw" / sid / "flows.binetflow")
    cfg = W.load_config(ROOT / "configs" / "phase8g" / "ctu13.yaml")
    cfg.update(data_root=str(tmp / "raw"), derived_root=str(tmp / "derived"),
               reports_root=str(tmp / "reports"), bootstrap_resamples=200,
               initiator_names=INIT)  # fmt: skip
    cfg["scenarios"] = {"synthetic": {
        "id": sid, "botnet": "synthetic", "conn_log": "conn.log",
        "label_files": ["flows.binetflow"], "capture_start_utc": iso(T0),
        "infected_utc": {n: iso(t) for n, t in INFECTED.items()}, "benign": BENIGN}}  # fmt: skip
    meta = W.build(cfg, "synthetic", batch_flows=5_000)
    return tmp, cfg, meta


def test_registered_split_and_initiator_exclusion(ws):
    tmp, cfg, meta = ws
    assert abs(meta["cut_ms"] - (meta["first_start_ms"] + 2.5 * 3.6e6)) < 1
    assert meta["flows"]["cal_excluded_initiator"] > 0 and meta["flows"]["test"] > 0
    cal = W.load_windows(cfg, "synthetic", "cal", "device")
    assert not set(cal["key"].to_list()) & set(INIT.values())  # no initiator in calibration
    import polars as pl

    dst = set(pl.read_parquet(tmp / "derived" / "synthetic" / "calibration_dst.parquet")["dst"])
    assert not dst & set(INIT.values())  # flows TO initiators excluded as well
    test = W.load_windows(cfg, "synthetic", "test", "device")
    assert set(INIT.values()) <= set(test["key"].to_list())
    assert int(test["window_end_ms"].min()) >= meta["cut_ms"]


def test_frozen_guard_and_label_blinding(ws):
    tmp, cfg, _ = ws
    (tmp / "reports").mkdir(exist_ok=True)
    (tmp / "reports" / "registry.json").write_text(json.dumps({"files": []}))
    with pytest.raises(SystemExit, match="frozen"):
        E.run(cfg)  # no frozen SHA recorded -> refuses
    with pytest.raises(SystemExit, match="blinded"):
        P.run(cfg)  # labels stay closed before the frozen run


@pytest.fixture(scope="module")
def results(ws):
    _, cfg, _ = ws
    return E.run(cfg, allow_unfrozen=True)


def test_design_based_truth_detection_and_reporting(ws, results):
    r = results["scenarios"]["synthetic"]
    assert r["time_aligned"] and not r["calibration_has_initiator_keys"]
    v = r["modes"]["vetted_benign"]
    v3 = v["V3"]
    assert v3["initiators_with_attack_windows"] == 3  # vm0 (infected before the cut) included
    assert v3["initiators_detected"] == 3 and v3["attack_window_recall"] > 0.5
    assert set(v3["delay_s_from_infection"]) == set(INIT.values())
    assert v3["benign_windows"] > 100 and v3["benign_fpr"] is not None
    z = v["Z_never_alert"]
    assert z["initiators_detected"] == 0 and z["benign_false_alerts"] == 0
    # 3.5 h of test = 14 blocks of 15 min (+1 partial: window ends run up to 30 s past the cut)
    assert v["bootstrap"]["blocks"] in (14, 15) and v["bootstrap"]["status"] == "inference"
    assert len(v["segments"]) == 4 and 0 <= v["normality_supported_share"] <= 1
    assert {s["baseline_state"] for s in v["segments"]} <= {
        "monitoring",
        "drift_suspected",
        "stale",
        "collecting_baseline",
    }
    assert set(v["V4"]) >= {"S1", "S5", "V4_success"}
    assert "vetted_benign" in r["modes"] and "unlabelled" in r["modes"]
    p = results["pooled"]
    assert p["V2_descriptive"]["verdict"].startswith("not evaluable")
    assert p["V1_verdict"] in ("success", "failure") or p["V1_verdict"].startswith("not evaluable")


def test_time_alignment_guard(ws):
    tmp, cfg, _ = ws
    bad = copy.deepcopy(cfg)
    bad["scenarios"]["synthetic"]["capture_start_utc"] = iso(T0 + 3600)  # one hour off
    bad["reports_root"] = str(tmp / "reports_bad")
    r = E.run(bad, allow_unfrozen=True)["scenarios"]["synthetic"]
    assert not r["time_aligned"]
    assert str(r["modes"]["vetted_benign"]["V3"]["initiators_detected"]).startswith("not evaluable")


def test_provenance_audit_after_the_run(ws, results):
    out = P.run(ws[1])["synthetic"][0]
    assert out["has_label_column"]
    assert out["from_botnet_sources_not_documented"] == ["147.32.99.99"]
    assert out["documented_initiators_without_from_botnet"] == [INIT["vm2"]]
    assert out["from_normal_not_in_documented_benign"] == []
    assert set(out["documented_benign_without_from_normal"]) == set(BENIGN[1:])
