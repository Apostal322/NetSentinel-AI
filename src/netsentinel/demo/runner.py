"""`netsentinel demo`: a complete, offline, deterministic walkthrough in a fresh workspace.

Steps (all local, CPU, about a minute, < 1 GB RAM):
 1. write synthetic NetFlow-v3 training data and a synthetic demo PCAP (demo/fixtures.py);
 2. ingest + build features + train a small LightGBM threat model and an Isolation Forest
    anomaly reference + bundle them (the same stages as the research pipeline);
 3. train a tiny application-protocol classifier (synthetic proxy labels) with a port table;
 4. calibrate a local behaviour baseline on the first 15 minutes of the capture;
 5. analyse the remaining 10 minutes (SSH brute force + port scan injected) with the default
    safe threat policy, aggregate incidents, store events for the dashboard;
 6. print what the outputs mean.

SOFTWARE DEMONSTRATION ONLY: models trained on synthetic data and evaluated on synthetic
traffic say nothing about real-world detection performance.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netsentinel.demo.fixtures import DEMO_T0, demo_labels, write_demo_pcap, write_nf_archive

log = logging.getLogger(__name__)
CAL_MINUTES = 15
WINDOW_S = 10


def _baseline_cfg(ws: Path) -> dict[str, Any]:
    return {
        "experiment": "demo_threat", "seed": 42, "task": "binary",
        "feature_set": "nf_portable_ctx", "models": ["lightgbm"], "target_fpr": 0.01,
        "max_train_rows": 300000, "train_with_prevalence_weights": False,
        "data": {"processed_dir": str(ws / "processed"), "days": None, "drop_labels": [],
                 "clean_labels": False},
        "split": {"protocol": "episode", "block_minutes": 10, "purge_seconds": 30,
                  "fractions": [0.6, 0.2, 0.2]},
        "model_params": {"lightgbm": {"n_estimators": 60, "num_leaves": 15, "n_jobs": 1}},
        "runs_dir": str(ws / "runs"),
    }  # fmt: skip


def _utc(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, UTC).replace(tzinfo=None)


def _train_appid(ws: Path, out: Path) -> Path:
    """Tiny application-protocol classifier on the synthetic flows (proxy labels from the
    synthetic L7 field) + training-data port table; demo purposes only."""
    import numpy as np
    import polars as pl
    from lightgbm import LGBMClassifier

    from netsentinel.appintel.model import (
        AppClassifier,
        build_class_profiles,
        build_port_table,
        save_classifier,
    )
    from netsentinel.features.nf_schema import NF_PORTABLE_COLUMNS
    from netsentinel.features.schema import add_derived

    names = {5: "dns", 7: "http", 91: "tls", 92: "ssh"}
    df = pl.concat([pl.read_parquet(p) for p in sorted((ws / "interim").glob("*.parquet"))])
    df = add_derived(df.filter(pl.col("label") == "benign"))
    feats = [*NF_PORTABLE_COLUMNS, "proto_tcp", "proto_udp", "proto_other", "port_class"]
    X = df.select([pl.col(f).cast(pl.Float32) for f in feats]).to_numpy()  # noqa: N806
    y = np.array([names.get(int(v), "other") for v in df["l7_proto"].to_list()], dtype=object)
    m = LGBMClassifier(n_estimators=40, num_leaves=7, verbose=-1, random_state=0,
                       n_jobs=1).fit(X, y)  # fmt: skip
    clf = AppClassifier(
        model=m,
        features=feats,
        classes=[str(c) for c in m.classes_],
        feature_set="portable",
        confidence_threshold=0.5,
        ood_low=np.nanpercentile(X, 0.5, axis=0),
        ood_high=np.nanpercentile(X, 99.5, axis=0),
        metadata={"role": "DEMO ONLY: trained on synthetic flows"},
        port_table=build_port_table(df["protocol"].to_numpy(), df["dst_port"].to_numpy(), y),
        policy={"min_purity": 0.9, "min_support": 50, "conflict": "unknown"},
        class_profiles=build_class_profiles(
            df["protocol"].to_numpy(), df["dst_port"].to_numpy(), y
        ),
    )
    return save_classifier(clf, out)


def run_demo(workspace: str | Path, quiet: bool = False) -> dict[str, Any]:
    from netsentinel.behavior.calibrate import calibrate_flows, save_profile, threat_domain_check
    from netsentinel.behavior.registry import activate
    from netsentinel.data.nf_v3 import ingest_nf_zip
    from netsentinel.features.build import BuildConfig, build_dataset
    from netsentinel.inference.bundle import build_bundle
    from netsentinel.inference.engine import Engine
    from netsentinel.streaming.offline import analyze_capture, load_capture
    from netsentinel.training.anomaly import run_anomaly
    from netsentinel.training.baseline import run_baselines

    t_start = time.perf_counter()
    ws = Path(workspace).resolve()
    if ws.exists() and any(ws.iterdir()):
        raise ValueError(f"demo workspace {ws} is not empty; choose a new directory")
    ws.mkdir(parents=True, exist_ok=True)
    say = (lambda *a: None) if quiet else print
    say(f"[1/6] synthetic fixtures -> {ws}")
    archive = write_nf_archive(ws / "fixtures" / "nf_demo.zip")
    pcap = write_demo_pcap(ws / "fixtures" / "demo.pcap")
    say("[2/6] ingest, features, train threat model + anomaly reference, bundle")
    ingest_nf_zip(archive, ws / "interim", 0.0, {"brute_force": "bruteforce"})
    build_dataset(
        ws / "interim",
        ws / "processed",
        BuildConfig(benign_per_day=1000, attack_cap_per_label_day=400, schema="nf"),
    )
    base = _baseline_cfg(ws)
    threat_run = run_baselines(base)[-1]
    anomaly_run = run_anomaly(
        {
            **base,
            "experiment": "demo_anomaly",
            "max_benign_train_rows": 2000,
            "reference_fraction": 0.2,
            "variants": [{"kind": "iforest", "conditioned": False}],
        }
    )[-1]
    bundle = build_bundle(ws / "models", ws / "runs" / threat_run, ws / "runs" / anomaly_run)
    say("[3/6] application-protocol classifier (demo)")
    appid = _train_appid(ws, ws / "models" / "appintel")
    say(f"[4/6] calibrate local baseline on the first {CAL_MINUTES} min (vetted benign)")
    cut = _utc(DEMO_T0 + CAL_MINUTES * 60)
    frame, _, _ = load_capture(pcap, "pcap", until=cut)
    profile = calibrate_flows(frame, window_s=WINDOW_S, mode="vetted_benign")
    check = threat_domain_check(Engine(bundle), frame, mode="vetted_benign")
    cal_root = ws / "models" / "calibrations"
    cal = save_profile(profile, cal_root, sources=[{"path": pcap.name, "kind": "pcap"}],
                       operator_statement="synthetic demo traffic, benign by construction",
                       threat_check=check)  # fmt: skip
    activate(cal.name, cal_root, note="netsentinel demo")
    say("[5/6] analyse the remaining traffic (default threat policy: unverified)")
    db = ws / "events.sqlite"
    summary = analyze_capture(pcap, bundle, db, kind="pcap", calibration_dir=cal,
                              appid_dir=appid, since=cut)  # fmt: skip
    (ws / "summary.json").write_text(json.dumps(summary, indent=2, default=str), "utf-8")
    result = {
        "workspace": str(ws), "bundle": str(bundle), "calibration": str(cal),
        "classifier": str(appid), "events_db": str(db), "flows": summary["flows"],
        "verdicts": summary["verdicts"], "threat_mode": summary["threat_mode"],
        "behavior_windows": summary.get("behavior_windows"),
        "incidents": summary.get("incidents"), "app_protocols": summary.get("app_protocols"),
        "models_dir": str(ws / "models"), "ground_truth": demo_labels(),
        "seconds": round(time.perf_counter() - t_start, 1),
    }  # fmt: skip
    say("[6/6] done")
    say(
        EXPLANATION.format(
            **{
                k: v if isinstance(v, str) else json.dumps(v, default=str)
                for k, v in result.items()
            }
        )
    )
    return result


EXPLANATION = """
NetSentinel demo - what you are looking at
------------------------------------------
Traffic: SYNTHETIC. 25 minutes of generated benign HTTPS/DNS from 60 hosts; from minute 18 an
SSH brute force (10.9.9.9) and from minute 21 a port scan (10.9.9.8) were injected.
Models: trained in this workspace on SYNTHETIC NetFlow data. This shows the software path,
not real-world detection performance.

flows analysed:        {flows}
verdicts:              {verdicts}
supervised threat:     {threat_mode}  (default policy: supervised scores are reported but
                       never escalate a verdict on a network not verified to match the
                       model's training data)
behaviour windows:     {behavior_windows}  (deviations from the LOCAL baseline learned on
                       minutes 0-15; anomaly_score is a percentile, not a probability)
incidents:             {incidents}
protocols (ML+port):   {app_protocols}

Files: {workspace}
Explore:  uv run --extra dashboard streamlit run dashboard/app.py --
          --events-db {events_db} --models-dir {models_dir}
"""
