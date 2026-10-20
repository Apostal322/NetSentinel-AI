"""`netsentinel` command line. Every command here performs real work; heavy imports are
done inside each handler so `netsentinel --help` stays fast and light on RAM."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from netsentinel.logging_utils import setup_logging

log = logging.getLogger("netsentinel")
DEFAULT_MANIFEST = "configs/datasets/cse_cic_ids2018.yaml"


def _cmd_data_verify(args: argparse.Namespace) -> int:
    from netsentinel.data.manifest import Manifest, verify

    manifest = Manifest.load(args.manifest)
    results = verify(manifest, check_etag=not args.size_only)
    for r in results:
        print(f"{r.status:14s} {r.name} {r.detail}")
    bad = [r for r in results if r.status != "ok"]
    print(f"{len(results) - len(bad)}/{len(results)} files ok")
    return 1 if bad else 0


def _cmd_data_ingest(args: argparse.Namespace) -> int:
    from netsentinel.data.ids2018 import ingest_csv
    from netsentinel.data.manifest import Manifest

    manifest = Manifest.load(args.manifest)
    out_dir = Path(args.out)
    reports = []
    for f in manifest.files:
        if args.day and f.day not in args.day:
            continue
        src = manifest.path_of(f)
        dst = out_dir / f"{f.day}.parquet"
        if dst.exists() and not args.force:
            log.info("skip %s (exists; use --force)", dst)
            continue
        if not src.is_file():
            log.error("missing raw file %s; run scripts/download_ids2018.sh", src)
            return 1
        reports.append(ingest_csv(src, dst, f.day).as_dict())
    if reports:
        report_path = out_dir / "ingest_report.json"
        old = json.loads(report_path.read_text("utf-8")) if report_path.exists() else []
        days = {r["day"] for r in reports}
        merged = [r for r in old if r["day"] not in days] + reports
        report_path.write_text(json.dumps(sorted(merged, key=lambda r: r["day"]), indent=2))
    return 0


def _cmd_data_ingest_nf(args: argparse.Namespace) -> int:
    from netsentinel.config import load_yaml
    from netsentinel.data.nf_v3 import ingest_nf_zip

    cfg = load_yaml(args.config)["datasets"]
    if args.dataset not in cfg:
        log.error("unknown dataset %s; choose from %s", args.dataset, sorted(cfg))
        return 2
    d = cfg[args.dataset]
    rep = ingest_nf_zip(d["archive"], d["out_dir"], float(d["utc_offset_hours"]),
                        d.get("family_map") or {}, verify=not args.no_verify,
                        label_map=d.get("label_map") or {})  # fmt: skip
    print(json.dumps({k: v for k, v in rep.as_dict().items() if k != "columns"}, indent=2))
    return 0


def _cmd_data_eda(args: argparse.Namespace) -> int:
    from netsentinel.data.eda import run_eda

    result = run_eda(args.interim, args.out, auc_per_day=args.auc_per_day, seed=args.seed)
    print(f"profiled {len(result['days'])} days -> {args.out}/eda.json")
    return 0


def _cmd_features_build(args: argparse.Namespace) -> int:
    from netsentinel.features.build import BuildConfig, build_dataset

    cfg = BuildConfig(
        benign_per_day=args.benign_per_day,
        attack_cap_per_label_day=args.attack_cap,
        seed=args.seed,
        schema=args.schema,
    )
    meta = build_dataset(args.interim, args.out, cfg)
    total = sum(d["rows_sampled"] for d in meta["days"])
    print(f"built {len(meta['days'])} days, {total:,} sampled rows -> {args.out}")
    return 0


def _experiment_config(args: argparse.Namespace) -> dict:
    from netsentinel.config import load_config

    return load_config(args.config, args.override, args.sets)


def _cmd_train_baseline(args: argparse.Namespace) -> int:
    from netsentinel.training.baseline import run_baselines

    for run_id in run_baselines(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_train_anomaly(args: argparse.Namespace) -> int:
    from netsentinel.training.anomaly import run_anomaly

    for run_id in run_anomaly(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_train_openset(args: argparse.Namespace) -> int:
    from netsentinel.training.openset import run_openset

    for run_id in run_openset(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_train_temporal(args: argparse.Namespace) -> int:
    from netsentinel.training.temporal import run_temporal

    for run_id in run_temporal(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_train_transfer(args: argparse.Namespace) -> int:
    from netsentinel.training.transfer import run_transfer

    for run_id in run_transfer(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_train_adapt(args: argparse.Namespace) -> int:
    from netsentinel.training.adapt import run_adapt

    for run_id in run_adapt(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_train_appid(args: argparse.Namespace) -> int:
    from netsentinel.training.appid import run_appid

    for run_id in run_appid(_experiment_config(args)):
        print(run_id)
    return 0


def _cmd_bundle_build(args: argparse.Namespace) -> int:
    from netsentinel.inference.bundle import build_bundle

    out = build_bundle(args.out, args.threat_run, args.anomaly_run, args.type_run,
                       attack_type_threshold=args.attack_type_threshold)  # fmt: skip
    print(out)
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    from datetime import datetime

    from netsentinel.inference.engine import Engine
    from netsentinel.storage.events import EventStore
    from netsentinel.streaming.replay import ReplayConfig, Replayer

    cfg = ReplayConfig(
        path=args.path,
        start=datetime.fromisoformat(args.start) if args.start else None,
        end=datetime.fromisoformat(args.end) if args.end else None,
        max_events=args.max_events,
        speed=args.speed,
    )
    status = Replayer(Engine(args.bundle), EventStore(args.events_db)).run(cfg)
    print(json.dumps(status.as_dict(), indent=2))
    return 0 if status.state == "finished" else 1


def _cmd_analyze(args: argparse.Namespace) -> int:
    from netsentinel.streaming.offline import analyze_capture

    summary = analyze_capture(args.capture, args.bundle, args.events_db, args.utc_offset,
                              args.kind, calibration_dir=_resolve_cal(args.calibration),
                              appid_dir=args.appid, threat_policy=args.threat_policy,
                              since=args.since, until=args.until)  # fmt: skip
    text = json.dumps(summary, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    keys = (
        "source",
        "kind",
        "flows",
        "verdicts",
        "threat_mode",
        "threat_status",
        "behavior_status",
        "app_status",
        "app_protocols",
        "baseline_state",
        "parse",
    )
    print(json.dumps({k: summary[k] for k in keys if k in summary}, indent=2, default=str))
    return 0


def _cmd_calibrate(args: argparse.Namespace) -> int:
    import polars as pl

    from netsentinel.behavior.calibrate import calibrate_flows, save_profile, threat_domain_check
    from netsentinel.ledger import file_sha256
    from netsentinel.streaming.offline import load_capture

    if args.mode == "vetted_benign" and not args.assert_benign:
        log.error(
            "vetted_benign mode needs --assert-benign: the operator must state that the "
            "calibration traffic is believed to be normal (otherwise use --mode unlabelled)"
        )
        return 2
    frames, sources = [], []
    for cap in args.captures:
        frame, kind, parse = load_capture(cap, args.kind, args.utc_offset, since=args.since,
                                          until=args.until)  # fmt: skip
        sources.append(
            {
                "path": Path(cap).name,
                "kind": kind,
                "sha256": file_sha256(Path(cap)),
                "flows": 0 if frame is None else frame.height,
                "parse": parse,
            }
        )
        if frame is not None:
            frames.append(frame)
    if not frames:
        log.error("no flows in the calibration captures")
        return 2
    frame = pl.concat(frames, how="diagonal_relaxed")
    profile = calibrate_flows(
        frame,
        window_s=args.window,
        mode=args.mode,
        target_fpr=args.target_fpr,
        min_windows=args.min_windows,
        threshold_method=args.threshold_method,
    )
    check = None
    if args.bundle:
        from netsentinel.inference.engine import Engine

        check = threat_domain_check(Engine(args.bundle), frame, mode=args.mode)
    statement = (
        "operator asserted the calibration traffic is benign (vetted_benign)"
        if args.mode == "vetted_benign"
        else "no benign assertion: unlabelled traffic, contamination-limiting trimming"
    )
    from netsentinel.behavior.registry import activate, resolve_calibration, update_check

    upd = None
    if args.previous:
        upd = update_check(resolve_calibration(args.previous, args.out), frame)
    out = save_profile(profile, args.out, sources=sources, operator_statement=statement,
                       threat_check=check, update_check=upd)  # fmt: skip
    summary = json.loads((out / "manifest.json").read_text("utf-8"))
    print(json.dumps({k: summary[k] for k in ("calibration_id", "status", "mode", "period",
                                              "levels", "threat_model_domain_check",
                                              "update_check")},
                     indent=2, default=str))  # fmt: skip
    if args.activate:
        try:
            activate(out.name, args.out, reviewed=False, note="calibrate --activate")
        except ValueError as exc:
            log.error("saved but NOT activated: %s", exc)
            print(out)
            return 3
    print(out)
    return 0


def _resolve_cal(arg):
    from netsentinel.behavior.registry import resolve_calibration

    return resolve_calibration(arg)


def _cmd_calibration(args: argparse.Namespace) -> int:
    from netsentinel.behavior.registry import activate, read_registry, rollback

    if args.action == "list":
        reg = read_registry(args.root)
        rows = []
        for d in sorted(Path(args.root).glob("calibration-*/manifest.json")):
            m = json.loads(d.read_text("utf-8"))
            rows.append({"id": m["calibration_id"], "status": m["status"], "mode": m["mode"],
                         "schema": m.get("schema_version"),
                         "review_required": (m.get("update_check") or {}).get("review_required"),
                         "active": m["calibration_id"] == reg.get("active")})  # fmt: skip
        print(json.dumps({"active": reg.get("active"), "calibrations": rows}, indent=2))
    elif args.action == "show":
        reg = read_registry(args.root)
        print(json.dumps(reg, indent=2))
    elif args.action == "activate":
        if not args.id:
            log.error("activate needs a calibration id")
            return 2
        reg = activate(args.id, args.root, reviewed=args.reviewed, note=args.note or "")
        print(json.dumps({"active": reg["active"]}))
    elif args.action == "rollback":
        reg = rollback(args.root)
        print(json.dumps({"active": reg["active"]}))
    return 0


def _cmd_monitor(args: argparse.Namespace) -> int:
    """Opt-in streaming of a LOCAL Zeek conn.log written by the operator's own Zeek."""
    from netsentinel.inference.pipeline import AnalysisPipeline
    from netsentinel.storage.events import EventStore
    from netsentinel.streaming.live import StreamMonitor, follow_lines
    from netsentinel.telemetry.zeek import ZeekStats, parse_conn_lines, read_conn_log

    path = Path(args.zeek_log)
    if not path.is_file():
        log.error("Zeek log %s not found", path)
        return 2
    cal = _resolve_cal(args.calibration)
    if not cal:
        log.error("monitoring needs a behaviour calibration (--calibration or an active one)")
        return 2
    pipe = AnalysisPipeline(args.bundle, cal, args.appid, args.threat_policy)
    store = EventStore(args.events_db)
    mon = StreamMonitor(pipe, store, source=f"zeek-stream:{path.name}",
                        lateness_s=args.lateness, max_buffer=args.max_buffer,
                        utc_offset_hours=args.utc_offset)  # fmt: skip
    zs = ZeekStats()
    if args.follow:
        recs = parse_conn_lines(follow_lines(path, idle_timeout_s=args.idle_timeout), zs)
    else:
        recs = read_conn_log(path, zs)
    try:
        mon.feed(recs)
    except KeyboardInterrupt:
        log.info("interrupted: closing open windows")
    mon.close()
    out = {**mon.summary(), "parse": {"lines": zs.lines, "records": zs.records,
                                      "skipped": zs.skipped}}  # fmt: skip
    print(json.dumps(out, indent=2, default=str))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    import tempfile

    from netsentinel.demo.runner import run_demo

    ws = args.workspace or tempfile.mkdtemp(prefix="netsentinel-demo-")
    result = run_demo(ws, quiet=args.quiet)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from netsentinel.api.app import Settings, create_app

    app = create_app(Settings(bundle_dir=args.bundle, events_db=args.events_db,
                              replay_dir=args.replay_dir,
                              calibration_dir=_resolve_cal(args.calibration),
                              appid_dir=args.appid, threat_policy=args.threat_policy))  # fmt: skip
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    if not args.final:
        log.error("validation metrics are produced at training time; pass --final for test")
        return 2
    from netsentinel.evaluation.final import evaluate_final

    result = evaluate_final(args.run)
    print(json.dumps({k: v for k, v in result.items() if not isinstance(v, dict)}, indent=2))
    return 0


def _add_config_args(p: argparse.ArgumentParser, default: str) -> None:
    p.add_argument("--config", default=default)
    p.add_argument("--override", default=None, help="YAML merged on top of --config")
    p.add_argument("--set", dest="sets", action="append", default=[], metavar="KEY=VALUE")


def _add_period_args(p: argparse.ArgumentParser) -> None:
    from datetime import datetime

    p.add_argument(
        "--since",
        type=datetime.fromisoformat,
        default=None,
        help="keep flows ending at/after this time (ISO 8601, UTC if naive)",
    )
    p.add_argument(
        "--until",
        type=datetime.fromisoformat,
        default=None,
        help="keep flows ending before this time (ISO 8601, UTC if naive)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netsentinel", description=__doc__)
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--json-logs", action="store_true")
    sub = parser.add_subparsers(dest="group", required=True)

    data = sub.add_parser("data", help="dataset acquisition, validation and preparation")
    data_sub = data.add_subparsers(dest="command", required=True)

    p = data_sub.add_parser("verify", help="check raw files against the manifest (size + ETag)")
    p.add_argument("--manifest", default=DEFAULT_MANIFEST)
    p.add_argument("--size-only", action="store_true")
    p.set_defaults(func=_cmd_data_verify)

    p = data_sub.add_parser("ingest", help="raw CSV -> typed per-day Parquet")
    p.add_argument("--manifest", default=DEFAULT_MANIFEST)
    p.add_argument("--out", default="data/interim/ids2018")
    p.add_argument("--day", action="append", help="limit to these days (YYYY-MM-DD)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=_cmd_data_ingest)

    p = data_sub.add_parser("ingest-nf", help="NetFlow v3 zip -> typed per-day Parquet")
    p.add_argument("dataset", help="key in the ingest config, e.g. nf-unsw-nb15-v3")
    p.add_argument("--config", default="configs/datasets/nf_v3_ingest.yaml")
    p.add_argument("--no-verify", action="store_true", help="skip the BagIt SHA-1 check")
    p.set_defaults(func=_cmd_data_ingest_nf)

    p = data_sub.add_parser("eda", help="profile ingested days: labels, quality, leakage")
    p.add_argument("--interim", default="data/interim/ids2018")
    p.add_argument("--out", default="reports/eda")
    p.add_argument("--auc-per-day", type=int, default=50_000)
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(func=_cmd_data_eda)

    feats = sub.add_parser("features", help="feature computation")
    feats_sub = feats.add_subparsers(dest="command", required=True)
    p = feats_sub.add_parser("build", help="causal context features + stratified sample")
    p.add_argument("--interim", default="data/interim/ids2018")
    p.add_argument("--out", default="data/processed/ids2018_v1")
    p.add_argument("--benign-per-day", type=int, default=50_000)
    p.add_argument("--attack-cap", type=int, default=25_000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--schema", choices=("cic", "nf"), default="cic")
    p.set_defaults(func=_cmd_features_build)

    train = sub.add_parser("train", help="model training")
    train_sub = train.add_subparsers(dest="command", required=True)
    p = train_sub.add_parser("baseline", help="classical baselines (validation metrics)")
    _add_config_args(p, "configs/experiments/baseline_binary.yaml")
    p.set_defaults(func=_cmd_train_baseline)
    p = train_sub.add_parser("anomaly", help="normal-behaviour models (validation metrics)")
    _add_config_args(p, "configs/experiments/anomaly.yaml")
    p.set_defaults(func=_cmd_train_anomaly)
    p = train_sub.add_parser("openset", help="leave-one-family-out unseen-attack evaluation")
    _add_config_args(p, "configs/experiments/openset.yaml")
    p.set_defaults(func=_cmd_train_openset)
    p = train_sub.add_parser("adapt", help="label-free adaptation + target normal modelling")
    _add_config_args(p, "configs/experiments/adapt_nf.yaml")
    p.set_defaults(func=_cmd_train_adapt)
    p = train_sub.add_parser("appid", help="application identification (nDPI label) from flows")
    _add_config_args(p, "configs/experiments/appid_nf.yaml")
    p.set_defaults(func=_cmd_train_appid)
    p = train_sub.add_parser("transfer", help="train on one dataset, evaluate on another")
    _add_config_args(p, "configs/experiments/transfer_nf.yaml")
    p.set_defaults(func=_cmd_train_transfer)
    p = train_sub.add_parser("temporal", help="GRU over causal flow sequences vs MLP control")
    _add_config_args(p, "configs/experiments/temporal.yaml")
    p.set_defaults(func=_cmd_train_temporal)

    bundle = sub.add_parser("bundle", help="deployable model bundles")
    bundle_sub = bundle.add_subparsers(dest="command", required=True)
    p = bundle_sub.add_parser("build", help="package threat + anomaly (+ type) runs")
    p.add_argument("--threat-run", required=True)
    p.add_argument("--anomaly-run", required=True)
    p.add_argument("--type-run", default=None)
    p.add_argument("--attack-type-threshold", type=float, default=0.6)
    p.add_argument("--out", default="models")
    p.set_defaults(func=_cmd_bundle_build)

    p = sub.add_parser("replay", help="offline replay of an ingested day into the event store")
    p.add_argument("--bundle", required=True)
    p.add_argument("--path", required=True, help="data/interim/ids2018/<day>.parquet")
    p.add_argument("--start", default=None, help="ISO time, e.g. 2018-02-21T14:00:00")
    p.add_argument("--end", default=None)
    p.add_argument("--max-events", type=int, default=50_000)
    p.add_argument("--speed", type=float, default=0.0)
    p.add_argument("--events-db", default="artifacts/events.sqlite")
    p.set_defaults(func=_cmd_replay)

    p = sub.add_parser("calibrate", help="learn a local behaviour profile from authorised traffic")
    p.add_argument("captures", nargs="+", help="PCAP/pcapng files or Zeek conn logs, in time order")
    p.add_argument("--kind", choices=("auto", "pcap", "zeek"), default="auto")
    p.add_argument("--mode", choices=("vetted_benign", "unlabelled"), default="unlabelled")
    p.add_argument(
        "--assert-benign",
        action="store_true",
        help="operator statement that the traffic is believed benign (vetted_benign)",
    )
    p.add_argument("--window", type=int, default=30, help="window length in seconds")
    p.add_argument("--target-fpr", type=float, default=0.01, help="per entity-window FPR")
    p.add_argument("--min-windows", type=int, default=30)
    p.add_argument("--bundle", default=None, help="also check the supervised model's domain")
    p.add_argument("--utc-offset", type=float, default=0.0)
    p.add_argument("--out", default="models/calibrations")
    p.add_argument(
        "--threshold-method",
        choices=("crossfit", "split"),
        default="crossfit",
        help="crossfit: time-blocked cross-fitted thresholds from all calibration "
        "windows (default); split: fit 70%% / threshold 30%% (Phase 6)",
    )
    p.add_argument(
        "--previous",
        default=None,
        help="compare with this calibration (or 'active'): flags the new artifact "
        "review_required if the new period is anomalous under it",
    )
    p.add_argument(
        "--activate",
        action="store_true",
        help="make it the active calibration unless review is required",
    )
    _add_period_args(p)
    p.set_defaults(func=_cmd_calibrate)

    p = sub.add_parser("calibration", help="list / show / activate / rollback calibrations")
    p.add_argument("action", choices=("list", "show", "activate", "rollback"))
    p.add_argument("id", nargs="?", default=None)
    p.add_argument("--root", default="models/calibrations")
    p.add_argument(
        "--reviewed",
        action="store_true",
        help="operator confirms a review_required period was vetted",
    )
    p.add_argument("--note", default=None)
    p.set_defaults(func=_cmd_calibration)

    p = sub.add_parser("analyze", help="offline analysis of a PCAP/pcapng file or Zeek conn.log")
    p.add_argument("capture")
    p.add_argument("--bundle", required=True)
    p.add_argument("--kind", choices=("auto", "pcap", "zeek"), default="auto")
    p.add_argument("--utc-offset", type=float, default=0.0, help="local time = UTC + offset h")
    p.add_argument("--events-db", default="artifacts/events.sqlite")
    p.add_argument("--out", default=None, help="write the full JSON summary here")
    p.add_argument(
        "--calibration", default=None, help="local behaviour profile from `netsentinel calibrate`"
    )
    p.add_argument("--appid", default=None, help="application classifier artifact directory")
    _add_period_args(p)
    p.add_argument(
        "--threat-policy",
        choices=("unverified", "auto", "trust", "unsupported"),
        default="unverified",
        help="unverified (default): supervised scores are reported but never escalate a "
        "verdict; auto: escalate only if the calibration's domain check v2 passed; trust: "
        "operator asserts the traffic is in the model's training domain",
    )
    p.set_defaults(func=_cmd_analyze)

    p = sub.add_parser("monitor", help="opt-in streaming of a local Zeek conn.log (read-only, "
                                       "detection only)")  # fmt: skip
    p.add_argument("--zeek-log", required=True, help="conn.log written by YOUR Zeek instance")
    p.add_argument("--follow", action="store_true", help="keep reading as the file grows")
    p.add_argument("--idle-timeout", type=float, default=None,
                   help="with --follow: stop after this many idle seconds")  # fmt: skip
    p.add_argument("--bundle", default=None, help="supervised bundle (optional)")
    p.add_argument("--calibration", default="active", help="behaviour profile (default: active)")
    p.add_argument("--appid", default=None)
    p.add_argument("--events-db", default="artifacts/events.sqlite")
    p.add_argument("--lateness", type=float, default=60.0, help="allowed lateness, seconds")
    p.add_argument("--max-buffer", type=int, default=2_000_000, help="max buffered records")
    p.add_argument("--utc-offset", type=float, default=0.0)
    p.add_argument("--threat-policy", choices=("unverified", "auto", "trust", "unsupported"),
                   default="unverified")  # fmt: skip
    p.set_defaults(func=_cmd_monitor)

    p = sub.add_parser("demo", help="offline synthetic end-to-end demonstration (no downloads)")
    p.add_argument("--workspace", default=None, help="new/empty directory (default: a temp dir)")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.set_defaults(func=_cmd_demo)

    p = sub.add_parser("serve", help="run the API (localhost only by default)")
    p.add_argument("--bundle", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--events-db", default="artifacts/events.sqlite")
    p.add_argument("--replay-dir", default="data/interim/ids2018")
    p.add_argument(
        "--calibration",
        default=os.environ.get("NETSENTINEL_CALIBRATION") or None,
        help="local behaviour profile directory (env NETSENTINEL_CALIBRATION)",
    )
    p.add_argument(
        "--appid",
        default=os.environ.get("NETSENTINEL_APPID") or None,
        help="application classifier directory (env NETSENTINEL_APPID)",
    )
    p.add_argument(
        "--threat-policy",
        choices=("unverified", "auto", "trust", "unsupported"),
        default=os.environ.get("NETSENTINEL_THREAT_POLICY", "unverified"),
    )
    p.set_defaults(func=_cmd_serve)

    p = sub.add_parser("evaluate", help="one-shot test evaluation of a run")
    p.add_argument("--run", required=True, help="runs/<run_id>")
    p.add_argument("--final", action="store_true", help="touch the test split (once per run)")
    p.set_defaults(func=_cmd_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level, args.json_logs)
    try:
        return int(args.func(args) or 0)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        log.error("%s", exc)
        return 2
    finally:
        from netsentinel.resources import peak_rss_mb

        peak = peak_rss_mb()
        if peak is not None:
            log.info("peak_rss_mb=%.1f", peak)


if __name__ == "__main__":
    sys.exit(main())
