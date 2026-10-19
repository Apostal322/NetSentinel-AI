"""`netsentinel` command line. Every command here performs real work; heavy imports are
done inside each handler so `netsentinel --help` stays fast and light on RAM."""

from __future__ import annotations

import argparse
import json
import logging
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
