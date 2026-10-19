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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level, args.json_logs)
    try:
        return int(args.func(args) or 0)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
