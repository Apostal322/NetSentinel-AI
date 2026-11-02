"""Phase 8l DEDALE evaluation windows (docs/phase8l/DEDALE_PREREGISTRATION.md sections 1, 2, 8).

Runs only after the freeze, on the Stage B members (D15-D28). Refused unless
docs/phase8l/DEDALE_FREEZE.md is committed with the pre-registration's SHA-256
(`dedale_fetch.freeze_ok`) and the N8 report says PASS.

1. Per evaluation day: the same parsing as Stage A (`dedale_stage_a.canonical`). Flows ending
   in [2025-01-06, 2025-01-20) UTC are kept; others are dropped and counted. The feature flows
   carry the placeholder label "benign"; the real labels go to a separate frame
   (source, end time, label, attack_step) that scoring never reads.
2. The P1x builder is rerun over calibration + evaluation flows in time order, unchanged, so the
   evaluation windows see the frozen calibration destination memory. The calibration windows must
   equal Stage A's `cal_p1x.parquet` exactly.
3. Window truth: per (source, window) whether it holds a label 1 / label 2 flow, and its attack
   steps. DHCP leases of all 28 days, for host attribution.

Output: data/derived/phase8l/dedale/{eval_flows/D??.parquet, eval_p1x.parquet,
eval_truth.parquet, leases.parquet} and reports/phase8l/dedale_eval_build.json
Usage: uv run python scripts/run_capped.py -- <abs python> scripts/phase8l/dedale_eval_build.py
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


A = _load("phase8l_dedale_stage_a", HERE / "dedale_stage_a.py")
F = _load("phase8l_dedale_fetch", HERE / "dedale_fetch.py")

END = datetime(2025, 1, 20, tzinfo=UTC)
END_MS = int(END.timestamp() * 1000)
N8_REPORT = ROOT / "reports" / "phase8l" / "dedale_n8.json"
OUT = ROOT / "reports" / "phase8l" / "dedale_eval_build.json"
W_MS = 30_000
SCRIPT_ADDRESSES = {
    "172.19.0.2",
    "172.17.0.2",
    "172.16.1.3",
    "172.19.1.1",
    "172.19.2.1",
    "172.16.0.2",
    "172.16.1.2",
}  # labelling_script_on_single_conn.log.py


def parse_eval_day(path: Path, day: int) -> tuple[pl.DataFrame, pl.DataFrame, dict]:
    """One evaluation conn_labeled member -> (feature flows with placeholder labels, label
    frame, counts). Unparseable rows are dropped and counted (no N2 gate after the freeze)."""
    header = gzip.open(path, "rt", encoding="utf-8").readline().rstrip("\n").split(";")
    need = [*A.NEED, "attack_step"]
    missing = [c for c in need if c not in header]
    if missing:
        raise SystemExit(f"day {day}: missing columns {missing}")
    raw = pl.read_csv(path, separator=";", columns=need, infer_schema_length=0)
    parsed = raw.with_columns(pl.col(c).cast(pl.Float64, strict=False) for c in A.NUMERIC)
    bad = parsed.select(pl.any_horizontal(pl.col(c).is_null() for c in A.NUMERIC)
                        | pl.col("ip_src").is_null() | pl.col("ip_dst").is_null()).to_series()  # fmt: skip
    ok = parsed.filter(~bad)
    lo = (A.DAY0 + timedelta(days=day - 1)).timestamp()
    end = ok["ts"] + ok["duration"]
    out_of_day = int(((end < lo - A.TOLERANCE_S) | (end >= lo + 86400 + A.TOLERANCE_S)).sum())
    flows = A.canonical(ok).with_columns(pl.lit("benign").alias("label"))  # placeholder
    # labels from every row whose ts, source and label parse (a bad numeric field elsewhere must
    # not turn an attack flow into a benign one); end time as canonical() computes it
    lab_ok = parsed.filter(pl.col("ts").is_not_null() & pl.col("ip_src").is_not_null()
                           & pl.col("label").is_not_null())  # fmt: skip
    end_ms = (pl.col("ts") * 1000).cast(pl.Int64) + (
        pl.col("duration").fill_null(0.0) * 1000).cast(pl.Int64)  # fmt: skip
    lab = lab_ok.select(pl.col("ip_src").alias("src"), pl.col("ip_dst").alias("dst"),
                    end_ms.alias("end_ms"), pl.col("label").cast(pl.Int64), "attack_step")  # fmt: skip
    e = pl.col("flow_end_milliseconds")
    before = int(flows.select((e < A.BOUNDARY_MS).sum()).item())
    after = int(flows.select((e >= END_MS).sum()).item())
    flows = flows.filter((e >= A.BOUNDARY_MS) & (e < END_MS))
    lab = lab.filter((pl.col("end_ms") >= A.BOUNDARY_MS) & (pl.col("end_ms") < END_MS))
    info = {"rows": raw.height, "unparseable": int(bad.sum()), "ending_outside_utc_day_2h": out_of_day,
            "dropped_ending_before_boundary": before, "dropped_ending_after_end": after,
            "evaluation_flows": flows.height,
            "unparseable_by_label": {str(r[0]): int(r[1]) for r in
                                     raw.filter(bad)["label"].value_counts().iter_rows()},
            "labels": {str(int(r[0])): int(r[1]) for r in ok["label"].value_counts().iter_rows()}}  # fmt: skip
    return flows, lab, info


def window_truth(labels: pl.DataFrame) -> pl.DataFrame:
    """Per (source, 30 s window by flow end): any label 1, any label 2, the attack steps."""
    return (labels.filter(pl.col("label") != 0)
            .with_columns((pl.col("end_ms") // W_MS).alias("win"))
            .group_by(pl.col("src").alias("key"), "win")
            .agg((pl.col("label") == 1).any().alias("y1"), (pl.col("label") == 2).any().alias("y2"),
                 pl.col("attack_step").filter(pl.col("label") == 1).unique().sort()
                 .alias("steps")))  # fmt: skip


def outside_script(labels: pl.DataFrame) -> list[str]:
    """Addresses on label 1/2 flows that are not in the official labelling script's address list
    (pre-registration section 2, label-file sanity check)."""
    lab = labels.filter(pl.col("label") != 0)
    addrs = set(lab["src"].to_list()) | set(lab["dst"].to_list())
    return sorted(addrs - SCRIPT_ADDRESSES)


def main() -> None:
    t0 = time.perf_counter()
    if not (F.freeze_ok() and F.n8_passed(N8_REPORT)):
        raise SystemExit("refused: the freeze is not verified (N7) or N8 has not passed")
    man = json.loads(A.MANIFEST.read_text("utf-8"))["stages"]["B"]["members"]
    fetched = json.loads((ROOT / "reports/phase8l/dedale_fetch_stageB.json").read_text("utf-8"))
    bad = [
        m["name"] for m in man if fetched["members"].get(m["name"], {}).get("crc32") != m["crc32"]
    ]
    if bad:
        raise SystemExit(f"N10: {bad}")
    out_dir = A.DERIVED / "eval_flows"
    out_dir.mkdir(parents=True, exist_ok=True)
    rep, labels, leases, files = {"days": {}}, [], [], []
    for stage in ("A", "B"):
        for m in json.loads(A.MANIFEST.read_text("utf-8"))["stages"][stage]["members"]:
            if m["name"].endswith("dhcp.log"):
                p = A.RAW / f"D{m['day']:02d}_{m['date']}_dhcp.log.gz"
                leases += [{**r, "day": m["day"]} for r in A.dhcp_leases(p)]
    for m in man:
        if not m["name"].endswith("conn_labeled.csv"):
            continue
        p = A.RAW / f"D{m['day']:02d}_{m['date']}_conn_labeled.csv.gz"
        flows, lab, info = parse_eval_day(p, m["day"])
        rep["days"][m["day"]] = info
        print(f"D{m['day']:02d}", info["rows"], info["unparseable"], flush=True)
        f = out_dir / f"D{m['day']:02d}.parquet"
        flows.write_parquet(f, row_group_size=100_000, statistics=True)
        files.append(f)
        labels.append(lab)
        del flows
    labels = pl.concat(labels)
    truth = window_truth(labels)
    rep["label_addresses_outside_script"] = outside_script(labels)
    truth.write_parquet(A.DERIVED / "eval_truth.parquet")
    pl.DataFrame(leases).write_parquet(A.DERIVED / "leases.parquet")
    del labels

    p1x = _load("phase8j_build_p1x", ROOT / "scripts" / "phase8j" / "build_p1x.py")
    if p1x.BW.W * 1000 != W_MS:
        raise SystemExit("window length differs from the builder's")
    builder = p1x.P1xBuilder(A.BOUNDARY_MS, set())
    cal_files = sorted((A.DERIVED / "flows").glob("D??.parquet"))
    for frame in p1x.BW.chunks(cal_files + files, False, p1x.BW.MAX_ROWS):
        builder.add(frame)
    cal = pl.concat(builder.cal, how="diagonal_relaxed")
    ev = pl.concat(builder.ev, how="diagonal_relaxed")
    frozen = pl.read_parquet(A.DERIVED / "cal_p1x.parquet")
    if not cal.equals(frozen):
        raise SystemExit("calibration windows differ from Stage A")
    ev.write_parquet(A.DERIVED / "eval_p1x.parquet")
    from netsentinel.resources import peak_rss_mb

    rep.update({"eval_windows": ev.height, "truth_windows": truth.height,
                "label1_windows": int(truth["y1"].sum()), "leases": len(leases),
                "calibration_windows_reproduced": True, "peak_rss_mb": peak_rss_mb(),
                "seconds": round(time.perf_counter() - t0, 1)})  # fmt: skip
    OUT.write_text(json.dumps(rep, indent=1, default=str), "utf-8")


if __name__ == "__main__":
    main()
