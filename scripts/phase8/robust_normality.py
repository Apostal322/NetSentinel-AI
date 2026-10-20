"""Phase 8F (development data, exploratory): robustness of the local baseline on benign
CTU-Normal captures (13; already inspected in Phases 6-7).

Per capture, evaluation = flows ending in the last 50% of its span (all benign by the dataset
description). Product calibration (vetted_benign, cross-fit thresholds, window 30 s, target 1%):
1. sample size: calibrate on the first L minutes (L = 15, 30, 60, 120, 240; within the first
   half). Report status and realised device-level FPR on the evaluation half.
2. time of day: realised FPR per UTC hour (calibration = whole first half).
3. drift alarms: baseline_state on the evaluation half (global level). With benign traffic,
   any "drift_suspected" is a false drift alarm.
4. contamination and safe updates: the update gate (registry.update_check) scores a candidate
   calibration period with the current baseline; with a 60 s port scan injected into it, the
   gate should require review, and without it, it should usually not. (First run: the
   rate-only gate flagged 0/12 contaminated periods; v2 adds the strong-outlier rule.)

Usage: uv run python scripts/phase8/robust_normality.py
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.behavior.calibrate import calibrate_flows, save_profile
from netsentinel.behavior.monitor import baseline_state, score_flows
from netsentinel.behavior.registry import update_check
from netsentinel.resources import peak_rss_mb
from netsentinel.streaming.offline import load_capture

OUT = Path("reports/phase8/robust_normality.json")
LENGTHS_MIN = (15, 30, 60, 120, 240)


def scan_rows(frame: pl.DataFrame, at_ms: int, n: int = 800) -> pl.DataFrame:
    """A 60 s TCP SYN scan from one existing device to n new hosts/ports (no replies)."""
    host = frame["ipv4_src_addr"].mode()[0]
    proto = frame.row(0, named=True)
    rows = []
    for i in range(n):
        r = dict(proto)
        t = at_ms + int(i * 60_000 / n)
        r.update(flow_start_milliseconds=t, flow_end_milliseconds=t,
                 flow_duration_milliseconds=0, ipv4_src_addr=host,
                 ipv4_dst_addr=f"172.31.{i // 250}.{i % 250}", dst_port=1000 + i, protocol=6,
                 in_bytes=60, out_bytes=0, in_pkts=1, out_pkts=0)  # fmt: skip
        rows.append(r)
    return pl.DataFrame(rows, schema=frame.schema)


def device_fpr(prof, ev: pl.DataFrame) -> tuple[float | None, int]:
    s = score_flows(prof, ev)
    d = s.filter(pl.col("level") == "device") if s.height else s
    return (float(d["anomalous"].mean()) if d.height else None), d.height


def main() -> None:
    t0 = time.perf_counter()
    caps = [Path("data/raw/ctu_normal_26/bro/conn.log"),
            *sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log"))]  # fmt: skip
    res: dict = {}
    tmp = Path(tempfile.mkdtemp(prefix="ns-8f-"))
    for cap in caps:
        name = cap.parent.name if cap.parent.name != "bro" else "CTU-Normal-26"
        frame, _, _ = load_capture(cap, "zeek")
        end = frame["flow_end_milliseconds"]
        lo, hi = int(end.min()), int(end.max())
        mid = lo + (hi - lo) // 2
        cal_all = frame.filter(pl.col("flow_end_milliseconds") < mid)
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        r: dict = {"span_h": (hi - lo) / 3.6e6, "flows": frame.height, "sample_size": {}}
        for L in LENGTHS_MIN:
            stop = lo + L * 60_000
            if stop > mid:
                break
            cal = cal_all.filter(pl.col("flow_end_milliseconds") < stop)
            prof = calibrate_flows(cal, window_s=30, mode="vetted_benign")
            fpr, n = device_fpr(prof, ev) if prof.status != "insufficient_history" else (None, 0)
            g = prof.levels.get("device")
            r["sample_size"][L] = {"status": prof.status, "device_fpr": fpr, "eval_windows": n,
                                   "fpr_upper95": (g.threshold_diag or {}).get("fpr_upper95")
                                   if g else None}  # fmt: skip
        prof = calibrate_flows(cal_all, window_s=30, mode="vetted_benign")
        if prof.status != "insufficient_history":
            s = score_flows(prof, ev)
            d = s.filter(pl.col("level") == "device")
            hod = (d.with_columns(((pl.col("window_end_ms") // 3_600_000) % 24).alias("h"))
                   .group_by("h").agg(pl.col("anomalous").mean().alias("fpr"), pl.len().alias("n"))
                   .sort("h"))  # fmt: skip
            r["fpr_by_hour_utc"] = hod.to_dicts()
            r["device_fpr_half"] = float(d["anomalous"].mean()) if d.height else None
            r["drift"] = baseline_state(prof, s)
            # safe updates: current = first half; candidate = evaluation half (+/- a scan)
            cur = save_profile(prof, tmp, sources=[], operator_statement="8F study")
            clean_gate = update_check(cur, ev)
            dirty = pl.concat([ev, scan_rows(ev, mid + (hi - mid) // 2)]).sort(
                "flow_end_milliseconds")  # fmt: skip
            dirty_gate = update_check(cur, dirty)
            r["update_gate"] = {"clean_review_required": clean_gate.get("review_required"),
                                "contaminated_review_required": dirty_gate.get("review_required"),
                                "clean": clean_gate, "contaminated": dirty_gate}  # fmt: skip
        res[name] = r
        print(name, {L: (v["status"], None if v["device_fpr"] is None else round(v["device_fpr"], 4))
                     for L, v in r["sample_size"].items()},
              r.get("drift", {}).get("state"), r.get("update_gate", {}).get(
                  "clean_review_required"), r.get("update_gate", {}).get(
                  "contaminated_review_required"), flush=True)  # fmt: skip
    summ = {}
    for L in LENGTHS_MIN:
        v = [x["sample_size"][L] for x in res.values() if L in x["sample_size"]]
        f = [x["device_fpr"] for x in v if x["device_fpr"] is not None]
        summ[L] = {"captures": len(v), "ready": sum(x["status"] == "baseline_ready" for x in v),
                   "provisional": sum(x["status"] == "baseline_provisional" for x in v),
                   "insufficient": sum(x["status"] == "insufficient_history" for x in v),
                   "median_fpr": float(np.median(f)) if f else None,
                   "within_3x": sum(x <= 0.03 for x in f)}  # fmt: skip
    gates = [x["update_gate"] for x in res.values() if "update_gate" in x]
    out = {"captures": res, "summary_sample_size": summ,
           "drift_false_alarms": sum(x.get("drift", {}).get("state") == "drift_suspected"
                                     for x in res.values()),
           "update_gate": {"clean_flagged": sum(bool(g["clean_review_required"]) for g in gates),
                           "contaminated_flagged": sum(bool(g["contaminated_review_required"])
                                                       for g in gates), "captures": len(gates)},
           "meta": {"seconds": round(time.perf_counter() - t0, 1),
                    "peak_rss_mb": peak_rss_mb()}}  # fmt: skip
    OUT.write_text(json.dumps(out, indent=1, default=str), "utf-8")
    print(json.dumps({k: out[k] for k in ("summary_sample_size", "drift_false_alarms",
                                          "update_gate", "meta")}, indent=1, default=str))  # fmt: skip


if __name__ == "__main__":
    main()
