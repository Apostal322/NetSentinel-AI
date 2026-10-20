"""Phase 8C incident evaluation (development data; product scorer = robust median/MAD).

For each source: anomalous behaviour windows (alerts) -> incidents (gap 300 s). Reports per
level: alerts/h vs incidents/h (all, and excluding insufficient_evidence), alert reduction,
incident purity (share of an incident's windows that contain attack flows), incidents that
contain any attack window, window recall, and fragmentation (incidents with attack windows per
attacking entity).

* demo: the synthetic demo capture with known ground truth (software check; device + global).
* iot23: the 9 inspected IoT-23 scenarios, clean calibration on the first half (as Phase 6).

Usage: uv run python scripts/phase8/eval_incidents.py [demo|iot23|all]
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.incidents import IncidentTracker
from netsentinel.resources import peak_rss_mb

OUT = Path("reports/phase8")
GAP_S = 300


def summarise(scored: pl.DataFrame, truth: dict, hours: float, window_s: int,
              levels=("device", "service", "global")) -> dict:  # fmt: skip
    """scored: behaviour windows; truth: {(level, key, win): is_attack_window}."""
    t = IncidentTracker("eval", "eval", window_s, gap_s=GAP_S)
    t.add_windows(scored)
    res: dict = {}
    for lv in levels:
        d = scored.filter(pl.col("level") == lv)
        if not d.height:
            continue
        a = d.filter(pl.col("anomalous"))
        labels: dict[str, list[bool]] = defaultdict(list)
        for r in a.iter_rows(named=True):
            iid = t._by_window[(lv, str(r["key"]), int(r["window_end_ms"]))]
            labels[iid].append(truth.get((lv, str(r["key"]), int(r["win"])), False))
        li = [i for i in t.incidents() if i.level == lv]
        per_entity: dict[str, int] = defaultdict(int)
        for i in li:
            if any(labels[i.incident_id]):
                per_entity[i.entity] += 1
        y = np.array([truth.get((lv, str(k), int(w)), False)
                      for k, w in zip(d["key"].to_list(), d["win"].to_list(), strict=True)])  # fmt: skip
        an = d["anomalous"].to_numpy()
        n_ins = sum(i.status == "insufficient_evidence" for i in li)
        att_entities = {k for (lv2, k, _), v in truth.items() if lv2 == lv and v}
        res[lv] = {
            "windows": d.height, "attack_windows": int(y.sum()),
            "alerts": a.height, "alerts_per_h": a.height / hours,
            "false_alerts_per_h": float((an & ~y).sum()) / hours,
            "incidents": len(li), "incidents_per_h": len(li) / hours,
            "incidents_excl_insufficient_per_h": (len(li) - n_ins) / hours,
            "benign_only_incidents_per_h": sum(not any(labels[i.incident_id]) for i in li) / hours,
            "alert_reduction": a.height / len(li) if li else None,
            "mean_purity": float(np.mean([np.mean(labels[i.incident_id]) for i in li]))
            if li else None,
            "incidents_with_attack": sum(any(labels[i.incident_id]) for i in li),
            "window_recall": float(an[y].mean()) if y.any() else None,
            "attacking_entities": len(att_entities),
            "attacking_entities_detected": len(per_entity),
            "max_incidents_per_attacking_entity": max(per_entity.values()) if per_entity else 0,
            "severity": {s: sum(i.severity == s for i in li) for s in ("low", "medium", "high")},
        }  # fmt: skip
    return res


def demo() -> dict:
    from netsentinel.demo.fixtures import demo_labels
    from netsentinel.demo.runner import run_demo

    ws = Path(tempfile.mkdtemp(prefix="ns-inc-")) / "ws"
    r = run_demo(ws, quiet=True)
    rows = sqlite3.connect(r["events_db"]).execute(
        "SELECT level, entity, window_end, window_s, n_flows, score, threshold, anomalous "
        "FROM behavior_events").fetchall()  # fmt: skip
    df = pl.DataFrame(rows, orient="row", schema=["level", "key", "window_end", "window_s",
                                                  "n_flows", "score", "threshold", "anomalous"])  # fmt: skip
    w_s = int(df["window_s"][0])
    df = df.with_columns(
        pl.col("window_end").str.to_datetime().dt.replace_time_zone("UTC").dt.epoch("ms")
        .alias("window_end_ms"), pl.col("anomalous").cast(pl.Boolean),
        pl.lit(None, dtype=pl.List(pl.Utf8)).alias("explanation"),
    ).with_columns((pl.col("window_end_ms") - w_s * 1000).alias("window_start_ms"),
                   (pl.col("window_end_ms") // (w_s * 1000) - 1).alias("win"))  # fmt: skip
    lab = demo_labels()
    t0 = lab["t0"] * 1000
    truth = {}
    for row in df.iter_rows(named=True):
        s, e = row["window_start_ms"] - t0, row["window_end_ms"] - t0
        hit = False
        for g in (lab["ssh_bruteforce"], lab["port_scan"]):
            # flows are assigned by END time; a few ms of slack for the last attempts
            overlap = s < g["end_s"] * 1000 + 100 and e > g["start_s"] * 1000
            hit |= overlap and (row["level"] == "global" or row["key"] == g["src"])
        truth[(row["level"], str(row["key"]), int(row["win"]))] = hit
    hours = (df["window_end_ms"].max() - df["window_start_ms"].min()) / 3.6e6
    out = summarise(df, truth, hours, w_s, levels=("device", "global"))
    out["store_incidents"] = r.get("incidents", {}).get("count")
    return out


def iot23() -> dict:
    from netsentinel.behavior.calibrate import calibrate_flows
    from netsentinel.behavior.monitor import score_flows
    from netsentinel.behavior.windows import _key_expr, prepare_flows
    from netsentinel.streaming.offline import load_capture

    def is_attack(d: dict) -> float:
        return 1.0 if str(d.get("label", "")).lower().startswith("malicious") else 0.0

    res = {}
    for f in sorted(Path("data/raw/iot23").glob("*/conn.log.labeled")):
        frame, _, _ = load_capture(f, "zeek", zeek_extras={"IS_ATTACK": is_attack})
        end = frame["flow_end_milliseconds"]
        mid = int(end.min() + (end.max() - end.min()) // 2)
        cal = frame.filter((pl.col("flow_end_milliseconds") < mid) & (pl.col("is_attack") == 0))
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        if not cal.height:
            res[f.parent.name] = {"status": "no benign calibration flows"}
            continue
        prof = calibrate_flows(cal, window_s=30, mode="vetted_benign", target_fpr=0.01)
        if prof.status not in ("baseline_ready", "baseline_provisional"):
            res[f.parent.name] = {"status": prof.status}
            continue
        sc = score_flows(prof, ev)
        pf = prepare_flows(ev)
        truth = {}
        for lv in ("global", "device", "service"):
            g = (pf.with_columns((pl.col("end_ms") // 30_000).alias("win"), _key_expr(lv))
                 .group_by("key", "win").agg((pl.col("is_attack").max() > 0).alias("y")))  # fmt: skip
            truth |= {(lv, str(k), int(w)): bool(y) for k, w, y in g.iter_rows()}
        hours = (int(end.max()) - mid) / 3.6e6
        res[f.parent.name] = summarise(sc, truth, hours, 30)
        d = res[f.parent.name].get("device", {})
        print(f.parent.name, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in d.items()
                              if k in ("alerts_per_h", "incidents_per_h", "mean_purity",
                                       "window_recall", "max_incidents_per_attacking_entity")},
              flush=True)  # fmt: skip
    return res


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    t0 = time.perf_counter()
    res = {}
    if which in ("demo", "all"):
        res["demo"] = demo()
        print("demo", json.dumps(res["demo"], default=str), flush=True)
    if which in ("iot23", "all"):
        res["iot23"] = iot23()
    res["meta"] = {"seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb(),
                   "gap_s": GAP_S}  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"incidents_{which}.json").write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(res["meta"])


if __name__ == "__main__":
    main()
