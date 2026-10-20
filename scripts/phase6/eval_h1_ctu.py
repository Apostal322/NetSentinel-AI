"""Phase 6, H1: does local calibration reduce false alerts on unfamiliar BENIGN traffic?

Data: CTU-Normal-26 and CTU-Normal-20..32 Zeek conn logs (never used for any model choice).
Per capture: calibration = flows ending in the first 50% of the capture's time span,
evaluation = the rest. All evaluation windows are benign (dataset provenance), so every alert
is a false alert.
* local profile: `calibrate_flows` (vetted_benign and unlabelled), window 30 s, target
  entity-window FPR 0.01; alerts = anomalous windows at the global/device/service level.
* comparator (uncalibrated Phase-5 bundle): a global 30 s window alerts if any flow in it
  receives verdict "unusual" or "suspicious".
Criteria (docs/phase6/IMPLEMENTATION_PLAN.md + DEVELOPMENT_LOG clarification): median over
captures of local global-level FA/h <= 1/10 of the comparator's window FA/h, AND global-window
FPR <= 3 x target in >= 75% of captures.

Usage: uv run python scripts/phase6/eval_h1_ctu.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.behavior.calibrate import calibrate_flows
from netsentinel.behavior.monitor import score_flows
from netsentinel.inference.engine import Engine
from netsentinel.resources import peak_rss_mb
from netsentinel.streaming.offline import load_capture

BUNDLE = "models/bundle-20261019T202605Z"
WINDOW = 30
TARGET = 0.01
OUT = Path("reports/phase6")


def captures() -> list[Path]:
    caps = [Path("data/raw/ctu_normal_26/bro/conn.log")]
    caps += sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log"))
    return caps


def main() -> None:
    engine = Engine(BUNDLE)
    rows = []
    t0 = time.perf_counter()
    for cap in captures():
        name = cap.parent.name if cap.parent.name != "bro" else "CTU-Normal-26"
        frame, _, parse = load_capture(cap, "zeek")
        end = frame["flow_end_milliseconds"]
        mid = int(end.min() + (end.max() - end.min()) // 2)
        cal = frame.filter(pl.col("flow_end_milliseconds") < mid)
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        hours = (int(ev["flow_end_milliseconds"].max()) - mid) / 3.6e6
        rec: dict = {"capture": name, "flows_cal": cal.height, "flows_eval": ev.height,
                     "eval_hours": round(hours, 3)}  # fmt: skip
        for mode in ("vetted_benign", "unlabelled"):
            prof = calibrate_flows(cal, window_s=WINDOW, mode=mode, target_fpr=TARGET)
            rec[f"{mode}_status"] = prof.status
            if prof.status != "baseline_ready":
                continue
            s = score_flows(prof, ev)
            for lv in ("global", "device", "service"):
                d = s.filter(pl.col("level") == lv)
                if d.height:
                    rec[f"{mode}_{lv}_fpr"] = float(d["anomalous"].mean())
                    rec[f"{mode}_{lv}_fa_per_h"] = float(d["anomalous"].sum()) / hours
                    rec[f"{mode}_{lv}_windows"] = d.height
        # comparator: uncalibrated bundle verdicts aggregated to global windows
        scored, _ = engine.score(ev, context="compute")
        alert = scored["verdict"].is_in(["unusual", "suspicious"])
        win = (scored["flow_end_milliseconds"] // (WINDOW * 1000)).alias("win")
        g = pl.DataFrame({"win": win, "alert": alert}).group_by("win").agg(pl.col("alert").any())
        w_ms = WINDOW * 1000
        n_windows = int(ev["flow_end_milliseconds"].max()) // w_ms - mid // w_ms + 1
        rec["bundle_flow_unusual_or_suspicious_share"] = float(alert.mean())
        rec["bundle_global_window_fa_per_h"] = float(g["alert"].sum()) / hours
        rec["bundle_global_window_fpr"] = float(g["alert"].sum()) / n_windows
        rows.append(rec)
        print(name, {k: round(v, 4) if isinstance(v, float) else v for k, v in rec.items()},
              flush=True)  # fmt: skip
    df = pl.DataFrame(rows)
    med = lambda c: float(np.nanmedian(df[c].to_numpy())) if c in df.columns else None  # noqa: E731
    local = med("vetted_benign_global_fa_per_h")
    comp = med("bundle_global_window_fa_per_h")
    ok_fpr = float((df["vetted_benign_global_fpr"] <= 3 * TARGET).mean())
    verdict = {
        "median_local_global_fa_per_h": local, "median_bundle_window_fa_per_h": comp,
        "share_captures_global_fpr_le_3x_target": ok_fpr,
        "criterion_ratio": local <= comp / 10, "criterion_fpr": ok_fpr >= 0.75,
        "H1_supported": bool(local <= comp / 10 and ok_fpr >= 0.75),
        "median_unlabelled_global_fa_per_h": med("unlabelled_global_fa_per_h"),
        "median_vetted_device_fa_per_h": med("vetted_benign_device_fa_per_h"),
        "median_vetted_service_fa_per_h": med("vetted_benign_service_fa_per_h"),
        "seconds": round(time.perf_counter() - t0, 1), "peak_rss_mb": peak_rss_mb(),
    }  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "h1_ctu.json").write_text(json.dumps({"captures": rows, "summary": verdict},
                                                indent=1, default=str), "utf-8")  # fmt: skip
    print(json.dumps(verdict, indent=1))


if __name__ == "__main__":
    main()
