"""Phase 8k feasibility gate F0 on the two probe units (PREREGISTRATION.md section 8, step 5).

The probes (AIT `russellmitchell`, UWF week 2024-03-03 - 03-10) are excluded from confirmation.
On each probe this computes ONLY:
  - integrity: rows, null share per canonical field, time span, largest gap between flow ends,
    flows per hour;
  - the CALIBRATION side (flows ending before the time midpoint): label vocabulary and unknown
    labels, calibration-period attackers (the P1x exclusion), benign source hosts, and the P1x
    hold-out (last 30% of calibration slots): windows, hosts, effective hosts, top host share,
    sessions.
No model, score, threshold or detection metric; no evaluation-period label is read.

Gate (as registered: "< 10 calibration hosts -> the family cannot test acceptance"), applied to
the P1x hold-out that every decision rule uses: >= 10 benign hold-out hosts AND >= 10 effective
hosts (M1 and M2 both need >= 10), plus >= 99% of flows with every canonical field.

Output: reports/phase8k/probes.json
Usage: uv run python scripts/run_capped.py -- <python> -I scripts/phase8k/probe_f0.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8k"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8j"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
import build_p1x as BP  # noqa: E402, N812
import telemetry_maps as TM  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

GAP_WINDOWS = 60  # a gap over 30 min of 30 s windows ends a session (calibration_audit.sessions)


def sessions(df: pl.DataFrame) -> np.ndarray:
    """Session id per row, as calibration_audit.sessions (inlined: importing that module after
    build_windows would bind its `common` to scripts/phase6/common.py)."""
    s = df.with_row_index("i").sort("key", "win").with_columns(
        ((pl.col("key") != pl.col("key").shift()) | (pl.col("win").diff() > GAP_WINDOWS))
        .fill_null(True).cum_sum().alias("sid"))  # fmt: skip
    return s.sort("i")["sid"].to_numpy()


PROBES = ROOT / "data" / "raw" / "phase8k_probes"
UWF_FILE = "part-00000-0955ed97-8460-41bd-872a-7375a7f0207e-c000.snappy.parquet"
OUT = ROOT / "reports" / "phase8k" / "probes.json"


def f0(flows: pl.DataFrame, family: str) -> dict:
    t0 = time.perf_counter()
    canon = [c for c in TM.CANON if c not in ("label", "is_attack")]
    nulls = {c: float(flows[c].null_count() / flows.height) for c in canon}
    complete = float(
        flows.select(pl.all_horizontal([pl.col(c).is_not_null() for c in canon])).to_series().mean()
    )
    end = flows["flow_end_milliseconds"].drop_nulls().sort().to_numpy()
    lo, hi = int(end[0]), int(end[-1])
    mid = lo + (hi - lo) // 2
    cal = flows.filter(pl.col("flow_end_milliseconds") < mid)
    vocab = cal.group_by("label").len().sort("len", descending=True)
    unknown = (vocab.filter(~pl.col("label").is_in(sorted(TM.AIT_BENIGN | TM.AIT_MALICIOUS)))
               if family == "F1" else pl.DataFrame())  # fmt: skip
    attackers = set(cal.filter(pl.col("is_attack") > 0)["ipv4_src_addr"].unique().to_list())
    b = BP.P1xBuilder(mid, attackers)
    b.add(cal)
    win = pl.concat(b.cal) if b.cal else pl.DataFrame()
    out = {"rows": flows.height, "complete_share": complete, "null_share": nulls,
           "span_hours": (hi - lo) / 3.6e6, "largest_gap_minutes": float(np.max(np.diff(end)) / 6e4),
           "flows_per_hour_median": float(np.median(np.bincount(((end - lo) // 3_600_000).astype(int)))),
           "calibration_rows": cal.height,
           "calibration_label_vocabulary": {str(k): int(v) for k, v in vocab.iter_rows()},
           "unknown_labels": {str(k): int(v) for k, v in unknown.iter_rows()} if unknown.height else {},
           "calibration_attackers": sorted(attackers),
           "benign_calibration_sources": int(cal.filter(~pl.col("ipv4_src_addr").is_in(sorted(attackers)))
                                             ["ipv4_src_addr"].n_unique())}  # fmt: skip
    if win.height:
        hold = win.filter(pl.col("win") >= BP.C.S.split_cut(win))
        m = hold.group_by("key").len()["len"].to_numpy().astype(float)
        out.update(p1x_calibration_windows=win.height, hold_windows=hold.height, hold_hosts=len(m),
                   hold_effective_hosts=float(m.sum() ** 2 / (m**2).sum()) if len(m) else 0.0,
                   hold_top_host_share=float(m.max() / m.sum()) if len(m) else None,
                   hold_sessions=int(len(np.unique(sessions(hold)))) if hold.height else 0,
                   hold_hosts_by_windows=dict(hold.group_by("key").len().sort("len", descending=True)
                                              .head(15).iter_rows()))  # fmt: skip
    hosts_ok = out.get("hold_hosts", 0) >= 10 and out.get("hold_effective_hosts", 0) >= 10
    out["gate"] = {"hold_hosts_ge_10_and_effective_ge_10": bool(hosts_ok),
                   "fields_complete_ge_99pct": bool(complete >= 0.99),
                   "pass": bool(hosts_ok and complete >= 0.99)}  # fmt: skip
    out["seconds"] = round(time.perf_counter() - t0, 1)
    return out


def main() -> None:
    res = {}
    ait = TM.read_ait(PROBES / "ait" / "extracted")
    res["F1_ait_russellmitchell"] = f0(ait, "F1")
    del ait
    uwf = TM.zeek_conn(pl.read_parquet(PROBES / "uwf" / UWF_FILE))
    res["F2_uwf_2024-03-03"] = f0(uwf, "F2")
    res["peak_rss_mb"] = peak_rss_mb()
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    for k, v in res.items():
        if isinstance(v, dict):
            print(k, {x: v.get(x) for x in ("rows", "complete_share", "span_hours", "largest_gap_minutes",
                                            "flows_per_hour_median", "benign_calibration_sources",
                                            "hold_windows", "hold_hosts", "hold_effective_hosts",
                                            "hold_top_host_share", "gate")})  # fmt: skip
            print("  vocabulary", v["calibration_label_vocabulary"], "unknown", v["unknown_labels"])
            print("  attackers", v["calibration_attackers"])


if __name__ == "__main__":
    main()
