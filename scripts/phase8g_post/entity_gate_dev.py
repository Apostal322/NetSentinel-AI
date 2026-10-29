"""Phase 8g post-hoc [E]: cost of the per-entity review rule of registry.update_check on
DEVELOPMENT data (the 12 benign CTU-Normal captures of scripts/phase8/robust_normality.py,
already inspected in Phases 6-8), docs/phase8g/V4_FAILURE_ANALYSIS.md section 5.

Same protocol as the Phase 8F update-gate study: current baseline = first half of each
capture (vetted_benign, 30 s); candidate = second half, clean and with a 60 s scan injected.
Writes reports/phase8g_post/entity_gate_dev.json; the Phase 8F report is not touched.
Adoption rule, fixed before this run: at most 1 of 12 clean periods newly requires review,
and no scan caught by the Phase 8F gate is lost.
Usage: uv run python scripts/phase8g_post/entity_gate_dev.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8"))
from robust_normality import scan_rows  # noqa: E402

from netsentinel.behavior.calibrate import calibrate_flows, save_profile  # noqa: E402
from netsentinel.behavior.registry import update_check  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.offline import load_capture  # noqa: E402

OUT = Path("reports/phase8g_post/entity_gate_dev.json")
PHASE8F = Path("reports/phase8/robust_normality.json")


def brief(chk: dict) -> dict:
    return {k: chk[k] for k in ("review_required", "rate_review", "excess_entity_count",
                                "reason")} | {"strong_outliers": len(chk["strong_outliers"]),
                                              "excess_entities": chk["excess_entities"][:5]}  # fmt: skip


def main() -> None:
    t0 = time.perf_counter()
    old = json.loads(PHASE8F.read_text("utf-8"))["captures"]
    caps = [Path("data/raw/ctu_normal_26/bro/conn.log"),
            *sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log"))]  # fmt: skip
    with tempfile.TemporaryDirectory(prefix="ns-8g-entity-", ignore_cleanup_errors=True) as t:
        res = run(caps, old, Path(t))
    summarize(res, t0)


def run(caps: list[Path], old: dict, tmp: Path) -> dict:
    res: dict = {}
    for cap in caps:
        name = cap.parent.name if cap.parent.name != "bro" else "CTU-Normal-26"
        if "update_gate" not in old.get(name, {}):
            continue
        frame, _, _ = load_capture(cap, "zeek")
        end = frame["flow_end_milliseconds"]
        lo, hi = int(end.min()), int(end.max())
        mid = lo + (hi - lo) // 2
        prof = calibrate_flows(frame.filter(pl.col("flow_end_milliseconds") < mid), window_s=30,
                               mode="vetted_benign")  # fmt: skip
        ev = frame.filter(pl.col("flow_end_milliseconds") >= mid)
        cur = save_profile(prof, tmp, sources=[], operator_statement="8g entity-gate study")
        clean = update_check(cur, ev)
        dirty = update_check(cur, pl.concat([ev, scan_rows(ev, mid + (hi - mid) // 2)]).sort(
            "flow_end_milliseconds"))  # fmt: skip
        g8f = old[name]["update_gate"]
        res[name] = {"clean": brief(clean), "contaminated": brief(dirty),
                     "phase8f_clean_review": g8f["clean_review_required"],
                     "phase8f_contaminated_review": g8f["contaminated_review_required"]}  # fmt: skip
        print(name, clean["review_required"], clean["excess_entity_count"],
              dirty["review_required"], g8f["clean_review_required"],
              g8f["contaminated_review_required"], flush=True)  # fmt: skip
    return res


def summarize(res: dict, t0: float) -> None:
    new_clean = sum(r["clean"]["review_required"] and not r["phase8f_clean_review"]
                    for r in res.values())  # fmt: skip
    lost = sum(r["phase8f_contaminated_review"] and not r["contaminated"]["review_required"]
               for r in res.values())  # fmt: skip
    out = {"label": "[E] development data (CTU-Normal, inspected in Phases 6-8)",
           "captures": res,
           "summary": {"captures": len(res),
                       "clean_review": sum(r["clean"]["review_required"] for r in res.values()),
                       "clean_review_new": new_clean,
                       "contaminated_review": sum(r["contaminated"]["review_required"]
                                                  for r in res.values()),
                       "contaminated_lost": lost,
                       "adopt": new_clean <= 1 and lost == 0},
           "seconds": time.perf_counter() - t0, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    OUT.write_text(json.dumps(out, indent=1, default=str), "utf-8")
    print(json.dumps(out["summary"], indent=1))


if __name__ == "__main__":
    main()
