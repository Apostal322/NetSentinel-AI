"""Phase 8g step 1: entity windows for a CTU-13 scenario (docs/phase8f/PREREG_CTU13.md s.2-3).

Phase 8b harness protocol (30 s windows by flow END; the stream is time-ordered through
WindowStream with the harness lateness / buffer; calibration destinations expand causally and
are frozen for the test), with the registered split rule instead of the time midpoint:
* calibration = flows ending before (first record start + calibration_hours);
* every calibration flow with an initiator address as source OR destination is removed;
* test = all flows ending at or after the cut (nothing removed).
Global, device and service windows are built in one pass and written as Parquet parts.
No label is read: the conn.log carries none.
Usage: uv run python scripts/phase8g/windows.py <scenario-key> [--config path]
"""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

import polars as pl
import yaml

from netsentinel.behavior.windows import aggregate, prepare_flows
from netsentinel.resources import peak_rss_mb
from netsentinel.streaming.live import END, START, WindowStream
from netsentinel.streaming.offline import parse_health
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log

LEVELS = ("global", "device", "service")
LATENESS_S, MAX_BUFFER = 3700, 1_500_000  # Phase 8b harness values


def load_config(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text("utf-8"))


def initiators(cfg: dict) -> set[str]:
    return set(cfg["initiator_names"].values())


class Builder:
    def __init__(self, cut_ms: int, init: set[str], window_s: int, out: Path):
        self.cut, self.init, self.w, self.out = cut_ms, init, window_s, out
        self.seen: set[str] = set()
        self.parts = {(p, lv): 0 for p in ("cal", "test") for lv in LEVELS}
        self.flows = {"cal_kept": 0, "cal_excluded_initiator": 0, "test": 0}
        out.mkdir(parents=True, exist_ok=True)

    def _write(self, part: str, lv: str, df: pl.DataFrame) -> None:
        if df.height:
            i = self.parts[(part, lv)]
            df.write_parquet(self.out / f"{part}_{lv}_{i:05d}.parquet")
            self.parts[(part, lv)] = i + 1

    def add(self, frame: pl.DataFrame) -> None:
        flows = prepare_flows(frame)
        cal = flows.filter(pl.col("end_ms") < self.cut)
        test = flows.filter(pl.col("end_ms") >= self.cut)
        touch = pl.col("src").is_in(list(self.init)) | pl.col("dst").is_in(list(self.init))
        kept = cal.filter(~touch)
        self.flows["cal_kept"] += kept.height
        self.flows["cal_excluded_initiator"] += cal.height - kept.height
        self.flows["test"] += test.height
        if kept.height:
            for lv in LEVELS:
                self._write("cal", lv, aggregate(kept, lv, self.w, prior_dst=self.seen))
            self.seen |= set(kept["dst"].unique().to_list())
        if test.height:
            for lv in LEVELS:
                self._write("test", lv, aggregate(test, lv, self.w, known_dst=self.seen))


def acceptance(lateness: float, stats) -> str:
    """Amendment A2 rule for a scenario built with a non-default lateness."""
    if lateness == LATENESS_S:
        return "default lateness"
    if stats.late == 0 and stats.forced_closes == 0:
        return "passed (late == 0, forced_closes == 0)"
    return f"failed (late {stats.late}, forced_closes {stats.forced_closes})"


def build(cfg: dict, key: str, batch_flows: int = 200_000) -> dict:
    sc = cfg["scenarios"][key]
    path = Path(cfg["data_root"]) / sc["id"] / sc["conn_log"]
    out = Path(cfg["derived_root"]) / key
    t0 = time.perf_counter()
    first, last, n = math.inf, -math.inf, 0
    for r in read_conn_log(path):  # pass 0: time span only
        first, last, n = min(first, int(r[START])), max(last, int(r[END])), n + 1
    cut = int(first + cfg["calibration_hours"] * 3.6e6)
    for old in out.glob("*.parquet") if out.exists() else ():  # parts of an aborted attempt
        old.unlink()
    (out / "meta.json").unlink(missing_ok=True)
    b = Builder(cut, initiators(cfg), cfg["window_s"], out)
    # Amendment A2: lateness per scenario (default = harness value); a non-default lateness
    # is accepted only if no record was late and no window was force-closed (then every
    # record is in its END window, exactly as with unlimited lateness)
    lateness = sc.get("lateness_s", LATENESS_S)
    ws = WindowStream(cfg["window_s"], lateness_s=lateness, max_buffer=MAX_BUFFER)
    zs = ZeekStats()
    pending: list[dict] = []
    for rec in read_conn_log(path, zs):
        for _, rs in ws.push(rec):
            pending += rs
        if len(pending) >= batch_flows:
            b.add(records_to_frame(pending))
            pending = []
    for _, rs in ws.flush():
        pending += rs
    if pending:
        b.add(records_to_frame(pending))
    pl.DataFrame({"dst": sorted(b.seen)}, schema={"dst": pl.Utf8}).write_parquet(
        out / "calibration_dst.parquet"
    )  # frozen destination set (profile.known_dst)
    meta = {"scenario": key, "id": sc["id"], "records": n, "first_start_ms": int(first),
            "last_end_ms": int(last), "cut_ms": cut,
            "test_hours": (last - cut) / 3.6e6, "flows": b.flows, "parts": {
                f"{p}_{lv}": c for (p, lv), c in b.parts.items()},
            "parse": {"lines": zs.lines, "records": zs.records, "skipped": zs.skipped},
            "telemetry_health": parse_health({"lines": zs.lines, "skipped": zs.skipped}),
            "stream": ws.stats.as_dict(), "lateness_s": lateness,
            "acceptance": acceptance(lateness, ws.stats),
            "seconds": time.perf_counter() - t0, "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    (out / "meta.json").write_text(json.dumps(meta, indent=1, default=str), "utf-8")
    return meta


def load_windows(cfg: dict, key: str, part: str, level: str) -> pl.DataFrame:
    files = sorted((Path(cfg["derived_root"]) / key).glob(f"{part}_{level}_*.parquet"))
    if not files:
        return pl.DataFrame()
    return pl.concat([pl.read_parquet(f) for f in files], how="diagonal_relaxed")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    ap.add_argument("--config", default="configs/phase8g/ctu13.yaml")
    a = ap.parse_args()
    print(json.dumps(build(load_config(a.config), a.scenario), indent=1, default=str))
