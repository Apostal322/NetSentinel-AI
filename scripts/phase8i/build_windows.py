"""Phase 8i: device windows per network, with calibration-period labels
(docs/phase8i/PREREGISTRATION.md section 2).

Same windows as Phase 8h (Phase 8b `WindowBuilder`: 30 s device windows by flow END time,
calibration = flows ending before the time midpoint of the domain's span, clean and unlabelled calibration variants,
truth per evaluation window). Phase 8i adds `cal_truth.parquet`: whether each UNLABELLED
calibration window holds an attack flow. It is needed only for the label-budget experiment
(the labelled target windows are drawn from the calibration period).

Inputs are streamed in time order across all files, so that a window spanning a day-file
boundary is aggregated once (the Phase 8b builder split such windows in two). Every slice
handed to the builder holds at most `MAX_ROWS` flows, cut on the 30 s window grid
(`window_ranges`), and is read one Parquet row group at a time, each filtered at once
(`_read_range`), so the flow data in memory is bounded by the slice and row-group sizes, not
by the traffic rate. (All timestamps and the per-window builder state still grow with the
capture length.) The features do not depend on where the cuts fall (`aggregate` carries earlier
destinations across slices). Before the Phase 8i audit, full captures were read in one-hour
slices by repeated lazy Polars scans, whose memory grew with every scan, and development parts
file by file; NF-BoT-IoT-v3 then peaked at 4.1 GB (docs/phase8i/AUDIT_TRAIL.md, item 7). The
audit version reproduces the frozen windows of every development network exactly.

Networks
  nfcic   NF-CIC-IDS2018-v3, development part (first 78% of each day), one domain per day,
          `infiltration` evaluation windows listed in noisy.parquet (as Phase 8h)
  nfunsw  NF-UNSW-NB15-v3, development part, one domain, split at the median flow end (as
          Phase 8b; its time midpoint falls in the 26-day gap between its two sessions)
  nfton   NF-ToN-IoT-v3, all flows (development network; never a test set), one domain
  nfbot   NF-BoT-IoT-v3, all flows: PROTECTED. Refused unless --protected-confirm is given and
          docs/phase8i/FREEZE.md exists (written when the protocol and code are frozen).

Output: data/derived/phase8i/<network>/<domain>/ and reports/phase8i/windows_<network>.json
(with --out DIR: DIR/<network>/<domain>/ and DIR/windows_<network>.json)
Usage: uv run python scripts/phase8i/build_windows.py nfcic|nfunsw|nfton [--days a,b]
       [--out DIR] [--max-rows N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from math import inf
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(ROOT / "scripts" / "phase6"))
from eval_nf_dev import COLS, DEV_SHARE  # noqa: E402
from harness import LEVEL, W, WindowBuilder  # noqa: E402

from netsentinel.behavior.windows import _key_expr, prepare_flows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("data/derived/phase8i")
REPORTS = Path("reports/phase8i")
NETWORKS = {
    "nfcic": ("data/interim/nf_cicids2018_v3", True, True),
    "nfunsw": ("data/interim/nf_unsw_nb15_v3", True, False),
    "nfton": ("data/interim/nf_ton_iot_v3", False, False),
    "nfbot": ("data/interim/nf_bot_iot_v3", False, False),
}  # (dir, dev_cut, per_day)
NOISY = "infiltration"
MAX_ROWS = 500_000  # flows per builder slice


class LabelledCalBuilder(WindowBuilder):
    def __init__(self, mid_ms: int):
        super().__init__(mid_ms)
        self.cal_truth: list[pl.DataFrame] = []

    def add(self, frame: pl.DataFrame) -> None:
        super().add(frame)
        cal = prepare_flows(frame).filter(pl.col("end_ms") < self.mid)
        if cal.height:
            self.cal_truth.append(
                cal.with_columns((pl.col("end_ms") // (W * 1000)).alias("win"), _key_expr(LEVEL))
                .group_by("key", "win").agg((pl.col("is_attack").max() > 0).alias("y")))  # fmt: skip

    def save(self, out: Path, meta: dict) -> None:
        super().save(out, meta)
        ct = pl.concat(self.cal_truth) if self.cal_truth else pl.DataFrame(
            schema={"key": pl.Utf8, "win": pl.Int64, "y": pl.Boolean})  # fmt: skip
        ct.write_parquet(out / "cal_truth.parquet")


def with_flags(df: pl.DataFrame) -> pl.DataFrame:
    return df.with_columns(
        ((pl.col("client_tcp_flags") & 4) > 0).cast(pl.Int8).alias("cli_rst"),
        ((pl.col("server_tcp_flags") & 4) > 0).cast(pl.Int8).alias("srv_rst"),
        (pl.col("label") != "benign").cast(pl.Float64).alias("is_attack"),
    ).sort("flow_end_milliseconds")


def window_ranges(wins: pl.DataFrame, max_rows: int) -> list[tuple[int, int]]:
    """[lo, hi) window-index ranges covering `wins` (columns win, len; sorted by win), each
    holding at most `max_rows` flows, unless a single window holds more."""
    out, lo, rows = [], None, 0
    for w, n in wins.iter_rows():
        if lo is not None and rows + n > max_rows:
            out.append((lo, w))
            lo, rows = None, 0
        lo = w if lo is None else lo
        rows += n
    if lo is not None:
        out.append((lo, int(wins["win"][-1]) + 1))
    return out


def _win_counts(frame: pl.DataFrame | pl.LazyFrame):
    win = (pl.col("flow_end_milliseconds") // (W * 1000)).alias("win")
    return frame.select(win).group_by("win").len().sort("win")


def _in_range(lo: int, hi: int) -> pl.Expr:
    e = pl.col("flow_end_milliseconds")
    return (e >= lo * W * 1000) & (e < hi * W * 1000)


def _cuts(files: list[Path], dev_cut: bool) -> dict[Path, float]:
    """Per-file bound on the flow end: the development part ends at 78% of each file's own
    span (as Phase 8h); full captures have none."""
    if not dev_cut:
        return {f: inf for f in files}
    out = {}
    for f in files:
        e = pl.col("flow_end_milliseconds")
        lo, hi = pl.scan_parquet(f).select(e.min(), e.max().alias("hi")).collect().row(0)
        out[f] = int(lo + DEV_SHARE * (hi - lo)) if lo is not None else -inf
    return out


def _ends(files: list[Path], cuts: dict[Path, float]) -> pl.LazyFrame:
    e = pl.col("flow_end_milliseconds")
    return pl.concat([pl.scan_parquet(f).select(e).filter(e < cuts[f]) for f in files])


def _row_groups(files: list[Path], cuts: dict[Path, float]) -> list[tuple]:
    """(ParquetFile, row group, min end, max end, file cut) from the Parquet statistics."""
    import pyarrow.parquet as pq

    out = []
    for f in files:
        pf = pq.ParquetFile(f)
        ci = pf.schema_arrow.get_field_index("flow_end_milliseconds")
        for g in range(pf.metadata.num_row_groups):
            st = pf.metadata.row_group(g).column(ci).statistics
            lo, hi = (st.min, st.max) if st is not None and st.has_min_max else (-inf, inf)
            out.append((pf, g, lo, hi, cuts[f]))
    return out


def _read_range(rgs: list, lo: int, hi: int) -> pl.DataFrame:
    """Flows ending in windows [lo, hi) (and before their file's cut), read row group by row
    group and filtered at once: at most one decoded row group exists beside the slice being
    assembled. (Repeated lazy scans grew by ~26 MB per slice on NF-ToN-IoT while holding
    nothing: the audit's root cause.)"""
    a, z = lo * W * 1000, hi * W * 1000
    e = pl.col("flow_end_milliseconds")
    return pl.concat([pl.from_arrow(pf.read_row_groups([g], columns=COLS))
                      .filter(_in_range(lo, hi) & (e < cut))
                      for pf, g, mn, mx, cut in rgs if mx >= a and mn < min(z, cut)])  # fmt: skip


def chunks(files: list[Path], dev_cut: bool, max_rows: int = MAX_ROWS):
    """Time-ordered frames of COMPLETE windows across all files (a window spanning a file
    boundary comes in one frame), each of at most `max_rows` flows unless one window holds
    more. Only the timestamps are ever loaded in full. dev_cut: each file cut at 78% of its
    own span first (`_cuts`)."""
    cuts = _cuts(files, dev_cut)
    rgs = _row_groups(files, cuts)
    for lo, hi in window_ranges(_win_counts(_ends(files, cuts)).collect(), max_rows):
        # no local reference: the raw frame is freed as soon as with_flags has copied it
        yield with_flags(_read_range(rgs, lo, hi))


def build(files: list[Path], dev_cut: bool, out: Path, source: str, split: str = "time",
          max_rows: int = MAX_ROWS) -> dict:  # fmt: skip
    """One domain from time-ordered files (`chunks`)."""
    t0 = time.perf_counter()
    ends = _ends(files, _cuts(files, dev_cut)).collect()
    if ends.height == 0:
        return {"status": "empty"}
    e = ends["flow_end_milliseconds"]
    if split == "median":  # NF-UNSW: the Phase 8b split (its time midpoint lies between sessions)
        mid = int(e.quantile(0.5))
    else:  # the registered time midpoint of the domain's span (Phase 8h; amendment A2)
        lo, hi = int(e.min()), int(e.max())
        mid = lo + (hi - lo) // 2
    del ends, e
    b = LabelledCalBuilder(mid)
    n, labels, noisy = 0, {}, []
    for df in chunks(files, dev_cut, max_rows):
        b.add(df)
        n += df.height
        ev = df.filter(pl.col("flow_end_milliseconds") >= mid)
        for lab, c in ev.group_by("label").len().iter_rows():
            labels[lab] = labels.get(lab, 0) + c
        noisy.append(ev.filter(pl.col("label") == NOISY)
                     .select(pl.col("ipv4_src_addr").alias("key"),
                             (pl.col("flow_end_milliseconds") // (W * 1000)).alias("win")))  # fmt: skip
        del df, ev  # release this slice before the next one is loaded
    b.save(out, {"source": source, "dev_share": DEV_SHARE if dev_cut else 1.0, "split": split})
    nz = pl.concat(noisy).unique() if noisy else pl.DataFrame()
    if nz.height:
        nz.write_parquet(out / "noisy.parquet")
    tr = pl.read_parquet(out / "truth.parquet")
    ct = pl.read_parquet(out / "cal_truth.parquet")
    att = tr.filter(pl.col("y"))
    if nz.height:
        att = att.join(nz, on=["key", "win"], how="anti")
    return {"flows": n, "mid_ms": mid, "eval_labels": labels,
            "cal_windows_clean": pl.read_parquet(out / "cal_clean.parquet").height,
            "cal_attack_windows": int(ct["y"].sum()) if ct.height else 0,
            "cal_attack_entities": ct.filter(pl.col("y"))["key"].n_unique() if ct.height else 0,
            "eval_windows": tr.height, "attack_windows": att.height,
            "attack_entities": att["key"].n_unique(), "noisy_windows": nz.height,
            "entities": tr["key"].n_unique(), "seconds": time.perf_counter() - t0}  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("network", choices=sorted(NETWORKS))
    ap.add_argument("--days")
    ap.add_argument("--protected-confirm", action="store_true")
    ap.add_argument("--out", type=Path, help="output root instead of data/derived/phase8i")
    ap.add_argument("--max-rows", type=int, default=MAX_ROWS)
    a = ap.parse_args()
    out_root, reports = (a.out, a.out) if a.out else (OUT, REPORTS)
    if a.network == "nfbot" and not (
        a.protected_confirm and Path("docs/phase8i/FREEZE.md").exists()
    ):
        sys.exit("nfbot is the protected Phase 8i test: freeze first (docs/phase8i/FREEZE.md) "
                 "and pass --protected-confirm")  # fmt: skip
    src, dev_cut, per_day = NETWORKS[a.network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    if not files:
        sys.exit(f"no ingested day files under {src}")
    t0 = time.perf_counter()
    res = {}
    if per_day:
        for f in files:
            if a.days and f.stem not in a.days.split(","):
                continue
            res[f.stem] = build([f], dev_cut, out_root / a.network / f.stem,
                                f"{a.network} {f.stem}", max_rows=a.max_rows)  # fmt: skip
            print(f.stem, json.dumps(res[f.stem], default=str), flush=True)
    else:
        split = "median" if a.network == "nfunsw" else "time"
        res["all"] = build(files, dev_cut, out_root / a.network / "all", a.network, split,
                           a.max_rows)  # fmt: skip
        print(json.dumps(res["all"], default=str), flush=True)
    reports.mkdir(parents=True, exist_ok=True)
    rep = reports / f"windows_{a.network}.json"
    prev = json.loads(rep.read_text("utf-8"))["domains"] if rep.exists() else {}
    rep.write_text(json.dumps({"domains": {**prev, **res}, "seconds": time.perf_counter() - t0,
                               "max_rows": a.max_rows, "peak_rss_mb": peak_rss_mb()}, indent=1, default=str), "utf-8")  # fmt: skip


if __name__ == "__main__":
    main()
