"""Phase 8i: device windows per network, with calibration-period labels
(docs/phase8i/PREREGISTRATION.md section 2).

Same windows as Phase 8h (Phase 8b `WindowBuilder`: 30 s device windows by flow END time,
calibration = flows ending before the time midpoint, clean and unlabelled calibration variants,
truth per evaluation window). Phase 8i adds `cal_truth.parquet`: whether each UNLABELLED
calibration window holds an attack flow. It is needed only for the label-budget experiment
(the labelled target windows are drawn from the calibration period).

Inputs are streamed in time order so that a window spanning a day-file boundary is aggregated
once (the Phase 8b builder split such windows in two): development parts file by file with the
last window carried forward; full captures in one-hour slices across all files (`chunks`).

Networks
  nfcic   NF-CIC-IDS2018-v3, development part (first 78% of each day), one domain per day,
          `infiltration` evaluation windows listed in noisy.parquet (as Phase 8h)
  nfunsw  NF-UNSW-NB15-v3, development part, one domain, global midpoint (as Phase 8b)
  nfton   NF-ToN-IoT-v3, all flows (development network; never a test set), one domain
  nfbot   NF-BoT-IoT-v3, all flows: PROTECTED. Refused unless --protected-confirm is given and
          docs/phase8i/FREEZE.md exists (written when the protocol and code are frozen).

Output: data/derived/phase8i/<network>/<domain>/ and reports/phase8i/windows_<network>.json
Usage: uv run python scripts/phase8i/build_windows.py nfcic|nfunsw|nfton [--days a,b]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
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
NETWORKS = {"nfcic": ("data/interim/nf_cicids2018_v3", True, True),
            "nfunsw": ("data/interim/nf_unsw_nb15_v3", True, False),
            "nfton": ("data/interim/nf_ton_iot_v3", False, False),
            "nfbot": ("data/interim/nf_bot_iot_v3", False, False)}  # (dir, dev_cut, per_day)
NOISY = "infiltration"


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


def read(path: Path, dev_cut: bool) -> pl.DataFrame:
    df = pl.read_parquet(path, columns=COLS)
    if dev_cut and df.height:
        e = df["flow_end_milliseconds"]
        df = df.filter(pl.col("flow_end_milliseconds")
                       < int(e.min() + DEV_SHARE * (e.max() - e.min())))  # fmt: skip
    return with_flags(df)


def with_flags(df: pl.DataFrame) -> pl.DataFrame:
    return df.with_columns(
        ((pl.col("client_tcp_flags") & 4) > 0).cast(pl.Int8).alias("cli_rst"),
        ((pl.col("server_tcp_flags") & 4) > 0).cast(pl.Int8).alias("srv_rst"),
        (pl.col("label") != "benign").cast(pl.Float64).alias("is_attack"),
    ).sort("flow_end_milliseconds")


def chunks(files: list[Path], dev_cut: bool):
    """Time-ordered frames of COMPLETE windows.
    dev_cut: whole files (each cut at 78% of its own span), each file's last window carried
    into the next. Otherwise: all files scanned together in one-hour slices aligned to the
    window grid (bounded memory for multi-million-flow days)."""
    if dev_cut:
        carry = None
        for i, f in enumerate(files):
            df = read(f, dev_cut)
            if carry is not None:
                df = pl.concat([carry, df]).sort("flow_end_milliseconds")
            if df.height and i < len(files) - 1:
                last = int(df["flow_end_milliseconds"].max()) // (W * 1000)
                cut = pl.col("flow_end_milliseconds") // (W * 1000) < last
                carry, df = df.filter(~cut), df.filter(cut)
            if df.height:
                yield df
        return
    lf = pl.scan_parquet([str(f) for f in files]).select(COLS)
    span = lf.select(pl.col("flow_end_milliseconds").min().alias("lo"),
                     pl.col("flow_end_milliseconds").max().alias("hi")).collect()  # fmt: skip
    step = 3_600_000  # a multiple of the 30 s window: no window spans two slices
    t = int(span["lo"][0]) // step * step
    while t <= int(span["hi"][0]):
        e = pl.col("flow_end_milliseconds")
        df = lf.filter((e >= t) & (e < t + step)).collect()
        if df.height:
            yield with_flags(df)
        t += step


def build(files: list[Path], dev_cut: bool, out: Path, source: str) -> dict:
    """One domain from time-ordered files (`chunks`)."""
    t0 = time.perf_counter()
    if dev_cut:
        ends = pl.concat([read(f, dev_cut).select("flow_end_milliseconds") for f in files])
    else:
        ends = pl.scan_parquet([str(f) for f in files]).select("flow_end_milliseconds").collect()
    if ends.height == 0:
        return {"status": "empty"}
    mid = int(ends["flow_end_milliseconds"].quantile(0.5))
    del ends
    b = LabelledCalBuilder(mid)
    n, labels, noisy = 0, {}, []
    for df in chunks(files, dev_cut):
        b.add(df)
        n += df.height
        ev = df.filter(pl.col("flow_end_milliseconds") >= mid)
        for lab, c in ev.group_by("label").len().iter_rows():
            labels[lab] = labels.get(lab, 0) + c
        noisy.append(ev.filter(pl.col("label") == NOISY)
                     .select(pl.col("ipv4_src_addr").alias("key"),
                             (pl.col("flow_end_milliseconds") // (W * 1000)).alias("win")))  # fmt: skip
    b.save(out, {"source": source, "dev_share": DEV_SHARE if dev_cut else 1.0})
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
    a = ap.parse_args()
    if a.network == "nfbot" and not (a.protected_confirm and Path("docs/phase8i/FREEZE.md").exists()):
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
            res[f.stem] = build([f], dev_cut, OUT / a.network / f.stem, f"{a.network} {f.stem}")
            print(f.stem, json.dumps(res[f.stem], default=str), flush=True)
    else:
        res["all"] = build(files, dev_cut, OUT / a.network / "all", a.network)
        print(json.dumps(res["all"], default=str), flush=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    rep = REPORTS / f"windows_{a.network}.json"
    prev = json.loads(rep.read_text("utf-8"))["domains"] if rep.exists() else {}
    rep.write_text(json.dumps({"domains": {**prev, **res}, "seconds": time.perf_counter() - t0,
                               "peak_rss_mb": peak_rss_mb()}, indent=1, default=str), "utf-8")  # fmt: skip


if __name__ == "__main__":
    main()
