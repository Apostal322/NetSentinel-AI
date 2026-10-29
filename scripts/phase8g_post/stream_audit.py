"""Phase 8g post-hoc [R]: real-data streaming audit on the consumed CTU-13 scenarios 9 and 10
(docs/phase8g/REAL_DATA_STREAMING_AUDIT.md).

Engineering verification only. Nothing here changes or replaces the frozen Phase 8g results
(code 121acbf, reports/phase8g/results.json) or the frozen window parts in
data/derived/phase8g. Everything is written to data/derived/phase8g_post and
reports/phase8g_post.

Steps (one process each, one heavy job at a time):
  cache      parse conn.log once with the product parser (SHA-256 checked against the
             registry) -> arrival-ordered Parquet parts of the record dicts, their file
             position `seq` and a 64-bit hash of the stream's DEDUP_KEY
  reference  exact offline reference: every record in the window of its END, duplicates
             (same DEDUP_KEY in the same window) removed keeping the first arrival; windows
             in order through the frozen windows.Builder (same split, batches of whole
             windows)
  stream     replay the cache through a WindowStream (`current` code, or the `frozen`
             121acbf module from git) with the given lateness / buffer / spill budget. Same
             window layout and meta.json as scripts/phase8g/windows.py (acceptance by the A2
             rule), plus record membership, per-record fates and resource measurements
  compare    record / window / feature / score / alert discrepancy tables of a run vs the
             reference -> reports/phase8g_post/<scenario>_<run>_compare.json (+ Parquet)
  compare-frozen  the published frozen window parts vs the reference (features, scores, alerts)
  evaluate   the frozen evaluate.scenario() on a run's windows (exploratory, labelled [R])
Usage: uv run python scripts/phase8g_post/stream_audit.py <step> <scenario> [--run NAME]
       [--code current|frozen] [--lateness S] [--max-buffer N] [--max-spill N] [--no-build]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8g"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8f"))
from windows import LATENESS_S, LEVELS, MAX_BUFFER, Builder, acceptance, initiators  # noqa: E402
from windows import load_config as _load_config  # noqa: E402

from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.live import DEDUP_KEY, END, START  # noqa: E402
from netsentinel.streaming.offline import parse_health  # noqa: E402
from netsentinel.telemetry.frames import records_to_frame  # noqa: E402
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log  # noqa: E402

POST = Path("data/derived/phase8g_post")
REPORTS = Path("reports/phase8g_post")
CONFIG = "configs/phase8g/ctu13.yaml"
FROZEN_SHA = "121acbfe208ef7637f6d2fe8e048f4cea65d92e4"
PART_ROWS = 250_000
BATCH_FLOWS = 200_000  # windows.build value
HOUR_MS = 3_600_000
BUCKET_MS = 1_800_000  # reference buckets: whole 30 s windows, bounded memory
FATES = {"duplicate": 1, "late": 2, "quarantined": 3, "invalid_time": 4}


def load_config() -> dict:
    return _load_config(ROOT / CONFIG)


def sc_dir(key: str) -> Path:
    return POST / key


def run_dir(key: str, run: str) -> Path:
    """<POST>/runs/<run>/<scenario key>: the layout evaluate.py expects under derived_root."""
    return POST / "runs" / run / key


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=str), "utf-8")


def keyhash(df: pl.DataFrame) -> pl.Series:
    return df.select(pl.struct([pl.col(c) for c in DEDUP_KEY]).hash(seed=0).alias("h"))["h"]


def arrival_parts(key: str) -> list[Path]:
    return sorted((sc_dir(key) / "arrival").glob("part_*.parquet"))


# ----------------------------------------------------------------------------- cache
def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 22):
            h.update(chunk)
    return h.hexdigest()


def cache(cfg: dict, key: str) -> dict:
    sc = cfg["scenarios"][key]
    src = Path(cfg["data_root"]) / sc["id"] / sc["conn_log"]
    reg = json.loads((Path(cfg["reports_root"]) / "registry.json").read_text("utf-8"))
    expect = {f["path"]: f["sha256"] for f in reg["files"]}[src.as_posix()]
    t0 = time.perf_counter()
    digest = sha256(src)
    if digest != expect:
        raise SystemExit(f"{src} does not match the registered SHA-256")
    out = sc_dir(key) / "arrival"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    zs, buf, seq, part = ZeekStats(), [], 0, 0
    first, last = None, None

    def write(rows: list[dict], i: int) -> None:
        df = pl.DataFrame(rows, infer_schema_length=None)
        df.with_columns(keyhash(df).alias("keyhash")).write_parquet(out / f"part_{i:05d}.parquet")

    for r in read_conn_log(src, zs):
        r["seq"] = seq
        seq += 1
        first = r[START] if first is None else min(first, r[START])
        last = r[END] if last is None else max(last, r[END])
        buf.append(r)
        if len(buf) >= PART_ROWS:
            write(buf, part)
            buf, part = [], part + 1
    if buf:
        write(buf, part)
    meta = {"scenario": key, "source": src.as_posix(), "sha256": digest, "sha256_ok": True,
            "records": seq, "first_start_ms": first, "last_end_ms": last,
            "parse": {"lines": zs.lines, "records": zs.records, "skipped": zs.skipped},
            "parts": part + 1, "seconds": time.perf_counter() - t0,
            "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    write_json(sc_dir(key) / "cache_meta.json", meta)
    return meta


# ----------------------------------------------------------------------------- shared
def new_builder(cfg: dict, key: str, cm: dict, out: Path) -> tuple[Builder, int]:
    for old in out.glob("*.parquet") if out.exists() else ():
        old.unlink()
    cut = int(cm["first_start_ms"] + cfg["calibration_hours"] * 3.6e6)  # windows.build rule
    return Builder(cut, initiators(cfg), cfg["window_s"], out), cut


def finish_builder(b: Builder, out: Path) -> None:
    pl.DataFrame({"dst": sorted(b.seen)}, schema={"dst": pl.Utf8}).write_parquet(
        out / "calibration_dst.parquet"
    )


def window_meta(cfg, key, cm, b, cut, stream_stats, lateness, accept, seconds) -> dict:
    sc = cfg["scenarios"][key]
    health = parse_health({"lines": cm["parse"]["lines"], "skipped": cm["parse"]["skipped"]})
    return {"scenario": key, "id": sc["id"], "records": cm["records"],
            "first_start_ms": cm["first_start_ms"], "last_end_ms": cm["last_end_ms"],
            "cut_ms": cut, "test_hours": (cm["last_end_ms"] - cut) / 3.6e6, "flows": b.flows,
            "parts": {f"{p}_{lv}": c for (p, lv), c in b.parts.items()},
            "parse": cm["parse"], "telemetry_health": health, "stream": stream_stats,
            "lateness_s": lateness, "acceptance": accept, "seconds": seconds,
            "peak_rss_mb": peak_rss_mb()}  # fmt: skip


# ----------------------------------------------------------------------------- reference
def reference(cfg: dict, key: str) -> dict:
    """Unlimited lateness, no buffer limit, no clock state machine: the definition the stream
    must reproduce on a well-behaved log."""
    cm = json.loads((sc_dir(key) / "cache_meta.json").read_text("utf-8"))
    out = run_dir(key, "reference")
    out.mkdir(parents=True, exist_ok=True)
    b, cut = new_builder(cfg, key, cm, out)
    w_ms = cfg["window_s"] * 1000
    t0 = time.perf_counter()
    lazy = pl.scan_parquet([str(p) for p in arrival_parts(key)])
    lo = cm["first_start_ms"] // BUCKET_MS * BUCKET_MS
    members, dups, pending = [], 0, []
    while lo <= cm["last_end_ms"]:
        hi = lo + BUCKET_MS
        df = lazy.filter((pl.col(END) >= lo) & (pl.col(END) < hi)).collect()
        lo = hi
        if not df.height:
            continue
        df = df.with_columns((pl.col(END) // w_ms).alias("win")).sort("win", "seq")
        uniq = df.unique(subset=["win", *DEDUP_KEY], keep="first", maintain_order=True)
        dups += df.height - uniq.height
        members.append(uniq.select("seq", "win"))
        for _, g in uniq.group_by("win", maintain_order=True):  # whole windows, in order
            pending += g.drop("win", "keyhash").to_dicts()
            if len(pending) >= BATCH_FLOWS:
                b.add(records_to_frame(pending))
                pending = []
        del df, uniq
    if pending:
        b.add(records_to_frame(pending))
    finish_builder(b, out)
    pl.concat(members).write_parquet(out / "members.parquet")
    stats = {"records": cm["records"], "emitted": int(sum(m.height for m in members)),
             "duplicates": dups}  # fmt: skip
    meta = window_meta(cfg, key, cm, b, cut, stats, None, "reference (unlimited lateness)",
                       time.perf_counter() - t0)  # fmt: skip
    write_json(out / "meta.json", meta)
    return meta


# ----------------------------------------------------------------------------- stream
def stream_module(code: str):
    if code == "current":
        from netsentinel.streaming import live

        return live
    path = POST / "_code" / f"live_{FROZEN_SHA[:7]}.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    src = subprocess.run(["git", "show", f"{FROZEN_SHA}:src/netsentinel/streaming/live.py"],
                         capture_output=True, text=True, check=True, cwd=ROOT).stdout  # fmt: skip
    path.write_text(src, "utf-8")
    spec = importlib.util.spec_from_file_location(f"live_{FROZEN_SHA[:7]}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


def dir_bytes(d: Path | None) -> int:
    if d is None or not d.exists():
        return 0
    return sum(f.stat().st_size for f in d.iterdir() if f.is_file())


def stream(cfg: dict, key: str, run: str, code: str, lateness: float, max_buffer: int,
           max_spill: int | None, build: bool = True) -> dict:  # fmt: skip
    cm = json.loads((sc_dir(key) / "cache_meta.json").read_text("utf-8"))
    out = run_dir(key, run)
    out.mkdir(parents=True, exist_ok=True)
    b, cut = new_builder(cfg, key, cm, out)
    mod = stream_module(code)
    kw = {} if code == "frozen" else {"max_spill": max_spill}
    ws = mod.WindowStream(cfg["window_s"], lateness_s=lateness, max_buffer=max_buffer, **kw)
    st = ws.stats
    spill = getattr(ws, "spill", None)
    take_s = [0.0, 0]
    if spill is not None:  # window reconstruction cost
        real_take = spill.take

        def timed_take(*a, **k):
            t = time.perf_counter()
            r = real_take(*a, **k)
            take_s[0] += time.perf_counter() - t
            take_s[1] += 1
            return r

        spill.take = timed_take
    mem_seq, mem_win, mem_emit, fate_seq, fate_code = [], [], [], [], []
    emit_i, pending = 0, []
    t_stream = t_build = 0.0
    peak_disk, spill_dirs = 0, set()
    t0, c0 = time.perf_counter(), time.process_time()

    def take(closed) -> None:
        nonlocal emit_i, pending, t_build
        for w, rs in closed:
            mem_seq.append(np.fromiter((r["seq"] for r in rs), np.int64, len(rs)))
            mem_win.append(np.full(len(rs), w, np.int64))
            mem_emit.append(np.full(len(rs), emit_i, np.int64))
            emit_i += 1
            if build:
                pending += rs
        if build and len(pending) >= BATCH_FLOWS:
            t = time.perf_counter()
            b.add(records_to_frame(pending))
            t_build += time.perf_counter() - t
            pending = []

    n = 0
    for part in arrival_parts(key):
        for rec in (r for sl in pl.read_parquet(part).drop("keyhash").iter_slices(50_000)
                    for r in sl.to_dicts()):  # fmt: skip
            before = (st.duplicates, st.late, st.clock_skew, getattr(st, "invalid_time", 0))
            t = time.perf_counter()
            closed = ws.push(rec)
            t_stream += time.perf_counter() - t
            after = (st.duplicates, st.late, st.clock_skew, getattr(st, "invalid_time", 0))
            if after != before:
                for name, i in (("duplicate", 0), ("late", 1), ("quarantined", 2),
                                ("invalid_time", 3)):  # fmt: skip
                    if after[i] > before[i]:
                        fate_seq.append(rec["seq"])
                        fate_code.append(FATES[name])
                        break
            if closed:
                take(closed)
            n += 1
            if spill is not None and n % 100_000 == 0 and spill.dir is not None:
                spill_dirs.add(spill.dir)
                peak_disk = max(peak_disk, dir_bytes(spill.dir))
    lazy = getattr(ws, "flush_iter", None)  # read back one spilled window at a time
    t = time.perf_counter()
    for item in lazy() if lazy else ws.flush():
        t_stream += time.perf_counter() - t
        take([item])
        t = time.perf_counter()
    t_stream += time.perf_counter() - t
    if build and pending:
        t = time.perf_counter()
        b.add(records_to_frame(pending))
        t_build += time.perf_counter() - t
    if build:
        finish_builder(b, out)
    wall, cpu = time.perf_counter() - t0, time.process_time() - c0
    pl.DataFrame({"seq": np.concatenate(mem_seq), "win": np.concatenate(mem_win),
                  "emit": np.concatenate(mem_emit)}).write_parquet(out / "members.parquet")  # fmt: skip
    pl.DataFrame({"seq": np.array(fate_seq, np.int64), "fate": np.array(fate_code, np.int8)}
                 ).write_parquet(out / "fates.parquet")  # fmt: skip
    stats = st.as_dict()
    res = {"code": code, "code_sha": FROZEN_SHA if code == "frozen" else git_head(),
           "lateness_s": lateness, "max_buffer": max_buffer,
           "max_spill": getattr(ws, "max_spill", None), "build": build,
           "wall_s": wall, "cpu_s": cpu, "cpu_share_of_one_core": cpu / wall if wall else None,
           "stream_s": t_stream, "build_s": t_build,
           "stream_records_per_s": cm["records"] / t_stream if t_stream else None,
           "end_to_end_records_per_s": cm["records"] / wall if wall else None,
           "peak_spill_disk_bytes_sampled": peak_disk,
           "spill_take_s": take_s[0], "spill_takes": take_s[1],
           "spill_dirs_removed_after_flush": all(not d.exists() for d in spill_dirs),
           "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    accept = acceptance(lateness, st)
    meta = window_meta(cfg, key, cm, b, cut, stats, lateness, accept, wall)
    meta["audit"] = res
    write_json(out / "meta.json", meta)
    return meta


def git_head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                          cwd=ROOT).stdout.strip()  # fmt: skip


# ----------------------------------------------------------------------------- compare
def _arrays(key: str, cm: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Per-seq DEDUP_KEY hash, packets and duration (dense: seq = file position)."""
    n = cm["records"]
    kh = np.zeros(n, np.uint64)
    pk = np.zeros(n, np.int64)
    du = np.zeros(n, np.int64)
    for part in arrival_parts(key):
        d = pl.read_parquet(part, columns=["seq", "keyhash", "IN_PKTS", "OUT_PKTS",
                                           "FLOW_DURATION_MILLISECONDS"])  # fmt: skip
        s = d["seq"].to_numpy()
        kh[s] = d["keyhash"].to_numpy()
        pk[s] = (d["IN_PKTS"].fill_null(0) + d["OUT_PKTS"].fill_null(0)).to_numpy()
        du[s] = d["FLOW_DURATION_MILLISECONDS"].fill_null(0).to_numpy()
    return kh, pk, du


def _ident(win: np.ndarray, kh: np.ndarray) -> np.ndarray:
    """(window, record content) -> one 64-bit identity."""
    return kh ^ (win.astype(np.uint64) * np.uint64(0x9E3779B97F4A7C15))


def _features(ref: Path, run: Path, part: str, level: str) -> dict:
    files_r = sorted(ref.glob(f"{part}_{level}_*.parquet"))
    files_s = sorted(run.glob(f"{part}_{level}_*.parquet"))
    if not files_r and not files_s:
        return {"windows_reference": 0, "windows_run": 0}
    a = pl.concat([pl.read_parquet(f) for f in files_r], how="diagonal_relaxed")
    c = pl.concat([pl.read_parquet(f) for f in files_s], how="diagonal_relaxed")
    cols = [x for x in ("n_flows", "up", "down", "pkts", "dst_hosts", "dst_ports",
                        *WINDOW_FEATURES, "window_start_ms", "window_end_ms")
            if x in a.columns]  # fmt: skip
    dup_r = a.height - a.select("key", "win").n_unique()
    dup_s = c.height - c.select("key", "win").n_unique()
    j = a.select("key", "win", *cols).join(c.select("key", "win", *cols), on=["key", "win"],
                                           how="full", suffix="_run", coalesce=True)  # fmt: skip
    only_r = int(j.filter(pl.col(f"{cols[0]}_run").is_null() & pl.col(cols[0]).is_not_null()
                          ).height)  # fmt: skip
    only_s = int(j.filter(pl.col(cols[0]).is_null() & pl.col(f"{cols[0]}_run").is_not_null()
                          ).height)  # fmt: skip
    both = j.filter(pl.col(cols[0]).is_not_null() & pl.col(f"{cols[0]}_run").is_not_null())
    diff = {}
    any_diff = pl.lit(False)
    for col in cols:
        x, y = pl.col(col).cast(pl.Float64), pl.col(f"{col}_run").cast(pl.Float64)
        ne = ((x - y).abs() > 1e-9) | (x.is_null() != y.is_null())
        any_diff = any_diff | ne.fill_null(False)
        d = both.select(ne.fill_null(False).sum().alias("n"),
                        (x - y).abs().max().alias("max_abs")).row(0)  # fmt: skip
        diff[col] = {"windows_differing": int(d[0]), "max_abs_diff": d[1]}
    differing = both.filter(any_diff)
    return {"windows_reference": a.height, "windows_run": c.height,
            "repeated_windows_reference": dup_r, "repeated_windows_run": dup_s,
            "only_in_reference": only_r, "only_in_run": only_s,
            "windows_with_any_feature_difference": differing.height, "per_feature": diff,
            "example_differing": differing.head(5).select("key", "win").to_dicts()}  # fmt: skip


def _scores(cfg: dict, key: str, ref: Path, run: Path, workdir: Path) -> dict:
    from evaluate import make_profile
    from windows import load_windows

    out = {}
    scored = {}
    for name, d in (("reference", ref), ("run", run)):
        c = dict(cfg, derived_root=str(d.parent))
        meta = json.loads((d / "meta.json").read_text("utf-8"))
        k = d.name
        cal = {lv: load_windows(c, k, "cal", lv) for lv in LEVELS}
        test = pl.concat([t for lv in LEVELS if (t := load_windows(c, k, "test", lv)).height],
                         how="diagonal_relaxed")  # fmt: skip
        prof, _ = make_profile(c, k, cal, "vetted_benign", meta, workdir / name)
        out[f"thresholds_{name}"] = {lv: p.threshold for lv, p in prof.levels.items()}
        scored[name] = prof.score(test).select("level", "key", "win", "score", "anomalous",
                                               "model_scope")  # fmt: skip
        del cal, test
    j = scored["reference"].join(scored["run"], on=["level", "key", "win"], how="full",
                                 suffix="_run", coalesce=True)  # fmt: skip
    both = j.filter(pl.col("score").is_not_null() & pl.col("score_run").is_not_null())
    out["scored_windows_reference"] = scored["reference"].height
    out["scored_windows_run"] = scored["run"].height
    out["only_in_reference"] = int(j.filter(pl.col("score_run").is_null()).height)
    out["only_in_run"] = int(j.filter(pl.col("score").is_null()).height)
    out["score_differing"] = int(both.filter((pl.col("score") - pl.col("score_run")).abs()
                                             > 1e-9).height)  # fmt: skip
    out["max_abs_score_diff"] = both.select((pl.col("score") - pl.col("score_run")).abs().max()
                                            ).item()  # fmt: skip
    flips = both.filter(pl.col("anomalous") != pl.col("anomalous_run"))
    out["alert_decisions_differing"] = flips.height
    out["alerts_reference"] = int(scored["reference"]["anomalous"].sum())
    out["alerts_run"] = int(scored["run"]["anomalous"].sum())
    out["alert_flips_by_level"] = {lv: int(flips.filter(pl.col("level") == lv).height)
                                   for lv in LEVELS}  # fmt: skip
    out["alerts_gained_run"] = int(flips["anomalous_run"].sum()) if flips.height else 0
    out["alerts_lost_run"] = int((~flips["anomalous_run"]).sum()) if flips.height else 0
    out["alert_flip_keys"] = flips.group_by("level", "key").len().sort(
        "len", descending=True).head(10).to_dicts()  # fmt: skip
    return out


def compare(cfg: dict, key: str, run: str, scores: bool = True) -> dict:
    cm = json.loads((sc_dir(key) / "cache_meta.json").read_text("utf-8"))
    ref, rd = run_dir(key, "reference"), run_dir(key, run)
    kh, pk, du = _arrays(key, cm)
    r = pl.read_parquet(ref / "members.parquet")
    s = pl.read_parquet(rd / "members.parquet")
    rs, rw = r["seq"].to_numpy(), r["win"].to_numpy()
    ss, sw, se = s["seq"].to_numpy(), s["win"].to_numpy(), s["emit"].to_numpy()
    rid, sid = _ident(rw, kh[rs]), _ident(sw, kh[ss])
    u_s, c_s = np.unique(sid, return_counts=True)
    repeated = int((c_s > 1).sum())
    missing_mask = ~np.isin(rid, sid)
    extra_mask = ~np.isin(sid, rid)
    # same record content placed in a different window
    moved = int(np.isin(kh[ss[extra_mask]], kh[rs[missing_mask]]).sum())
    seq_missing = rs[missing_mask]
    fates = pl.read_parquet(rd / "fates.parquet")
    fate_of = dict(zip(fates["seq"].to_list(), fates["fate"].to_list(), strict=True))
    inv = {v: k for k, v in FATES.items()}
    by_fate: dict[str, int] = {}
    for q in seq_missing.tolist():
        f = inv.get(fate_of.get(q), "accepted_then_dropped")
        by_fate[f] = by_fate.get(f, 0) + 1
    lat_ms = (cfg["scenarios"][key].get("lateness_s", LATENESS_S)) * 1000
    long_ = du[seq_missing] > 3_600_000 + lat_ms
    w0 = int(min(rw.min(), sw.min()))
    nwin = int(max(rw.max(), sw.max())) - w0 + 1
    n_r = np.bincount(rw - w0, minlength=nwin)
    n_s = np.bincount(sw - w0, minlength=nwin)
    p_r = np.bincount(rw - w0, weights=pk[rs], minlength=nwin)
    p_s = np.bincount(sw - w0, weights=pk[ss], minlength=nwin)
    em = pl.DataFrame({"win": sw, "emit": se}).unique().group_by("win").len()
    multi = em.filter(pl.col("len") > 1)
    win_tab = pl.DataFrame({"win": np.arange(w0, w0 + nwin), "flows_reference": n_r,
                            "flows_run": n_s, "pkts_reference": p_r, "pkts_run": p_s}
                           ).filter((pl.col("flows_reference") != pl.col("flows_run"))
                                    | (pl.col("pkts_reference") != pl.col("pkts_run")))  # fmt: skip
    REPORTS.mkdir(parents=True, exist_ok=True)
    stem = REPORTS / f"{key}_{run}"
    win_tab.write_parquet(f"{stem}_windows_differing.parquet")
    pl.DataFrame({"seq": seq_missing, "win": rw[missing_mask], "duration_ms": du[seq_missing],
                  "fate": [inv.get(fate_of.get(q), "accepted_then_dropped")
                           for q in seq_missing.tolist()]}
                 ).write_parquet(f"{stem}_records_missing.parquet")  # fmt: skip
    meta_s = json.loads((rd / "meta.json").read_text("utf-8"))
    out = {"scenario": key, "run": run, "audit": meta_s.get("audit"),
           "stream": meta_s.get("stream"), "acceptance": meta_s.get("acceptance"),
           "records": {"input": cm["records"], "reference_members": int(len(rs)),
                       "reference_duplicates_removed": int(cm["records"] - len(rs)),
                       "run_members": int(len(ss)), "missing": int(missing_mask.sum()),
                       "extra": int(extra_mask.sum()), "moved_to_another_window": moved,
                       "repeated_in_run": repeated,
                       "missing_by_fate": by_fate,
                       "missing_longer_than_skew_plus_lateness": int(long_.sum()),
                       "missing_duration_ms_quantiles": (
                           np.quantile(du[seq_missing], [0, .5, .9, 1]).tolist()
                           if len(seq_missing) else None)},
           "windows": {"reference": int((n_r > 0).sum()), "run": int((n_s > 0).sum()),
                       "flow_count_differing": int((n_r != n_s).sum()),
                       "packet_sum_differing": int((p_r != p_s).sum()),
                       "emitted_more_than_once": multi.height,
                       "only_in_reference": int(((n_r > 0) & (n_s == 0)).sum()),
                       "only_in_run": int(((n_s > 0) & (n_r == 0)).sum())}}  # fmt: skip
    if (rd / "calibration_dst.parquet").exists():
        out["features"] = {f"{p}_{lv}": _features(ref, rd, p, lv)
                           for p in ("cal", "test") for lv in LEVELS}  # fmt: skip
        a = set(pl.read_parquet(ref / "calibration_dst.parquet")["dst"].to_list())
        c = set(pl.read_parquet(rd / "calibration_dst.parquet")["dst"].to_list())
        out["calibration_destinations"] = {"reference": len(a), "run": len(c),
                                           "only_reference": len(a - c),
                                           "only_run": len(c - a)}  # fmt: skip
        if scores:
            with tempfile.TemporaryDirectory(prefix="ns-8g-post-",
                                             ignore_cleanup_errors=True) as tmp:  # fmt: skip
                out["scores"] = _scores(cfg, key, ref, rd, Path(tmp))
    out["equivalent"] = bool(
        out["records"]["missing"] == 0 and out["records"]["extra"] == 0 and repeated == 0
        and out["windows"]["flow_count_differing"] == 0
        and out["windows"]["emitted_more_than_once"] == 0
        and all(f.get("windows_with_any_feature_difference", 0) == 0
                and f.get("only_in_reference", 0) == 0 and f.get("only_in_run", 0) == 0
                for f in out.get("features", {}).values())
        and (out.get("scores") or {}).get("alert_decisions_differing", 0) == 0
        and (out.get("scores") or {}).get("score_differing", 0) == 0)  # fmt: skip
    out["peak_rss_mb"] = peak_rss_mb()
    write_json(Path(f"{stem}_compare.json"), out)
    return out


def compare_frozen(cfg: dict, key: str) -> dict:
    """The published frozen window parts (data/derived/phase8g, code 121acbf) vs the reference:
    what the 1,039 dropped records changed in features, scores and alert decisions."""
    ref, fz = run_dir(key, "reference"), Path(cfg["derived_root"]) / key
    out = {"scenario": key, "frozen_parts": fz.as_posix(),
           "features": {f"{p}_{lv}": _features(ref, fz, p, lv)
                        for p in ("cal", "test") for lv in LEVELS}}  # fmt: skip
    with tempfile.TemporaryDirectory(prefix="ns-8g-post-", ignore_cleanup_errors=True) as tmp:
        out["scores"] = _scores(cfg, key, ref, fz, Path(tmp))
    out["peak_rss_mb"] = peak_rss_mb()
    write_json(REPORTS / f"{key}_frozen_parts_compare.json", out)
    return out


# ----------------------------------------------------------------------------- evaluate
def evaluate(cfg: dict, key: str, run: str) -> dict:
    """Exploratory [R]: the frozen evaluation function on this run's windows."""
    from evaluate import scenario

    d = run_dir(key, run)
    c = dict(cfg, derived_root=str(d.parent))
    tmpd = Path(tempfile.mkdtemp(prefix="ns-8g-post-ev-"))
    try:
        res = scenario(c, key, tmpd) if (d / "meta.json").exists() else {"status": "no run"}
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    out = {"label": "[R] retrospective, exploratory: consumed data; not confirmatory",
           "scenario": key, "run": run, "result": res}  # fmt: skip
    write_json(REPORTS / f"{key}_{run}_evaluate.json", out)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "step", choices=("cache", "reference", "stream", "compare", "compare-frozen", "evaluate")
    )
    ap.add_argument("scenario")
    ap.add_argument("--run", default="current")
    ap.add_argument("--code", choices=("current", "frozen"), default="current")
    ap.add_argument("--lateness", type=float)
    ap.add_argument("--max-buffer", type=int, default=MAX_BUFFER)
    ap.add_argument("--max-spill", type=int)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--no-scores", action="store_true")
    a = ap.parse_args()
    cfg = load_config()
    if a.step == "cache":
        r = cache(cfg, a.scenario)
    elif a.step == "reference":
        r = reference(cfg, a.scenario)
    elif a.step == "stream":
        lat = a.lateness if a.lateness is not None else cfg["scenarios"][a.scenario].get(
            "lateness_s", LATENESS_S)  # fmt: skip
        r = stream(cfg, a.scenario, a.run, a.code, lat, a.max_buffer, a.max_spill,
                   build=not a.no_build)  # fmt: skip
    elif a.step == "compare":
        r = compare(cfg, a.scenario, a.run, scores=not a.no_scores)
    elif a.step == "compare-frozen":
        r = compare_frozen(cfg, a.scenario)
    else:
        r = evaluate(cfg, a.scenario, a.run)
    print(json.dumps(r, indent=1, default=str)[:4000])
