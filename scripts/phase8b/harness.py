"""Phase 8b shared harness: identical entity-window inputs for every scorer, operational metrics.

Window construction (the same protocol as Phase 8, docs/phase8/RESEARCH_PLAN.md):
* flows are assigned to 30 s windows by END time; level = device (source address);
* calibration = flows ending before the time midpoint, evaluation = the rest;
* calibration variants: clean (benign-labelled flows only; oracle for vetted traffic) and
  unlabelled (all flows); expanding destination sets in calibration, frozen in evaluation;
* truth: an entity-window is an attack window if any of its flows is labelled malicious;
  for detection delay, the first attack-flow START per entity is kept.
Inputs are streamed in time-ordered chunks (bounded memory); results are cached as Parquet
under data/derived/phase8b/<capture>/ so every scorer sees byte-identical windows.

Labels are used only for metrics and for the oracle-clean calibration variant.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.behavior.windows import WINDOW_FEATURES, _key_expr, aggregate, prepare_flows

W = 30
TARGET = 0.01
LEVEL = "device"
VARIANTS = ("clean", "unlabelled")
DERIVED = Path("data/derived/phase8b")


class WindowBuilder:
    def __init__(self, mid_ms: int):
        self.mid = mid_ms
        self.seen = {v: set() for v in VARIANTS}
        self.cal = {v: [] for v in VARIANTS}
        self.ev = {v: [] for v in VARIANTS}
        self.truth: list[pl.DataFrame] = []
        self.first_attack: dict[str, int] = {}
        self.span = [math.inf, -math.inf]
        self.flows = {"cal": 0, "eval": 0, "cal_attack": 0, "eval_attack": 0}

    def add(self, frame: pl.DataFrame) -> None:
        """A canonical flow frame (with is_attack) holding COMPLETE windows."""
        flows = prepare_flows(frame)
        cal = flows.filter(pl.col("end_ms") < self.mid)
        ev = flows.filter(pl.col("end_ms") >= self.mid)
        self.flows["cal"] += cal.height
        self.flows["eval"] += ev.height
        self.flows["cal_attack"] += int((cal["is_attack"] > 0).sum())
        self.flows["eval_attack"] += int((ev["is_attack"] > 0).sum())
        for v in VARIANTS:
            sub = cal if v == "unlabelled" else cal.filter(pl.col("is_attack") == 0)
            if sub.height:
                self.cal[v].append(aggregate(sub, LEVEL, W, prior_dst=self.seen[v]))
                self.seen[v] |= set(sub["dst"].unique().to_list())
        if ev.height:
            self.span = [min(self.span[0], int(ev["end_ms"].min())),
                         max(self.span[1], int(ev["end_ms"].max()))]  # fmt: skip
            start = pl.col("end_ms") - pl.col("dur_ms")
            self.truth.append(
                ev.with_columns((pl.col("end_ms") // (W * 1000)).alias("win"), _key_expr(LEVEL))
                .group_by("key", "win")
                .agg((pl.col("is_attack").max() > 0).alias("y"),
                     start.filter(pl.col("is_attack") > 0).min().alias("first_attack_ms")))  # fmt: skip
            att = ev.filter(pl.col("is_attack") > 0)
            if att.height:
                fa = att.group_by("src").agg((pl.col("end_ms") - pl.col("dur_ms")).min().alias("t"))
                for k, t in fa.iter_rows():
                    self.first_attack[k] = min(self.first_attack.get(k, t), int(t))
            for v in VARIANTS:
                self.ev[v].append(aggregate(ev, LEVEL, W, known_dst=self.seen[v]))

    def save(self, out: Path, meta: dict) -> None:
        out.mkdir(parents=True, exist_ok=True)
        for v in VARIANTS:
            for part, lst in (("cal", self.cal[v]), ("eval", self.ev[v])):
                df = pl.concat(lst, how="diagonal_relaxed") if lst else pl.DataFrame()
                df.write_parquet(out / f"{part}_{v}.parquet")
        tr = pl.concat(self.truth) if self.truth else pl.DataFrame()
        tr.write_parquet(out / "truth.parquet")
        meta = {**meta, "flows": self.flows, "eval_span_ms": self.span, "mid_ms": self.mid,
                "first_attack_ms": self.first_attack,
                "eval_hours": (self.span[1] - self.mid) / 3.6e6 if self.truth else 0.0}  # fmt: skip
        (out / "meta.json").write_text(json.dumps(meta, indent=1, default=str), "utf-8")


def zeek_windows(path: Path, out: Path, batch_flows: int = 200_000) -> dict:
    """Stream a Zeek conn.log(.labeled): pass 0 = time span, pass 1 = windows."""
    from netsentinel.streaming.live import END, WindowStream
    from netsentinel.telemetry.frames import records_to_frame
    from netsentinel.telemetry.zeek import ZeekStats, read_conn_log

    def is_attack(d: dict) -> float:
        return 1.0 if str(d.get("label", "")).lower().startswith("malicious") else 0.0

    ex = {"IS_ATTACK": is_attack}
    lo, hi, n = math.inf, -math.inf, 0
    for r in read_conn_log(path, extras=ex):
        lo, hi, n = min(lo, r[END]), max(hi, r[END]), n + 1
    mid = int(lo + (hi - lo) // 2)
    b = WindowBuilder(mid)
    ws = WindowStream(W, lateness_s=3700, max_buffer=1_500_000)
    zs = ZeekStats()
    pending: list[dict] = []
    for rec in read_conn_log(path, zs, extras=ex):
        for _, rs in ws.push(rec):
            pending += rs
        if len(pending) >= batch_flows:
            b.add(records_to_frame(pending))
            pending = []
    for _, rs in ws.flush():
        pending += rs
    if pending:
        b.add(records_to_frame(pending))
    b.save(out, {"source": str(path.name), "records": n, "stream": ws.stats.as_dict(),
                 "parse_skipped": zs.skipped})  # fmt: skip
    return load(out)


def nf_unsw_windows(out: Path) -> dict:
    """NF-UNSW-NB15-v3 development part (first 78% of each day; Phase 6/8 protocol)."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase6"))
    from eval_nf_dev import read_day  # noqa: PLC0415

    files = sorted(Path("data/interim/nf_unsw_nb15_v3").glob("[0-9]*.parquet"))
    ends = pl.concat([read_day(f, []).select("flow_end_milliseconds") for f in files])
    mid = int(ends["flow_end_milliseconds"].quantile(0.5))
    b = WindowBuilder(mid)
    for f in files:
        day = read_day(f, []).sort("flow_end_milliseconds")
        b.add(day)
    b.save(out, {"source": "NF-UNSW-NB15-v3 development part"})
    return load(out)


def load(out: Path) -> dict:
    d = {"meta": json.loads((out / "meta.json").read_text("utf-8")),
         "truth": pl.read_parquet(out / "truth.parquet")}  # fmt: skip
    for v in VARIANTS:
        d[f"cal_{v}"] = pl.read_parquet(out / f"cal_{v}.parquet")
        d[f"eval_{v}"] = pl.read_parquet(out / f"eval_{v}.parquet")
    return d


def windows(name: str, source) -> dict:
    """Cached windows for a capture. `source` = a Zeek path or the string 'nf_unsw'."""
    out = DERIVED / name
    if (out / "meta.json").exists():
        return load(out)
    return nf_unsw_windows(out) if source == "nf_unsw" else zeek_windows(Path(source), out)


# ----------------------------------------------------------------------------- metrics
def with_truth(ev: pl.DataFrame, truth: pl.DataFrame) -> pl.DataFrame:
    return ev.join(truth, on=["key", "win"], how="left").with_columns(
        pl.col("y").fill_null(False))  # fmt: skip


def operational(ev: pl.DataFrame, truth: pl.DataFrame, score: np.ndarray, thr: float,
                hours: float, first_attack: dict) -> dict:  # fmt: skip
    """Window metrics + entity-level detection delay. `ev` rows align with `score`."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    d = with_truth(ev.select("key", "win", "window_end_ms"), truth).with_columns(
        pl.Series("score", score), pl.Series("alert", score > thr))  # fmt: skip
    y = d["y"].to_numpy().astype(int)
    a = d["alert"].to_numpy()
    out = {"windows": len(y), "attack_windows": int(y.sum()), "base_rate": float(y.mean())
           if len(y) else None, "threshold": float(thr)}  # fmt: skip
    if 0 < y.sum() < len(y):
        out["pr_auc"] = float(average_precision_score(y, score))
        out["roc_auc"] = float(roc_auc_score(y, score))
        t1 = np.quantile(score[y == 0], 0.99)
        out["recall_at_fpr1_oracle"] = float((score[y == 1] > t1).mean())
    out["recall"] = float(a[y == 1].mean()) if y.sum() else None
    out["fpr"] = float(a[y == 0].mean()) if (y == 0).sum() else None
    out["false_alerts_per_h"] = float((a & (y == 0)).sum()) / hours if hours else None
    # entity-level detection delay, two definitions:
    # * observable: end of the entity's first attack window (when its first attack evidence is
    #   available to any window-level detector) -> end of its first alerting attack window;
    # * from_attack_start: first attack flow START -> first alert (includes Zeek's logging delay
    #   of long-lived connections, which no connection-log detector can avoid).
    obs, full = [], []
    first_att_win = {k: int(v) for k, v in d.filter(pl.col("y")).group_by("key")
                     .agg(pl.col("window_end_ms").min()).iter_rows()}  # fmt: skip
    for ent, t0 in first_attack.items():
        hit = d.filter((pl.col("key") == ent) & pl.col("alert") & pl.col("y"))
        if hit.height:
            t_alert = int(hit["window_end_ms"].min())
            full.append((t_alert - int(t0)) / 1000)
            if ent in first_att_win:
                obs.append((t_alert - first_att_win[ent]) / 1000)
    out["attacking_entities"] = len(first_attack)
    out["entities_detected"] = len(full)
    out["median_delay_s"] = float(np.median(obs)) if obs else None
    out["median_delay_from_attack_start_s"] = float(np.median(full)) if full else None
    return out


def domain_shift(src: pl.DataFrame, tgt: pl.DataFrame) -> dict:
    """Per-feature two-sample KS statistic between source and target benign windows."""
    from scipy.stats import ks_2samp

    out = {}
    for f in WINDOW_FEATURES:
        a = src[f].drop_nulls().to_numpy()
        b = tgt[f].drop_nulls().to_numpy()
        if len(a) > 10 and len(b) > 10:
            out[f] = float(ks_2samp(a, b).statistic)
    out["median_ks"] = float(np.median(list(out.values()))) if out else None
    return out
