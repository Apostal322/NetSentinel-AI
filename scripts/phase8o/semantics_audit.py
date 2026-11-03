"""Phase 8o Stage A: `new_dst_frac` semantics and false-alert decomposition from SAVED artifacts
(no training). EXPLORATORY; the development networks are consumed.

1. Source training rows (Phase 8h `train_matrix`: clean calibration + non-noisy evaluation):
   how many rows carry each memory semantics (expanding in calibration, frozen in evaluation),
   per label, and how far the Phase 8m causal expanding replay (`nov_unconditional`, clean
   memory) differs from the historical value.
2. Target windows (Phase 8j P1x): the T0 hold-out (expanding memory) against the evaluation
   windows (frozen memory), benign only, by quarter of the evaluation span; hosts first seen
   after the freeze.
3. False alerts of the saved Phase 8n M0 and M2 fits (base and stress, replicates 0-5) at T0:
   FPR by evaluation quarter, by host status, by novelty; host concentration; workload per
   active host-hour and per day; the hold-out vs evaluation benign 99th-percentile gap.

Output: reports/phase8o/semantics_audit.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8o/semantics_audit.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8n_fragility", ROOT / "scripts/phase8n/fragility.py"
)
FR = importlib.util.module_from_spec(_spec)
sys.modules["phase8n_fragility"] = FR
_spec.loader.exec_module(FR)
C, S, LA, DS = FR.C, FR.S, FR.LA, FR.DS

from netsentinel.resources import peak_rss_mb  # noqa: E402

NOV = ROOT / "data" / "derived" / "phase8m" / "novelty"
CAND = ROOT / "data" / "derived" / "phase8n" / "candidates"
REPORT = ROOT / "reports" / "phase8o" / "semantics_audit.json"
ALPHA = 0.01
HOUR_MS = 3_600_000


def k_of(n: int) -> int:
    return min(n, math.ceil((n + 1) * (1 - ALPHA)))


def stats(v: np.ndarray) -> dict:
    if v.size == 0:
        return {"n": 0}
    return {"n": int(v.size), "mean": round(float(v.mean()), 4),
            "share_pos": round(float((v > 0).mean()), 4),
            "share_one": round(float((v >= 1).mean()), 4),
            "q90": round(float(np.quantile(v, 0.9)), 4)}  # fmt: skip


def mid_ms(d: dict) -> int:
    meta = C.DERIVED / d["network"] / d["name"] / "meta.json"
    return int(json.loads(meta.read_text("utf-8"))["mid_ms"])


def source_rows(d: dict) -> dict:
    """Memory semantics of the training rows of one source domain (before the CAP subsample)."""
    cal, ev = d["cal"], d["ev"].filter(~pl.col("noisy"))
    out = {"cal_expanding_benign": stats(cal["new_dst_frac"].to_numpy()),
           "eval_frozen_benign": stats(ev.filter(~pl.col("y"))["new_dst_frac"].to_numpy()),
           "eval_frozen_attack": stats(ev.filter(pl.col("y"))["new_dst_frac"].to_numpy())}  # fmt: skip
    nov = NOV / d["network"] / d["name"] / "clean.parquet"
    if nov.exists():
        n = pl.read_parquet(nov, columns=["key", "win", "nov_unconditional"])
        j = ev.select("key", "win", "y", "new_dst_frac").join(n, on=["key", "win"], how="left")
        miss = int(j["nov_unconditional"].null_count())
        j = j.drop_nulls("nov_unconditional")
        diff = (j["new_dst_frac"] - j["nov_unconditional"]).abs().to_numpy()
        out["f2_expanding_replay_eval_rows"] = {
            "missing": miss, "share_changed": round(float((diff > 1e-12).mean()), 4),
            "benign": stats(j.filter(~pl.col("y"))["nov_unconditional"].to_numpy()),
            "attack": stats(j.filter(pl.col("y"))["nov_unconditional"].to_numpy())}  # fmt: skip
        cj = cal.select("key", "win", "new_dst_frac").join(n, on=["key", "win"], how="left")
        cj = cj.drop_nulls("nov_unconditional")
        cd = (cj["new_dst_frac"] - cj["nov_unconditional"]).abs().to_numpy()
        out["f2_cal_rows_max_abs_diff"] = float(cd.max()) if cd.size else None
    return out


def quarter(end: np.ndarray, mid: int) -> np.ndarray:
    span = max(int(end.max()) - mid, 1)
    return np.minimum(((end - mid) * 4) // span, 3).astype(int)


def target_windows(d: dict) -> tuple[dict, dict]:
    cal, ev = DS.p1x_frames(d)
    hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
    mid = mid_ms(d)
    end = ev["window_end_ms"].to_numpy()
    q = quarter(end, mid)
    ben = ev["benign"].to_numpy().astype(bool)
    nd = ev["new_dst_frac"].to_numpy()
    known = set(cal["key"].unique().to_list())
    new_host = ~np.isin(ev["key"].to_numpy().astype(str), np.array(sorted(known), dtype=str))
    out = {"holdout_benign_expanding": stats(cal["new_dst_frac"].to_numpy()[hold]),
           "eval_hours": round((int(end.max()) - mid) / HOUR_MS, 2),
           "eval_benign_by_quarter": {int(i): stats(nd[ben & (q == i)]) for i in range(4)},
           "eval_benign_new_host_share": round(float(new_host[ben].mean()), 4),
           "eval_benign_new_host": stats(nd[ben & new_host]),
           "eval_benign_known_host": stats(nd[ben & ~new_host])}  # fmt: skip
    ctx = {"q": q, "ben": ben, "nov": nd > 0, "new_host": new_host,
           "key": ev["key"].to_numpy().astype(str), "hour": end // HOUR_MS,
           "n_hold": int(hold.sum()),
           "hold_blocks": int(cal.filter(pl.Series(hold)).select(
               "key", (pl.col("window_end_ms") // HOUR_MS).alias("h")).unique().height)}  # fmt: skip
    return out, ctx


def rate(a: np.ndarray, m: np.ndarray) -> float | None:
    return round(float(a[m].mean()), 4) if m.any() else None


def alerts(ctx: dict, s_hold: np.ndarray, s_ev: np.ndarray) -> dict:
    t0 = float(np.sort(s_hold)[k_of(s_hold.size) - 1])
    a = s_ev > t0
    ben, q, nov, nh = ctx["ben"], ctx["q"], ctx["nov"], ctx["new_host"]
    fa = a & ben
    host_hours = np.unique(np.char.add(ctx["key"][ben], "|" + ctx["hour"][ben].astype(str))).size
    keys, cnt = np.unique(ctx["key"][fa], return_counts=True)
    top = np.sort(cnt)[::-1]
    return {"fpr": rate(a, ben), "false_alerts": int(fa.sum()),
            "fpr_by_quarter": {int(i): rate(a, ben & (q == i)) for i in range(4)},
            "fpr_new_host": rate(a, ben & nh), "fpr_known_host": rate(a, ben & ~nh),
            "fpr_novel": rate(a, ben & nov), "fpr_not_novel": rate(a, ben & ~nov),
            "fa_share_novel": round(float(nov[fa].mean()), 4) if fa.any() else None,
            "fa_share_new_host": round(float(nh[fa].mean()), 4) if fa.any() else None,
            "fa_hosts": int(keys.size),
            "fa_share_top5_hosts": round(float(top[:5].sum() / max(fa.sum(), 1)), 4),
            "fa_per_active_host_hour": round(float(fa.sum() / max(host_hours, 1)), 4),
            "holdout_q99": round(float(np.quantile(s_hold, 1 - ALPHA)), 4),
            "eval_benign_q99": round(float(np.quantile(s_ev[ben], 1 - ALPHA)), 4)}  # fmt: skip


def main() -> None:
    t0 = time.perf_counter()
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    res: dict = {"status": "EXPLORATORY (saved artifacts, consumed development networks)",
                 "sources": {}, "targets": {}}  # fmt: skip
    for n in C.DEV_NETWORKS:
        for name, d in nets[n].items():
            res["sources"][name] = source_rows(d)
    for name, d, _ in LA.targets(nets):
        win, ctx = target_windows(d)
        win["holdout_windows"], win["holdout_host_hour_blocks"] = ctx["n_hold"], ctx["hold_blocks"]
        fits = {}
        for model in ("M0", "M2"):
            for regime in ("base", "stress"):
                for r in range(6):
                    f = CAND / model / regime / f"{name.replace('/', '__')}__r{r}.npz"
                    if f.exists():
                        z = np.load(f)
                        fits[f"{model}/{regime}/r{r}"] = alerts(ctx, z["s_hold"], z["s_ev"])
        win["fits"] = fits
        res["targets"][name] = win
        print(name, json.dumps({k: win[k] for k in ("eval_hours", "eval_benign_new_host_share")}),
              flush=True)  # fmt: skip
    res["seconds"], res["peak_rss_mb"] = round(time.perf_counter() - t0, 1), peak_rss_mb()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    main()
