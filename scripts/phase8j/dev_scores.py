"""Phase 8j development scores under P1x [E] (docs/phase8j/PREREGISTRATION.md sections 2, 7).

For one seed: one source model per target network (B-raw, Phase 8i settings; sources = the
other Phase 8i development networks, as in leakage_audit.py; NF-BoT-IoT-v3 is a development
target, never a source here). It scores every P1x calibration window (with the hold-out flag of
the Phase 8i 70/30 time split) and every P1x evaluation window. The evaluation labels (attack;
verified benign = hosts that never attack; NF-CIC infiltration = noisy) are joined for metrics
only.

Output: data/derived/phase8j/dev/<domain>__seed<k>.npz
Usage: uv run python scripts/run_capped.py -- uv run python scripts/phase8j/dev_scores.py --seed 0
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leakage_audit as LA  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

C = LA.C
P1X = Path("data/derived/phase8j/p1x")
OUT = Path("data/derived/phase8j/dev")


def p1x_frames(d: dict) -> tuple[pl.DataFrame, pl.DataFrame]:
    base = P1X / d["network"] / d["name"]
    cal = pl.read_parquet(base / "cal_p1x.parquet").sort("win", "key")
    ev = pl.read_parquet(base / "eval_p1x.parquet")
    lab = d["ev"].select("key", "win", "y", "benign", "noisy")
    ev = ev.join(lab, on=["key", "win"], how="inner").sort("win", "key")
    if ev.height != d["ev"].height:
        raise SystemExit(f"{d['name']}: P1x evaluation windows do not match the labelled ones")
    return cal, ev


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    seed = ap.parse_args().seed
    t0 = time.perf_counter()
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    cache: dict[tuple, object] = {}
    OUT.mkdir(parents=True, exist_ok=True)
    info = {}
    for name, d, srcs in LA.targets(nets):
        key = tuple(sorted(srcs))
        if key not in cache:
            cache[key] = C.fit_source(srcs, seed, C.Rep("raw"))[0]
        model = cache[key]
        cal, ev = p1x_frames(d)
        hold = (cal["win"] >= C.S.split_cut(cal)).to_numpy()
        s_cal = model.predict_proba(C.S._x(cal))[:, 1]
        s_ev = model.predict_proba(C.S._x(ev))[:, 1]
        np.savez_compressed(
            OUT / f"{name.replace('/', '__')}__seed{seed}.npz",
            cal_key=cal["key"].to_numpy().astype(str), cal_win=cal["win"].to_numpy(),
            cal_end=cal["window_end_ms"].to_numpy(), cal_s=s_cal, cal_hold=hold,
            ev_key=ev["key"].to_numpy().astype(str), ev_win=ev["win"].to_numpy(),
            ev_end=ev["window_end_ms"].to_numpy(), ev_s=s_ev, ev_y=ev["y"].to_numpy(),
            ev_benign=ev["benign"].to_numpy(), ev_noisy=ev["noisy"].to_numpy(),
            attackers=np.array(sorted(d["attackers"]), dtype=str),
            hours=np.array(d["hours"]), network=np.array(d["network"]))  # fmt: skip
        info[name] = {"cal": cal.height, "hold": int(hold.sum()), "eval": ev.height}
        print(name, info[name], flush=True)
    rep = Path("reports/phase8j/dev") / f"scores_seed{seed}.json"
    rep.parent.mkdir(parents=True, exist_ok=True)
    rep.write_text(json.dumps({"seed": seed, "domains": info, "peak_rss_mb": peak_rss_mb(),
                               "seconds": round(time.perf_counter() - t0, 1)}, indent=1), "utf-8")  # fmt: skip


if __name__ == "__main__":
    main()
