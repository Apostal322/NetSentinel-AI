"""Phase 8m Stage 4: development scores of the registered variants (REGISTERED DEVELOPMENT;
docs/phase8m/PREREGISTRATION.md sections 1-2).

The Phase 8j P1x protocol (scripts/phase8j/dev_scores.py) unchanged except for the feature
columns: per target network one B-raw LightGBM source model (Phase 8i settings, the other
development networks as sources, the same training-window subsample per seed), scored on every
P1x calibration window (with the hold-out flag) and every P1x evaluation window. The novelty
columns come from scripts/phase8m/build_novelty.py: the ``clean`` memory for the source
(training) windows, the ``p1x`` memory for the target windows, joined on (key, win).

Variants (section 2): B0r (= B0 refitted, a pipeline check that must reproduce the Phase 8j
scores), B1, B2, B1u, A_none, A_novol. B0r also stores ``ev_s_q1``: the B0 model on evaluation
windows whose `new_dst_frac` is replaced by `nov_guarded` (Q1). B3 needs no model (compare.py).

Output: data/derived/phase8m/dev/<variant>/<domain>__seed<k>.npz (Phase 8j fields) and
        data/derived/phase8m/models/<variant>/<target network>__seed<k>.txt (LightGBM boosters)
        reports/phase8m/dev/scores_seed<k>.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8m/dev_scores.py --seed 0
       [--variants B2,B0r] [--targets nfunsw]   (subsets: smoke runs only)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LA = _load("leakage_audit_8j", ROOT / "scripts/phase8j/leakage_audit.py")
DS = _load("dev_scores_8j", ROOT / "scripts/phase8j/dev_scores.py")
C = LA.C
S = C.S

from netsentinel.resources import peak_rss_mb  # noqa: E402

NOV = ROOT / "data" / "derived" / "phase8m" / "novelty"
OUT = ROOT / "data" / "derived" / "phase8m" / "dev"
MODELS = ROOT / "data" / "derived" / "phase8m" / "models"
REPORTS = ROOT / "reports" / "phase8m" / "dev"
B0_SCORES = ROOT / "data" / "derived" / "phase8j" / "dev"

BASE = list(S.FEATS)  # the 12 registered window features (B0)
BASE11 = [f for f in BASE if f != "new_dst_frac"]
B1 = BASE11 + ["nov_guarded", "log_new_guarded", "familiarity_decay"]
B2 = B1 + ["nov_host", "log_prevalence"]
VARIANTS = {
    "B0r": BASE,
    "B1": B1,
    "B2": B2,
    "B1u": BASE11 + ["nov_unconditional", "familiarity_decay"],
    "A_none": BASE11,
    "A_novol": [f for f in B2 if f not in C.VOLUME],
}
NOVCOLS = ("nov_frozen", "nov_unconditional", "nov_guarded", "nov_host", "log_new_guarded",
           "familiarity_decay", "log_prevalence")  # fmt: skip


def join_novelty(frame: pl.DataFrame, nov: pl.DataFrame, what: str) -> pl.DataFrame:
    """`frame` with the novelty columns, row order and count unchanged; every window must have
    them (a missing window means the build and the windows disagree)."""
    j = (frame.drop([c for c in NOVCOLS if c in frame.columns]).with_row_index("_i")
         .join(nov, on=["key", "win"], how="left").sort("_i").drop("_i"))  # fmt: skip
    miss = int(j["nov_guarded"].null_count())
    if miss or j.height != frame.height:
        raise SystemExit(f"{what}: {miss} windows without novelty features")
    return j


def novelty(network: str, domain: str, variant: str) -> pl.DataFrame:
    nov = pl.read_parquet(NOV / network / domain / f"{variant}.parquet")
    if nov.select(pl.struct("key", "win").is_duplicated().any()).item():
        raise SystemExit(f"{network}/{domain} {variant}: duplicate (key, win) novelty rows")
    return nov


def attach_sources(nets: dict[str, dict[str, dict]]) -> None:
    """Training windows (Phase 8i clean) get the clean-memory novelty columns."""
    for net, doms in nets.items():
        for name, d in doms.items():
            C.prepare(d)  # cache the benign split before the feature list changes
            nov = novelty(net, name.split("/")[1], "clean")
            d["cal"] = join_novelty(d["cal"], nov, f"{name} cal_clean")
            d["ev"] = join_novelty(d["ev"], nov, f"{name} eval_clean")


def target_frames(d: dict) -> tuple[pl.DataFrame, pl.DataFrame]:
    cal, ev = DS.p1x_frames(d)
    nov = novelty(d["network"], d["name"], "p1x")
    return join_novelty(cal, nov, f"{d['name']} cal_p1x"), join_novelty(
        ev, nov, f"{d['name']} eval_p1x"
    )


def x_of(frame: pl.DataFrame, feats: list[str]) -> np.ndarray:
    S.FEATS = feats
    try:
        return S._x(frame)
    finally:
        S.FEATS = BASE


def fit(srcs: dict, seed: int, feats: list[str]):
    S.FEATS = feats  # train_matrix -> S._x reads the module-level list
    try:
        return C.fit_source(srcs, seed, C.Rep("raw"))[0]
    finally:
        S.FEATS = BASE


def save_npz(path: Path, d: dict, cal: pl.DataFrame, ev: pl.DataFrame, s_cal, s_ev, hold,
             **extra) -> None:  # fmt: skip
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path, cal_key=cal["key"].to_numpy().astype(str), cal_win=cal["win"].to_numpy(),
        cal_end=cal["window_end_ms"].to_numpy(), cal_s=s_cal, cal_hold=hold,
        ev_key=ev["key"].to_numpy().astype(str), ev_win=ev["win"].to_numpy(),
        ev_end=ev["window_end_ms"].to_numpy(), ev_s=s_ev, ev_y=ev["y"].to_numpy(),
        ev_benign=ev["benign"].to_numpy(), ev_noisy=ev["noisy"].to_numpy(),
        attackers=np.array(sorted(d["attackers"]), dtype=str),
        hours=np.array(d["hours"]), network=np.array(d["network"]), **extra)  # fmt: skip


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--variants", default=",".join(VARIANTS))
    ap.add_argument("--targets", help="comma-separated target networks (smoke runs)")
    a = ap.parse_args()
    seed, chosen = a.seed, a.variants.split(",")
    t0 = time.perf_counter()
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    attach_sources({n: nets[n] for n in C.DEV_NETWORKS})
    todo = [t for t in LA.targets(nets) if not a.targets or t[1]["network"] in a.targets.split(",")]
    frames = {name: target_frames(d) for name, d, _ in todo}
    info: dict[str, dict] = {}
    for v in chosen:
        feats = VARIANTS[v]
        cache: dict[tuple, object] = {}
        for name, d, srcs in todo:
            key = tuple(sorted(srcs))
            if key not in cache:
                cache[key] = fit(srcs, seed, feats)
                mp = MODELS / v / f"{d['network']}__seed{seed}.txt"
                mp.parent.mkdir(parents=True, exist_ok=True)
                cache[key].booster_.save_model(str(mp))
            model = cache[key]
            cal, ev = frames[name]
            hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
            s_cal = model.predict_proba(x_of(cal, feats))[:, 1]
            s_ev = model.predict_proba(x_of(ev, feats))[:, 1]
            extra, row = {}, {"cal": cal.height, "hold": int(hold.sum()), "eval": ev.height}
            if v == "B0r":
                q1 = ev.with_columns(pl.col("nov_guarded").alias("new_dst_frac"))
                extra["ev_s_q1"] = model.predict_proba(x_of(q1, feats))[:, 1]
                ref = np.load(B0_SCORES / f"{name.replace('/', '__')}__seed{seed}.npz")
                row["b0_max_abs_diff"] = float(max(np.abs(ref["ev_s"] - s_ev).max(),
                                                   np.abs(ref["cal_s"] - s_cal).max()))  # fmt: skip
            save_npz(OUT / v / f"{name.replace('/', '__')}__seed{seed}.npz", d, cal, ev, s_cal,
                     s_ev, hold, **extra)  # fmt: skip
            info.setdefault(v, {})[name] = row
            print(v, name, row, flush=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    tail = "" if a.variants == ",".join(VARIANTS) and not a.targets else "_subset"
    (REPORTS / f"scores_seed{seed}{tail}.json").write_bytes(json.dumps(
        {"seed": seed, "variants": {v: VARIANTS[v] for v in chosen}, "domains": info,
         "peak_rss_mb": peak_rss_mb(), "seconds": round(time.perf_counter() - t0, 1)},
        indent=1).encode())  # fmt: skip


if __name__ == "__main__":
    main()
