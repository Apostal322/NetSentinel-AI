"""Phase 8p Experiment E: train the registered arms (docs/phase8p/PREREGISTRATION.md).
REGISTERED DEVELOPMENT.

Every fit is the Phase 8n M2 construction:
- 5 members, seeds 1000 + 10r + m;
- `candidates.fit_one`, unchanged;
- training rows built exactly as Phase 8n `fragility.train_rows` / `candidates.source_data`, with a
  feature list. With the 12 registered features, `S0` must reproduce the Phase 8o F0 member scores
  exactly (R1, checked on every base fit).

**Source arms** (source windows; SX features joined on (key, win) from `build_victim.py`):
- S0, the 12 features (base only; also scores the C2 windows);
- D2 = 12 + context;
- S1 = 12 + service;
- D2S = 12 + context + service;
- Sonly = service only.

**Victim arms** (victim windows of `build_victim.py`):
- D1, the 16 VW features;
- D1h, D1 without the history features.

A victim arm scores ALL victim windows of each target. The analysis forms the D1 hold-out, its
evaluation and the D3 fusion from those scores.

Output:
- data/derived/phase8p/experiment_e/<arm>/<regime>/<domain>__r<k>.npz (per-member scores);
- data/derived/phase8p/experiment_e/_vw_index/<domain>.parquet;
- reports/phase8p/experiment_e_runs.json (resumable; existing outputs are kept).

Usage: python scripts/run_capped.py -- <python> scripts/phase8p/experiment_e.py --arms S0,D2 [--regimes base] [--reps 6]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
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


CA = _load("phase8n_candidates", ROOT / "scripts/phase8n/candidates.py")
FR, C, S, LA, DS = CA.FR, CA.C, CA.S, CA.LA, CA.DS

from netsentinel.behavior.victim import CONTEXT_FEATURES, SERVICE_FEATURES, VICTIM_FEATURES  # noqa: E402
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = ROOT / "data" / "derived" / "phase8p" / "experiment_e"
VICTIM = ROOT / "data" / "derived" / "phase8p" / "victim"
C2 = ROOT / "data" / "derived" / "phase8p" / "c2"
F0 = ROOT / "data" / "derived" / "phase8o" / "experiment_d" / "F0"
REPORT = ROOT / "reports" / "phase8p" / "experiment_e_runs.json"
MEMBERS = 5
REPS = (6, 7, 8)
HIST = ("v_hist_dev", "v_hist_n")
FEATURES = {
    "S0": tuple(WINDOW_FEATURES),
    "D2": tuple(WINDOW_FEATURES) + CONTEXT_FEATURES,
    "S1": tuple(WINDOW_FEATURES) + SERVICE_FEATURES,
    "D2S": tuple(WINDOW_FEATURES) + CONTEXT_FEATURES + SERVICE_FEATURES,
    "Sonly": SERVICE_FEATURES,
    "D1": VICTIM_FEATURES,
    "D1h": tuple(f for f in VICTIM_FEATURES if f not in HIST),
}
REGIMES = {"S0": ("base",), "D2": ("base", "stress"), "S1": ("base", "stress"),
           "D2S": ("base", "stress"), "Sonly": ("base",), "D1": ("base", "stress"), "D1h": ("base",)}  # fmt: skip
VICTIM_ARMS = ("D1", "D1h")
SX_COLS = CONTEXT_FEATURES + SERVICE_FEATURES


def member_seed(r: int, m: int) -> int:
    return 1000 + 10 * r + m


def xmat(frame: pl.DataFrame, feats: tuple[str, ...]) -> np.ndarray:
    """As Phase 8b `scorers._x`, for any feature list."""
    return np.nan_to_num(frame.select([pl.col(f).cast(pl.Float64) for f in feats]).to_numpy())


def sx_join(frame: pl.DataFrame, sx: pl.DataFrame) -> pl.DataFrame:
    """`frame` with the SX columns on matching (key, win), same rows and order; every row must match."""
    j = frame.join(
        sx.select("key", "win", *SX_COLS), on=["key", "win"], how="left", maintain_order="left"
    )
    if (
        j.height != frame.height
        or not j["key"].equals(frame["key"])
        or not j["win"].equals(frame["win"])
    ):
        raise RuntimeError("SX join changed the rows")
    miss = int(j[SX_COLS[0]].null_count())
    if miss:
        raise RuntimeError(f"{miss} rows without SX features")
    return j


def load_sx(network: str, domain: str) -> pl.DataFrame:
    sx = pl.read_parquet(VICTIM / network / domain / "sx" / "*.parquet")
    # defensive only: slices hold whole windows, so (key, win) is unique (checked in the review)
    return sx.unique(subset=["key", "win"], keep="first")


def train_rows(
    d: dict, sample_seed: int, feats: tuple[str, ...]
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Phase 8n `fragility.train_rows` with a feature list (same rows, labels, cap and draw)."""
    ev = d["ev"].filter(~pl.col("noisy"))
    x = np.vstack([xmat(d["cal"], feats), xmat(ev, feats)])
    y = np.concatenate([np.zeros(d["cal"].height), ev["y"].to_numpy()]).astype(int)
    keys = np.concatenate([d["cal"]["key"].to_numpy(), ev["key"].to_numpy()]).astype(str)
    return cap(x, y, keys, sample_seed)


def cap(x: np.ndarray, y: np.ndarray, keys: np.ndarray, sample_seed: int):
    if len(y) > C.CAP:
        rng = np.random.default_rng(sample_seed)
        pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
        pos = rng.choice(pos, min(len(pos), C.CAP // 2), replace=False)
        neg = rng.choice(neg, min(len(neg), C.CAP - len(pos)), replace=False)
        idx = np.sort(np.concatenate([pos, neg]))
        x, y, keys = x[idx], y[idx], keys[idx]
    return x, y, keys


def source_data(srcs: dict, sample_seed: int, outer: int | None, rows) -> list[tuple]:
    """Phase 8n `candidates.source_data` with a row builder `rows(d, sample_seed)`."""
    names = list(srcs)
    dw = C.network_weights([srcs[n]["network"] for n in names])
    out = []
    for j, (n, w_dom) in enumerate(zip(names, dw, strict=True)):
        x, y, keys = rows(srcs[n], sample_seed)
        if outer is not None:
            idx = FR.host_bootstrap(keys, np.random.default_rng([8, outer, j]))
            x, y, keys = x[idx], y[idx], keys[idx]
        out.append((x, y, keys, w_dom))
    return out


def fit_members(srcs: dict, regime: str, r: int, rows) -> list:
    outer = r if regime == "stress" else None
    return [CA.fit_one(source_data(srcs, member_seed(r, m), outer, rows), member_seed(r, m))
            for m in range(MEMBERS)]  # fmt: skip


def scores(members: list, x: np.ndarray) -> np.ndarray:
    return np.vstack([m.predict_proba(x)[:, 1] for m in members])


# ---------------------------------------------------------------- victim data


def load_vw(network: str, domain: str) -> pl.DataFrame:
    return pl.read_parquet(VICTIM / network / domain / "vw" / "*.parquet").sort("win", "dst")


def victim_domain(network: str, domain: str) -> dict:
    """Training victim windows of a source domain: not noisy; y = holds an attack flow."""
    v = load_vw(network, domain).filter(~pl.col("noisy"))
    return {
        "network": network,
        "name": domain,
        "frame": v,
        "y": (v["attack_flows"] > 0).to_numpy().astype(int),
        "keys": v["dst"].to_numpy().astype(str),
    }


def victim_rows(feats: tuple[str, ...]):
    def rows(d: dict, sample_seed: int):
        return cap(xmat(d["frame"], feats), d["y"], d["keys"], sample_seed)

    return rows


def provenance(args) -> dict:
    import lightgbm

    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    code = {p: hashlib.sha256((ROOT / p).read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:16]
            for p in ("scripts/phase8p/experiment_e.py", "src/netsentinel/behavior/victim.py",
                      "scripts/phase8n/candidates.py", "scripts/phase8i/common.py")}  # fmt: skip
    return {"git_head": sha, "code_sha256_16": code, "lightgbm": lightgbm.__version__,
            "numpy": np.__version__, "polars": pl.__version__, "args": vars(args),
            "lgb_params": C.LGB, "members": MEMBERS}  # fmt: skip


def save_log(log: dict) -> None:
    log["peak_rss_mb"] = peak_rss_mb()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(log, indent=1).encode())
    tmp.replace(REPORT)


def c2_frames(d: dict) -> tuple[pl.DataFrame, pl.DataFrame] | None:
    base = C2 / d["network"] / d["name"]
    if not (base / "cal_p1x.parquet").exists():
        return None
    cal = pl.read_parquet(base / "cal_p1x.parquet").sort("win", "key")
    ev = pl.read_parquet(base / "eval_p1x.parquet")
    lab = d["ev"].select("key", "win", "y", "benign", "noisy")
    ev = ev.join(lab, on=["key", "win"], how="inner").sort("win", "key")
    if ev.height != d["ev"].height:
        raise RuntimeError(f"{d['name']}: C2 evaluation windows do not match the labelled ones")
    return cal, ev


def run_source_arms(arms: list[str], regimes: list[str], reps: list[int], log: dict) -> None:
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    for doms in nets.values():  # SX columns on every training and labelled window, once
        for d in doms.values():
            # keys of `load_network` are "<network>/<domain>"; a missing build must fail, not skip
            sx = load_sx(d["network"], d["name"])
            d["cal"] = sx_join(d["cal"], sx)
            d["ev"] = sx_join(d["ev"], sx)
    todo = LA.targets(nets)
    frames = {}
    for name, d, _ in todo:
        cal, ev = DS.p1x_frames(d)
        sx = load_sx(d["network"], d["name"])
        frames[name] = (sx_join(cal, sx), sx_join(ev, sx))
    groups: dict[tuple, list] = {}
    for name, d, srcs in todo:
        groups.setdefault(tuple(sorted(srcs)), []).append((name, d, srcs))
    for arm in arms:
        feats = FEATURES[arm]
        rows = lambda d, s, f=feats: train_rows(d, s, f)  # noqa: E731
        for regime in [g for g in regimes if g in REGIMES[arm]]:
            for r in reps:
                for items in groups.values():
                    outs = [
                        OUT / arm / regime / f"{n.replace('/', '__')}__r{r}.npz"
                        for n, _, _ in items
                    ]
                    if all(o.exists() for o in outs):
                        continue
                    t0 = time.perf_counter()
                    members = fit_members(items[0][2], regime, r, rows)
                    fit_s = round(time.perf_counter() - t0, 1)
                    for (name, d, _), out in zip(items, outs, strict=True):
                        cal, ev = frames[name]
                        hold = cal.filter(pl.Series((cal["win"] >= S.split_cut(cal)).to_numpy()))
                        arrays = {
                            "s_hold": scores(members, xmat(hold, feats)),
                            "s_ev": scores(members, xmat(ev, feats)),
                        }
                        row = {"fit_seconds": fit_s, "features": len(feats)}
                        if arm == "S0":
                            ref = np.load(F0 / regime / f"{name.replace('/', '__')}__r{r}.npz")
                            row["R1_max_abs_diff_vs_phase8o_F0"] = float(max(np.abs(ref["s_hold"] - arrays["s_hold"]).max(),
                                                                             np.abs(ref["s_ev"] - arrays["s_ev"]).max()))  # fmt: skip
                            c2 = c2_frames(d)
                            if c2 is not None:
                                c2cal, c2ev = c2
                                h2 = c2cal.filter(
                                    pl.Series((c2cal["win"] >= S.split_cut(c2cal)).to_numpy())
                                )
                                arrays["s_hold_c2"] = scores(members, xmat(h2, feats))
                                arrays["s_ev_c2"] = scores(members, xmat(c2ev, feats))
                        out.parent.mkdir(parents=True, exist_ok=True)
                        CA.save_atomic(out, **arrays)
                        log["runs"].setdefault(f"{arm}/{regime}", {})[f"{name} r{r}"] = row
                        print(arm, regime, name, r, row, flush=True)
                    del members
                    save_log(log)


def run_victim_arms(arms: list[str], regimes: list[str], reps: list[int], log: dict) -> None:
    sources = {}
    for net in C.DEV_NETWORKS:
        for p in sorted((VICTIM / net).iterdir()):
            if (C.DERIVED / net / p.name).exists():
                sources[f"{net}/{p.name}"] = victim_domain(net, p.name)
    targets = sorted(
        f"{p.parent.parent.name}/{p.parent.name}"
        for p in (C.DERIVED.parent / "phase8j" / "p1x").glob("*/*/eval_p1x.parquet")
    )
    tvw = {}
    for t in targets:
        net, dom = t.split("/")
        v = load_vw(net, dom)
        idx = OUT / "_vw_index" / f"{t.replace('/', '__')}.parquet"
        idx.parent.mkdir(parents=True, exist_ok=True)
        if not idx.exists():
            v.select(
                "dst", "win", "period", "noisy", "flows", "srcs", "attack_flows", "attack_srcs"
            ).write_parquet(idx)
        tvw[t] = v
    for arm in arms:
        feats = FEATURES[arm]
        for regime in [g for g in regimes if g in REGIMES[arm]]:
            for r in reps:
                for tnet in LA.NETWORKS:
                    srcs = {k: v for k, v in sources.items() if k.split("/")[0] != tnet}
                    names = [t for t in targets if t.startswith(tnet + "/")]
                    outs = [OUT / arm / regime / f"{t.replace('/', '__')}__r{r}.npz" for t in names]
                    if all(o.exists() for o in outs):
                        continue
                    t0 = time.perf_counter()
                    members = fit_members(srcs, regime, r, victim_rows(feats))
                    fit_s = round(time.perf_counter() - t0, 1)
                    for t, out in zip(names, outs, strict=True):
                        out.parent.mkdir(parents=True, exist_ok=True)
                        CA.save_atomic(out, s_vw=scores(members, xmat(tvw[t], feats)))
                        row = {"fit_seconds": fit_s, "features": len(feats), "sources": len(srcs)}
                        log["runs"].setdefault(f"{arm}/{regime}", {})[f"{t} r{r}"] = row
                        print(arm, regime, t, r, row, flush=True)
                    del members
                    save_log(log)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", required=True)
    ap.add_argument("--regimes", default="base,stress")
    ap.add_argument("--reps", default=",".join(map(str, REPS)))
    a = ap.parse_args()
    arms = a.arms.split(",")
    if any(x not in FEATURES for x in arms):
        sys.exit(f"unknown arm in {arms}")
    log = json.loads(REPORT.read_text("utf-8")) if REPORT.exists() else {"runs": {}}
    log.setdefault("provenance", []).append(provenance(a))
    regimes, reps = a.regimes.split(","), [int(x) for x in a.reps.split(",")]
    src_arms = [x for x in arms if x not in VICTIM_ARMS]
    if src_arms:
        run_source_arms(src_arms, regimes, reps, log)
    if any(x in VICTIM_ARMS for x in arms):
        run_victim_arms([x for x in arms if x in VICTIM_ARMS], regimes, reps, log)
    save_log(log)


if __name__ == "__main__":
    main()
