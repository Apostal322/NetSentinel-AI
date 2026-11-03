"""Phase 8n Experiments B/C: train the registered candidates M0-M3 in the base and stress
regimes (docs/phase8n/PREREGISTRATION.md, amendment 1). REGISTERED DEVELOPMENT.

- M0: B0 (Phase 8i LightGBM, 12 features). Base = Experiment A's P_ref, stress =
  `A5_host_bootstrap`; both are recomputed here and must match those saved scores exactly.
- M2: mean probability of 5 members, each with its own subsample and LightGBM seed.
- M1: mean probability of 5 members, each on its own host bootstrap of the training data.
- M3: one model with min_child_samples 200 and reg_lambda 5.

Regimes: base (Phase 8j training data, subsample seed r) and stress (source hosts resampled
with replacement, seed (8, r, domain), before the model is built). Calibration and evaluation
are the Phase 8j P1x ones.

Output: data/derived/phase8n/candidates/<model>/<regime>/<domain>__r<k>.npz (s_hold, s_ev) and
reports/phase8n/candidates_runs.json (resumable; existing outputs are kept).
Usage: python scripts/run_capped.py -- <python> scripts/phase8n/candidates.py [--models M0,M3]
       [--regimes base] [--reps 0] [--targets nfcic]
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
_spec = importlib.util.spec_from_file_location(
    "phase8n_fragility", ROOT / "scripts/phase8n/fragility.py"
)
FR = importlib.util.module_from_spec(_spec)
sys.modules["phase8n_fragility"] = FR
_spec.loader.exec_module(FR)
C, S, LA, DS = FR.C, FR.S, FR.LA, FR.DS

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = ROOT / "data" / "derived" / "phase8n" / "candidates"
FRAG = ROOT / "data" / "derived" / "phase8n" / "fragility"
REPORT = ROOT / "reports" / "phase8n" / "candidates_runs.json"
MEMBERS = 5
REGULARISED = {"min_child_samples": 200, "reg_lambda": 5.0}
MODELS = ("M0", "M1", "M2", "M3")
REPLICATION = frozenset({3, 4, 5})  # fresh-randomness replicates of amendment 2
REGIMES = ("base", "stress")


def source_data(srcs: dict, sample_seed: int, outer: int | None) -> list[tuple]:
    """Per source domain: (X, y, hosts, network weight); with `outer`, the hosts resampled with
    replacement exactly as Experiment A's `A5_host_bootstrap`."""
    names = list(srcs)
    dw = C.network_weights([srcs[n]["network"] for n in names])
    out = []
    for j, (n, w_dom) in enumerate(zip(names, dw, strict=True)):
        x, y, keys = FR.train_rows(srcs[n], sample_seed)
        if outer is not None:
            idx = FR.host_bootstrap(keys, np.random.default_rng([8, outer, j]))
            x, y, keys = x[idx], y[idx], keys[idx]
        out.append((x, y, keys, w_dom))
    return out


def fit_one(
    data: list[tuple], model_seed: int, inner: tuple | None = None, overrides: dict | None = None
):
    """Phase 8i fit_source on prepared data (network- and class-balanced weights computed after
    any resampling); `inner` adds a member-level host bootstrap (bagging)."""
    import lightgbm as lgb

    xs, ys, ws = [], [], []
    for j, (x, y, keys, w_dom) in enumerate(data):
        if inner is not None:
            idx = FR.host_bootstrap(keys, np.random.default_rng([18, *inner, j]))
            x, y = x[idx], y[idx]
        xs.append(x)
        ys.append(y)
        ws.append(w_dom * np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
    X, y, w = np.vstack(xs), np.concatenate(ys), np.concatenate(ws)  # noqa: N806
    params = {**C.LGB, **(overrides or {})}
    return lgb.LGBMClassifier(random_state=model_seed, **params).fit(
        X, y, sample_weight=w * len(y) / w.sum()
    )


def build(model: str, regime: str, r: int, srcs: dict) -> list:
    outer = r if regime == "stress" else None
    # replicates 0-2: stress fits use seeds (0, 0) as Experiment A's A5_host_bootstrap; the fresh
    # replication replicates (amendment 2) use seed r in both regimes
    zero = regime == "stress" and r not in REPLICATION
    base_sample = 0 if zero else r
    base_seed = 0 if zero else r
    if model in ("M0", "M3"):
        over = REGULARISED if model == "M3" else None
        return [fit_one(source_data(srcs, base_sample, outer), base_seed, overrides=over)]
    members = []
    if model == "M1":
        data = source_data(srcs, base_sample, outer)
        for m in range(MEMBERS):
            members.append(fit_one(data, 1000 + 10 * r + m, inner=(r, m)))
        return members
    for m in range(
        MEMBERS
    ):  # M2: each member its own subsample (and the same outer bootstrap seed)
        seed = 1000 + 10 * r + m
        members.append(fit_one(source_data(srcs, seed, outer), seed))
    return members


def save_atomic(out: Path, **arrays) -> None:
    """Write the npz under a temporary name and rename it, so an interrupted run never leaves a
    truncated file that a resumed run would take as complete."""
    tmp = out.with_name(out.stem + ".tmp.npz")
    np.savez_compressed(tmp, **arrays)
    tmp.replace(out)


def provenance(args) -> dict:
    """Git commit, package versions, code hash and arguments of this invocation."""
    import hashlib
    import subprocess

    import lightgbm

    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    code = hashlib.sha256(Path(__file__).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    return {"git_head": sha, "candidates_py_sha256": code, "lightgbm": lightgbm.__version__,
            "numpy": np.__version__, "polars": pl.__version__, "args": vars(args),
            "lgb_params": C.LGB, "regularised": REGULARISED, "members": MEMBERS}  # fmt: skip


def score(members: list, x: np.ndarray) -> np.ndarray:
    return np.mean([m.predict_proba(x)[:, 1] for m in members], axis=0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default=",".join(MODELS))
    ap.add_argument("--regimes", default=",".join(REGIMES))
    ap.add_argument("--reps", default="0,1,2")
    ap.add_argument("--targets")
    a = ap.parse_args()
    t_start = time.perf_counter()
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    todo = [t for t in LA.targets(nets) if not a.targets or t[1]["network"] in a.targets.split(",")]
    frames = {name: DS.p1x_frames(d) for name, d, _ in todo}
    log = json.loads(REPORT.read_text("utf-8")) if REPORT.exists() else {"runs": {}}
    log.setdefault("provenance", []).append(provenance(a))
    for model in a.models.split(","):
        for regime in a.regimes.split(","):
            for r in [int(x) for x in a.reps.split(",")]:
                groups: dict[tuple, list] = {}
                for name, _d, srcs in todo:
                    groups.setdefault(tuple(sorted(srcs)), []).append((name, srcs))
                for items in groups.values():
                    outs = [
                        OUT / model / regime / f"{n.replace('/', '__')}__r{r}.npz" for n, _ in items
                    ]
                    if all(o.exists() for o in outs):
                        continue
                    t0 = time.perf_counter()
                    members = build(model, regime, r, items[0][1])
                    fit_s = round(time.perf_counter() - t0, 1)
                    for (name, _), out in zip(items, outs, strict=True):
                        cal, ev = frames[name]
                        hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
                        s_hold = score(members, S._x(cal.filter(pl.Series(hold))))
                        s_ev = score(members, S._x(ev))
                        row = {"members": len(members), "fit_seconds": fit_s}
                        if model == "M0" and r not in REPLICATION:  # = the Experiment A arm
                            arm = "P_ref" if regime == "base" else "A5_host_bootstrap"
                            ref = np.load(FRAG / arm / f"{name.replace('/', '__')}__r{r}.npz")
                            row["experiment_a_max_abs_diff"] = float(max(np.abs(ref["s_ev"] - s_ev).max(),
                                                                         np.abs(ref["s_hold"] - s_hold).max()))  # fmt: skip
                        out.parent.mkdir(parents=True, exist_ok=True)
                        save_atomic(out, s_hold=s_hold, s_ev=s_ev)
                        log["runs"].setdefault(f"{model}/{regime}", {})[f"{name} r{r}"] = row
                        print(model, regime, name, r, row, flush=True)
                    log["peak_rss_mb"] = peak_rss_mb()
                    log["seconds_last_call"] = round(time.perf_counter() - t_start, 1)
                    REPORT.parent.mkdir(parents=True, exist_ok=True)
                    tmp = REPORT.with_suffix(".tmp")
                    tmp.write_bytes(json.dumps(log, indent=1).encode())
                    tmp.replace(REPORT)


if __name__ == "__main__":
    main()
