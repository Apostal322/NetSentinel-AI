"""Phase 8n Experiment A: isolate refit fragility of the B0 LightGBM detector
(docs/phase8n/PREREGISTRATION.md, Experiment A). REGISTERED DEVELOPMENT DIAGNOSTIC.

The Phase 8j P1x protocol (scripts/phase8j/dev_scores.py) with one controlled perturbation at a
time. Every perturbation starts from the exact reference fit `P_ref`, which must reproduce the
saved Phase 8j B0 scores bit for bit (checked and recorded); anything else is a change of ONE of:

- A2 no-op representations (information preserved): reversed column order, an extra constant
  column, a monotone transform of `new_dst_frac` (square root);
- A4 feature removal (one of the 12 features at a time) and `A4_shuffle_new_dst_frac` (the column
  kept but its values permuted within each training domain: information removed, layout kept);
- A5 training randomness: LightGBM seed only, training-subsample seed only, and a host-cluster
  bootstrap of each source domain's training windows;
- A6 source-network reweighting: one source network's weight doubled.

The target side (P1x calibration hold-out, T0, evaluation windows) is unchanged except for the
same column transform; shuffling and resampling act on training data only.

Output: data/derived/phase8n/fragility/<perturbation>/<domain>__r<k>.npz (hold-out and evaluation
scores; windows are those of the Phase 8j B0 file of the same domain) and
reports/phase8n/fragility_runs.json. Existing outputs are kept (resumable).
Usage: python scripts/run_capped.py -- <python> scripts/phase8n/fragility.py [--perts a,b]
       [--targets nfcic] [--reps 0,1,2]
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

OUT = ROOT / "data" / "derived" / "phase8n" / "fragility"
REPORT = ROOT / "reports" / "phase8n" / "fragility_runs.json"
B0_DIR = ROOT / "data" / "derived" / "phase8j" / "dev"
FEATS = list(S.FEATS)  # the 12 registered window features, in order
NDF = FEATS.index("new_dst_frac")


def perturbations() -> dict[str, dict]:
    """name -> spec. `reps` maps a replicate index to (model seed, sample seed)."""
    base = {k: (k, k) for k in range(3)}
    p = {"P_ref": {"reps": base},
         "A2_reverse_columns": {"reps": base, "order": list(range(len(FEATS)))[::-1]},
         "A2_constant_column": {"reps": base, "constant": True},
         "A2_sqrt_new_dst_frac": {"reps": base, "sqrt": NDF}}  # fmt: skip
    for i, f in enumerate(FEATS):
        p[f"A4_drop_{f}"] = {"reps": base, "drop": i}
    p["A4_shuffle_new_dst_frac"] = {"reps": base, "shuffle": NDF}
    p["A5_lgb_seed"] = {"reps": {k: (100 + k, 0) for k in range(3)}}
    p["A5_sample_seed"] = {"reps": {k: (0, 100 + k) for k in range(3)}}
    p["A5_host_bootstrap"] = {"reps": {k: (0, 0) for k in range(3)}, "boot": True}
    for net in C.DEV_NETWORKS:
        p[f"A6_double_{net}"] = {"reps": base, "double": net}
    return p


def transform(x: np.ndarray, spec: dict) -> np.ndarray:
    """The column change applied identically to training and target matrices."""
    if "sqrt" in spec:
        x = x.copy()
        x[:, spec["sqrt"]] = np.sqrt(np.clip(x[:, spec["sqrt"]], 0, None))
    if "drop" in spec:
        x = np.delete(x, spec["drop"], axis=1)
    if "order" in spec:
        x = x[:, spec["order"]]
    if spec.get("constant"):
        x = np.hstack([x, np.ones((len(x), 1))])
    return x


def train_rows(d: dict, sample_seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Raw X, y and source host of a source domain: exactly Phase 8h `train_matrix` (clean
    calibration + non-noisy evaluation, CAP subsample drawn with `sample_seed`), plus the keys."""
    ev = d["ev"].filter(~pl.col("noisy"))
    x = np.vstack([S._x(d["cal"]), S._x(ev)])
    y = np.concatenate([np.zeros(d["cal"].height), ev["y"].to_numpy()]).astype(int)
    keys = np.concatenate([d["cal"]["key"].to_numpy(), ev["key"].to_numpy()]).astype(str)
    if len(y) > C.CAP:
        rng = np.random.default_rng(sample_seed)
        pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
        pos = rng.choice(pos, min(len(pos), C.CAP // 2), replace=False)
        neg = rng.choice(neg, min(len(neg), C.CAP - len(pos)), replace=False)
        idx = np.sort(np.concatenate([pos, neg]))
        x, y, keys = x[idx], y[idx], keys[idx]
    return x, y, keys


def host_bootstrap(keys: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    """Row indices after resampling the source hosts with replacement (all of a host's windows
    move together, so correlated windows are never treated as independent draws)."""
    hosts, inv = np.unique(keys, return_inverse=True)
    mult = np.bincount(rng.integers(0, len(hosts), len(hosts)), minlength=len(hosts))
    return np.repeat(np.arange(len(keys)), mult[inv])


def fit(srcs: dict, spec: dict, model_seed: int, sample_seed: int, rep: int):
    """Phase 8i `fit_source` (B-raw LightGBM, network-balanced, class-balanced weights) with the
    perturbation `spec`; with an empty spec it is the same computation."""
    import lightgbm as lgb

    names = list(srcs)
    nets = [srcs[n]["network"] for n in names]
    dw = C.network_weights(nets)
    if "double" in spec:
        dw = np.where(np.array(nets) == spec["double"], 2 * dw, dw)
    xs, ys, ws = [], [], []
    for j, (n, w_dom) in enumerate(zip(names, dw, strict=True)):
        x, y, keys = train_rows(srcs[n], sample_seed)
        if spec.get("boot"):
            idx = host_bootstrap(keys, np.random.default_rng([8, rep, j]))
            x, y = x[idx], y[idx]
        if "shuffle" in spec:
            x = x.copy()
            x[:, spec["shuffle"]] = np.random.default_rng([9, model_seed, j]).permutation(
                x[:, spec["shuffle"]]
            )
        xs.append(transform(x, spec))
        ys.append(y)
        ws.append(w_dom * np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
    X, y, w = np.vstack(xs), np.concatenate(ys), np.concatenate(ws)  # noqa: N806
    return lgb.LGBMClassifier(random_state=model_seed, **C.LGB).fit(
        X, y, sample_weight=w * len(y) / w.sum()
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--perts", help="comma-separated perturbation names (default: all)")
    ap.add_argument("--targets", help="comma-separated target networks (default: all)")
    ap.add_argument("--reps", default="0,1,2")
    a = ap.parse_args()
    specs = perturbations()
    chosen = a.perts.split(",") if a.perts else list(specs)
    reps = [int(r) for r in a.reps.split(",")]
    t_start = time.perf_counter()
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    todo = [t for t in LA.targets(nets) if not a.targets or t[1]["network"] in a.targets.split(",")]
    frames = {name: DS.p1x_frames(d) for name, d, _ in todo}
    log = json.loads(REPORT.read_text("utf-8")) if REPORT.exists() else {"runs": {}}
    for pname in chosen:
        spec = specs[pname]
        for r in reps:
            model_seed, sample_seed = spec["reps"][r]
            cache: dict[tuple, object] = {}
            for name, _d, srcs in todo:
                out = OUT / pname / f"{name.replace('/', '__')}__r{r}.npz"
                if out.exists():
                    continue
                key = tuple(sorted(srcs))
                t0 = time.perf_counter()
                if key not in cache:
                    if "double" in spec and spec["double"] not in {
                        s["network"] for s in srcs.values()
                    }:
                        cache[key] = None  # that network is not a source for this target
                    else:
                        cache[key] = fit(srcs, spec, model_seed, sample_seed, r)
                model = cache[key]
                if model is None:
                    continue
                cal, ev = frames[name]
                hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
                s_hold = model.predict_proba(transform(S._x(cal.filter(pl.Series(hold))), spec))[
                    :, 1
                ]
                s_ev = model.predict_proba(transform(S._x(ev), spec))[:, 1]
                out.parent.mkdir(parents=True, exist_ok=True)
                row = {"model_seed": model_seed, "sample_seed": sample_seed, "hold": int(hold.sum()),
                       "eval": ev.height, "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
                if pname == "P_ref":
                    ref = np.load(B0_DIR / f"{name.replace('/', '__')}__seed{r}.npz")
                    row["b0_max_abs_diff"] = float(max(np.abs(ref["ev_s"] - s_ev).max(),
                                                       np.abs(ref["cal_s"][ref["cal_hold"]] - s_hold).max()))  # fmt: skip
                np.savez_compressed(out, s_hold=s_hold, s_ev=s_ev)
                log["runs"].setdefault(pname, {})[f"{name} r{r}"] = row
                print(pname, name, r, row, flush=True)
            log["peak_rss_mb"] = peak_rss_mb()
            log["seconds_last_call"] = round(time.perf_counter() - t_start, 1)
            REPORT.parent.mkdir(parents=True, exist_ok=True)
            tmp = REPORT.with_suffix(".tmp")
            tmp.write_bytes(json.dumps(log, indent=1).encode())
            tmp.replace(REPORT)


if __name__ == "__main__":
    main()
