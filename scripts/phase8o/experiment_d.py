"""Phase 8o Experiment D: train the registered arms (docs/phase8o/PREREGISTRATION.md).
REGISTERED DEVELOPMENT.

Every fit is the Phase 8n M2 construction:
- 5 members, member m of replicate r with LightGBM seed and subsample seed 1000 + 10r + m;
- `candidates.source_data` and `candidates.fit_one` unchanged.

The scores of EACH member are stored, so K-member ensembles (nested prefixes) can be formed
afterwards without refitting. Arms change only the source training rows (F1, F2, F5), or one
column of every matrix (F4):

- F0  historical.
- F1  calibration rows from the last 30 % of source calibration slots take `new_dst_frac` from a
      memory frozen at that slot boundary (build_aligned.py `f1_clean`).
- F2  source evaluation rows take the Phase 8m causal expanding value (`nov_unconditional`).
- F4  `new_dst_frac` squared in training and target matrices (matched-information control).
- F5  source domains with fewer than 1,000 calibration windows are dropped.

For F0 the members also score:
- the C1 hold-out (`new_dst_frac` from the P1x memory frozen at the hold-out start);
- the unlabelled calibration hold-out and evaluation windows (C3).

Reproduction checks, run first; the run stops on any difference:
- R1: the F0 base r0 mean equals the Phase 8n M2 base r0 scores;
- R2: one M0 fit (seeds 0, 0) equals the Phase 8n P_ref r0 scores.

Output: data/derived/phase8o/experiment_d/<arm>/<regime>/<domain>__r<k>.npz
        reports/phase8o/experiment_d_runs.json (resumable; existing outputs are kept)
Usage: python scripts/run_capped.py -- <python> scripts/phase8o/experiment_d.py
       [--arms F0,F1] [--regimes base] [--reps 6] [--checks-only]
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

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = ROOT / "data" / "derived" / "phase8o" / "experiment_d"
ALIGNED = ROOT / "data" / "derived" / "phase8o" / "aligned"
NOV = ROOT / "data" / "derived" / "phase8m" / "novelty"
REPORT = ROOT / "reports" / "phase8o" / "experiment_d_runs.json"
MEMBERS = 5
REPS = (6, 7, 8)
ARMS = {"F0": ("base", "stress"), "F1": ("base", "stress"), "F4": ("base", "stress"),
        "F2": ("base",), "F5": ("base",)}  # fmt: skip
MIN_CAL_WINDOWS = 1000  # F5
WINDOW_MS = 30_000  # Phase 8b harness.W
NDF = "new_dst_frac"


def member_seed(r: int, m: int) -> int:
    return 1000 + 10 * r + m


def replace_column(frame: pl.DataFrame, values: pl.DataFrame, col: str,
                   required: pl.Expr | None = None) -> pl.DataFrame:  # fmt: skip
    """`frame` with `new_dst_frac` taken from `values[col]` on matching (key, win), in the same
    row order. Rows matched by `required` must all have a value."""
    j = frame.join(values, on=["key", "win"], how="left", maintain_order="left")
    if (
        j.height != frame.height
        or not j["key"].equals(frame["key"])
        or not j["win"].equals(frame["win"])
    ):
        raise RuntimeError("join changed the rows")
    if required is not None:
        miss = int(j.filter(required)[col].null_count())
        if miss:
            raise RuntimeError(f"{miss} required rows have no {col}")
    return j.with_columns(pl.coalesce(col, NDF).alias(NDF)).drop(col)


def arm_sources(arm: str, srcs: dict) -> dict:
    """The source domains of one arm (new dicts; the loaded data are not modified)."""
    if arm == "F0":
        return srcs
    out = {}
    for name, d in srcs.items():
        if arm == "F5" and d["cal"].height < MIN_CAL_WINDOWS:
            continue
        d2 = dict(d)
        if arm == "F1":
            f1 = pl.read_parquet(ALIGNED / d["network"] / d["name"] / "f1_clean.parquet")
            q = int(
                json.loads((ALIGNED / d["network"] / d["name"] / "meta.json").read_text("utf-8"))[
                    "q_src_ms"
                ]
            )
            d2["cal"] = replace_column(d["cal"], f1, "new_dst_frac_f1",
                                       required=pl.col("win") >= q // WINDOW_MS)  # fmt: skip
        elif arm == "F2":
            nov = pl.read_parquet(NOV / d["network"] / d["name"] / "clean.parquet",
                                  columns=["key", "win", "nov_unconditional"])  # fmt: skip
            d2["ev"] = replace_column(d["ev"], nov, "nov_unconditional", required=pl.lit(True))
        elif arm == "F4":
            d2["cal"] = d["cal"].with_columns(pl.col(NDF) ** 2)
            d2["ev"] = d["ev"].with_columns(pl.col(NDF) ** 2)
        out[name] = d2
    return out


def target_matrices(arm: str, name: str, d: dict, frames: dict,
                    extras: bool = True) -> dict[str, np.ndarray]:  # fmt: skip
    """hold / ev matrices of a target domain; for F0 (with `extras`) also the C1 hold-out and
    the unlabelled (C3) hold-out and evaluation windows."""
    cal, ev = frames[name]
    hold = (cal["win"] >= S.split_cut(cal)).to_numpy()
    ch = cal.filter(pl.Series(hold))
    if arm == "F4":
        ch, ev = ch.with_columns(pl.col(NDF) ** 2), ev.with_columns(pl.col(NDF) ** 2)
    mats = {"hold": S._x(ch), "ev": S._x(ev)}
    if arm == "F0" and extras:
        c1 = pl.read_parquet(ALIGNED / d["network"] / d["name"] / "c1_p1x.parquet")
        mats["hold_c1"] = S._x(replace_column(ch, c1, "new_dst_frac_c1", required=pl.lit(True)))
        cu, eu = LA.unlabelled(d)
        hu = (cu["win"] >= S.split_cut(cu)).to_numpy()
        mats["hold_u"], mats["ev_u"] = S._x(cu.filter(pl.Series(hu))), S._x(eu)
    return mats


def fit_members(srcs: dict, regime: str, r: int) -> list:
    outer = r if regime == "stress" else None
    return [CA.fit_one(CA.source_data(srcs, member_seed(r, m), outer), member_seed(r, m))
            for m in range(MEMBERS)]  # fmt: skip


def member_scores(members: list, x: np.ndarray) -> np.ndarray:
    return np.vstack([m.predict_proba(x)[:, 1] for m in members])


def groups(todo: list) -> dict[tuple, list]:
    g: dict[tuple, list] = {}
    for name, d, srcs in todo:
        g.setdefault(tuple(sorted(srcs)), []).append((name, d, srcs))
    return g


def checks(todo: list, frames: dict) -> dict:
    """R1 and R2 (PREREGISTRATION section 2): max |difference| per target domain."""
    res = {}
    for items in groups(todo).values():
        srcs = items[0][2]
        m2 = fit_members(srcs, "base", 0)
        m0 = [CA.fit_one(CA.source_data(srcs, 0, None), 0)]
        for name, d, _ in items:
            mats = target_matrices("F0", name, d, frames, extras=False)
            f = f"{name.replace('/', '__')}__r0.npz"
            ref2 = np.load(CA.OUT / "M2" / "base" / f)
            ref0 = np.load(CA.FRAG / "P_ref" / f)
            r1 = max(float(np.abs(member_scores(m2, mats[k]).mean(0) - ref2[f"s_{k}"]).max())
                     for k in ("hold", "ev"))  # fmt: skip
            r2 = max(float(np.abs(member_scores(m0, mats[k])[0] - ref0[f"s_{k}"]).max())
                     for k in ("hold", "ev"))  # fmt: skip
            res[name] = {"R1_m2_r0_max_abs_diff": r1, "R2_m0_r0_max_abs_diff": r2}
            print("check", name, res[name], flush=True)
    return res


def provenance(args) -> dict:
    import lightgbm

    sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                         cwd=ROOT).stdout.strip()  # fmt: skip
    code = {p: hashlib.sha256((ROOT / p).read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:16]
            for p in ("scripts/phase8o/experiment_d.py", "scripts/phase8n/candidates.py",
                      "scripts/phase8n/fragility.py", "scripts/phase8i/common.py")}  # fmt: skip
    return {"git_head": sha, "code_sha256_16": code, "lightgbm": lightgbm.__version__,
            "numpy": np.__version__, "polars": pl.__version__, "args": vars(args),
            "lgb_params": C.LGB, "members": MEMBERS}  # fmt: skip


def save_log(log: dict) -> None:
    log["peak_rss_mb"] = peak_rss_mb()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    tmp = REPORT.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(log, indent=1).encode())
    tmp.replace(REPORT)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--regimes", default="base,stress")
    ap.add_argument("--reps", default=",".join(map(str, REPS)))
    ap.add_argument("--checks-only", action="store_true")
    a = ap.parse_args()
    t_start = time.perf_counter()
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    todo = LA.targets(nets)
    frames = {name: DS.p1x_frames(d) for name, d, _ in todo}
    log = json.loads(REPORT.read_text("utf-8")) if REPORT.exists() else {"runs": {}}
    log.setdefault("provenance", []).append(provenance(a))
    if "checks" not in log:
        log["checks"] = checks(todo, frames)
        save_log(log)
    bad = {n: v for n, v in log["checks"].items() if max(v.values()) > 0}
    if bad:
        sys.exit(f"reproduction check failed (R1/R2): {bad}")
    if a.checks_only:
        return
    for arm in a.arms.split(","):
        for regime in [g for g in a.regimes.split(",") if g in ARMS[arm]]:
            for r in [int(x) for x in a.reps.split(",")]:
                for items in groups(todo).values():
                    outs = [
                        OUT / arm / regime / f"{n.replace('/', '__')}__r{r}.npz"
                        for n, _, _ in items
                    ]
                    if all(o.exists() for o in outs):
                        continue
                    t0 = time.perf_counter()
                    srcs = arm_sources(arm, items[0][2])
                    members = fit_members(srcs, regime, r)
                    fit_s = round(time.perf_counter() - t0, 1)
                    for (name, d, _), out in zip(items, outs, strict=True):
                        mats = target_matrices(arm, name, d, frames)
                        out.parent.mkdir(parents=True, exist_ok=True)
                        CA.save_atomic(out, **{f"s_{k}": member_scores(members, x)
                                               for k, x in mats.items()})  # fmt: skip
                        row = {"members": len(members), "fit_seconds": fit_s,
                               "sources": len(srcs)}  # fmt: skip
                        log["runs"].setdefault(f"{arm}/{regime}", {})[f"{name} r{r}"] = row
                        print(arm, regime, name, r, row, flush=True)
                    del members, srcs
                    log["seconds_last_call"] = round(time.perf_counter() - t_start, 1)
                    save_log(log)


if __name__ == "__main__":
    main()
