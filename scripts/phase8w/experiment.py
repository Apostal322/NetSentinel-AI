"""Phase 8w registered experiment (docs/phase8w/PREREGISTRATION.md): network-relative
representations of the 12 window features in the frozen M2 member recipe, leave-one-network-out
(one fit per target network; the six NF-CIC days share a fit).

Arms: every arm has the same 12 columns in the same order, the same rows, labels, weights, seed
and hyper-parameters. Only the value in each cell changes.
- `R0`: the raw features (matched null control; must reproduce the saved Phase 8o member);
- `S`:  signed deviation z from the network reference (the Phase 8h method, as a contrast arm);
- `A`:  unsigned deviation |z|.

References:
- source domains: label-benign calibration windows of that domain (training labels);
- target domain, chosen at scoring time, no refit (`references.target_references`):
  `Z1` unlabelled history (deployable), `Z2` simulated vetted subset, `Z3` oracle-clean,
  `T` label-benign calibration (Phase 8h-compatible), `Z0` no target statistics (the element-wise
  median of the source domains' references).

Stages: `dryrun` (no real fit), `train --seed s --arms R0,S,A`, `eval --tag T`.
Ledger: reports/phase8w/fit_ledger.json; the run refuses to exceed 48 fits or 7,200 s.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


REF = _load("phase8w_ref", "scripts/phase8w/references.py")
G = _load("phase8w_gates", "scripts/phase8w/gates.py")
RL, X, OF, S, LA = REF.RL, REF.X, REF.OF, REF.S, REF.LA
LF, C, FR, CA = X.LF, X.C, X.FR, X.CA
DER = ROOT / "data" / "derived" / "phase8w"
REP = ROOT / "reports" / "phase8w"
LEDGER = REP / "fit_ledger.json"
SAVED = ROOT / "data" / "derived" / "phase8o" / "experiment_d" / "F0" / "base"
MAX_FITS, MAX_SECONDS = 48, 7200.0
SEED0 = X.SEED0  # 1060
ARMS = {"R0": "raw", "S": "signed", "A": "abs"}
SCENARIOS = ("Z1", "Z2", "Z3", "T", "Z0")
SCENARIO_KIND = {"Z0": "zero-shot", "Z1": "unsupervised target-adaptive",
                 "Z2": "weakly supervised target-adaptive (simulated perfect review)",
                 "Z3": "oracle-assisted", "T": "oracle-assisted (label-benign calibration, Phase 8h)"}  # fmt: skip
NETS = G.NETS
FEATS = REF.FEATS


# ----------------------------------------------------------------------------- ledger
def ledger() -> dict:
    return json.loads(LEDGER.read_text("utf-8")) if LEDGER.exists() else {"fits": []}


def budget_ok(n_new: int) -> None:
    lg = ledger()
    if len(lg["fits"]) + n_new > MAX_FITS or sum(f["seconds"] for f in lg["fits"]) > MAX_SECONDS:
        sys.exit(
            f"authorisation boundary: {len(lg['fits'])} fits used, {n_new} more requested (max {MAX_FITS})"
        )


def record_fit(entry: dict) -> None:
    lg = ledger()
    lg["fits"].append(entry)
    lg["total_fits"] = len(lg["fits"])
    lg["total_seconds"] = round(sum(f["seconds"] for f in lg["fits"]), 1)
    REP.mkdir(parents=True, exist_ok=True)
    tmp = LEDGER.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(lg, indent=1).encode())
    os.replace(tmp, LEDGER)


def git_state() -> tuple[str, bool]:
    """HEAD and whether any tracked or untracked file other than the fit ledger differs from it."""

    def run(*a: str) -> str:
        return subprocess.run(["git", *a], capture_output=True, text=True, cwd=ROOT).stdout

    own = LEDGER.relative_to(ROOT).as_posix()
    dirty = [ln for ln in run("status", "--porcelain").splitlines() if ln[3:].strip('"') != own]
    return run("rev-parse", "HEAD").strip(), bool(dirty)


# ----------------------------------------------------------------------------- data
def rows(d: dict, seed: int) -> dict:
    """The frozen training rows of a source domain after the CAP subsample, checked row for row
    against `fragility.train_rows`."""
    ev = d["ev"].filter(~pl.col("noisy"))
    cal = d["cal"]
    x = np.vstack([S._x(cal), S._x(ev)])
    y = np.concatenate([np.zeros(cal.height), ev["y"].to_numpy()]).astype(int)
    key = np.concatenate([cal["key"].to_numpy(), ev["key"].to_numpy()]).astype(str)
    idx = X.subsample_idx(y, seed)
    x0, y0, k0 = FR.train_rows(d, seed)
    if not (
        np.array_equal(x[idx], x0) and np.array_equal(y[idx], y0) and np.array_equal(key[idx], k0)
    ):
        raise RuntimeError(f"{d['name']}: training rows differ from the frozen recipe")
    return {"x": x[idx], "y": y[idx]}


def source_reference(d: dict):
    ref = RL.fit_reference(S._x(d["cal"]), FEATS, "label_benign_training", REF.interval(d["cal"]))
    if ref.status != "ok":
        raise RuntimeError(f"{d['name']}: source reference {ref.status} ({ref.n} windows)")
    return ref


def transform(x: np.ndarray, ref, arm: str) -> np.ndarray:
    """The arm's 12 columns. `R0` returns the raw matrix untouched and needs no reference."""
    if ARMS[arm] == "raw":
        return x
    return RL.represent(RL.zscore(x, ref), ARMS[arm])


def zero_shot_reference(src_refs: dict):
    """Z0: no target statistics. The element-wise median of the source domains' references."""
    loc = np.median([r.location for r in src_refs.values()], axis=0)
    sc = np.median([r.scale for r in src_refs.values()], axis=0)
    return RL.Reference(names=FEATS, population="source_pooled_training", status="ok", location=loc,
                        n=int(sum(r.n for r in src_refs.values())), scale=sc,
                        note="median of the source domains' references; no target data")  # fmt: skip


def training_set(srcs: dict, seed: int) -> dict:
    """Raw rows, labels, weights and source references of one fit (shared by every arm)."""
    names = list(srcs)
    dw = C.network_weights([srcs[n]["network"] for n in names])
    xs, ys, ws, refs = [], [], [], {}
    for n, w_dom in zip(names, dw, strict=True):
        r = rows(srcs[n], seed)
        y = r["y"]
        xs.append(r["x"])
        ys.append(y)
        ws.append(w_dom * np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
        refs[n] = source_reference(srcs[n])
    y, w = np.concatenate(ys), np.concatenate(ws)
    return {"names": names, "x": xs, "y": y, "w": w * len(y) / w.sum(), "refs": refs}


def arm_matrix(ts: dict, arm: str) -> np.ndarray:
    return np.vstack([transform(x, ts["refs"][n], arm) for n, x in zip(ts["names"], ts["x"], strict=True)])  # fmt: skip


def fit_arm(ts: dict, seed: int, arm: str):
    import lightgbm as lgb

    return lgb.LGBMClassifier(random_state=seed, **C.LGB).fit(
        arm_matrix(ts, arm), ts["y"], sample_weight=ts["w"]
    )


def target_frames(items: list, src_refs: dict) -> dict:
    """Per target domain: the raw hold-out and evaluation matrices and every scenario's reference."""
    out = {}
    for name, d, _ in items:
        p = REF.calibration_parts(d, name)
        refs = REF.target_references(d, name, p)
        refs.pop("Z3h", None)
        refs["Z0"] = zero_shot_reference(src_refs)
        out[name] = {"xh": S._x(p["cu"].filter(pl.Series(p["hold"]))), "xe": S._x(p["eu"]), "refs": refs}  # fmt: skip
    return out


def score_targets(model, frames: dict, arm: str) -> dict:
    out = {}
    for name, f in frames.items():
        s = {}
        for sc in ("NA",) if arm == "R0" else SCENARIOS:
            ref = None if arm == "R0" else f["refs"][sc]
            if ref is not None and ref.status != "ok":
                continue  # recorded in the manifest; never substituted
            s[f"s_hold_{sc}"] = model.predict(transform(f["xh"], ref, arm), raw_score=True)
            s[f"s_ev_{sc}"] = model.predict(transform(f["xe"], ref, arm), raw_score=True)
        out[name] = s
    return out


def saved_member(name: str, seed: int) -> tuple[np.ndarray, np.ndarray]:
    z = np.load(SAVED / f"{name.replace('/', '__')}__r6.npz")
    return z["s_hold_u"][seed - SEED0], z["s_ev_u"][seed - SEED0]


def _sig(v: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-v))


# ----------------------------------------------------------------------------- stages
def stage_dryrun(seed: int, targets: list[str]) -> None:
    """No real model is fitted. Builds every arm's training matrix and every scenario's target
    representation, checks them, and times one fit on a random matrix of the real shape."""
    import lightgbm as lgb

    from netsentinel.resources import peak_rss_mb

    _, groups = X.load_groups()
    rep = {"seed": seed, "folds": {}}
    for tnet in targets:
        items = groups[tnet]
        t0 = time.perf_counter()
        ts = training_set(items[0][2], seed)
        mats = {a: arm_matrix(ts, a) for a in ARMS}
        frames = target_frames(items, ts["refs"])
        build = time.perf_counter() - t0
        shape = mats["R0"].shape
        ok = all(m.shape == shape and np.isfinite(m).all() for m in mats.values())
        tgt = {}
        for name, f in frames.items():
            st = {sc: r.status for sc, r in f["refs"].items()}
            fin = all(np.isfinite(transform(f[k], r, a)).all() for a in ("S", "A") for k in ("xh", "xe")
                      for r in f["refs"].values() if r.status == "ok")  # fmt: skip
            tgt[name] = {"holdout_windows": int(f["xh"].shape[0]), "evaluation_windows": int(f["xe"].shape[0]),
                         "reference_status": st, "reference_n": {sc: r.n for sc, r in f["refs"].items()},
                         "finite": bool(fin)}  # fmt: skip
        rep["folds"][tnet] = {"train_rows": int(shape[0]), "columns": int(shape[1]), "positives": int(ts["y"].sum()),
                              "source_domains": len(ts["names"]), "arms_same_shape_and_finite": bool(ok),
                              "abs_equals_abs_of_signed": bool(np.array_equal(mats["A"], np.abs(mats["S"]))),
                              "build_seconds": round(build, 2), "targets": tgt}  # fmt: skip
        print(tnet, shape, round(build, 1), "s", flush=True)
    rng = np.random.default_rng(0)
    lgb.LGBMClassifier(random_state=0, **C.LGB).fit(
        rng.normal(size=(500, 12)), rng.integers(0, 2, 500)
    )
    n = max(f["train_rows"] for f in rep["folds"].values())
    xs, ysyn = rng.normal(size=(n, 12)), rng.integers(0, 2, n)
    t0 = time.perf_counter()
    lgb.LGBMClassifier(random_state=0, **C.LGB).fit(xs, ysyn)
    rep["synthetic_fit"] = {"rows": int(n), "seconds": round(time.perf_counter() - t0, 2),
                            "note": "random features and labels of the largest fold's shape; timing only"}  # fmt: skip
    rep["peak_rss_mb"] = peak_rss_mb()
    REP.mkdir(parents=True, exist_ok=True)
    (REP / "dry_run.json").write_bytes(json.dumps(rep, indent=1).encode())
    print(json.dumps(rep["synthetic_fit"]), rep["peak_rss_mb"], flush=True)


def stage_train(seed: int, arms: list[str], targets: list[str]) -> None:
    from netsentinel.resources import peak_rss_mb

    budget_ok(len(arms) * len(targets))
    sha, dirty = git_state()
    if dirty:
        sys.exit("refusing to train on a dirty tree (registered fits must record a clean commit)")
    _, groups = X.load_groups()
    for tnet in targets:
        items = groups[tnet]
        ts = training_set(items[0][2], seed)
        frames = target_frames(items, ts["refs"])
        for arm in arms:
            outs = [
                DER / "scores" / arm / f"{n.replace('/', '__')}__s{seed}.npz" for n, _, _ in items
            ]
            if any(o.exists() for o in outs):
                sys.exit(f"{arm} {tnet} seed {seed}: scores exist; completed results are never overwritten")  # fmt: skip
            budget_ok(1)
            if git_state() != (sha, False):
                sys.exit("the tree changed during the run; stopping before the next fit")
            t0 = time.perf_counter()
            model = fit_arm(ts, seed, arm)
            sec = time.perf_counter() - t0
            txt = model.booster_.model_to_string()
            msha = hashlib.sha256(txt.encode()).hexdigest()
            mp = DER / "models" / f"{arm}__{tnet}__s{seed}.txt"
            mp.parent.mkdir(parents=True, exist_ok=True)
            mp.write_bytes(txt.encode("utf-8"))  # bytes: text mode writes CRLF (Phase 8v V-1)
            sc = score_targets(model, frames, arm)
            null_diff = None
            if arm == "R0":  # the null control against the saved frozen member
                null_diff = {n: float(max(np.abs(_sig(v["s_hold_NA"]) - saved_member(n, seed)[0]).max(),
                                          np.abs(_sig(v["s_ev_NA"]) - saved_member(n, seed)[1]).max()))
                             for n, v in sc.items()}  # fmt: skip
            for o, s in zip(outs, sc.values(), strict=True):
                o.parent.mkdir(parents=True, exist_ok=True)
                CA.save_atomic(o, **s)
            manifest = {"arm": arm, "representation": ARMS[arm], "target": tnet, "seed": seed, "git_sha": sha,
                        "schema": RL.SCHEMA_VERSION, "columns": FEATS, "lgb_params": dict(C.LGB),
                        "train_rows": int(ts["y"].size), "source_domains": ts["names"],
                        "source_references": {n: {"n": r.n, "floored": [f for f, b in zip(FEATS, r.floored, strict=True) if b]}
                                              for n, r in ts["refs"].items()},
                        "target_references": {n: {k: r.to_json() for k, r in f["refs"].items()} for n, f in frames.items()},
                        "model_sha256": msha, "fit_seconds": round(sec, 2),
                        "null_vs_saved_member_max_abs_diff": null_diff,
                        "score_sha256": {n: {k: hashlib.sha256(a.tobytes()).hexdigest() for k, a in v.items()}
                                         for n, v in sc.items()}}  # fmt: skip
            mf = DER / "manifests" / f"{arm}__{tnet}__s{seed}.json"
            mf.parent.mkdir(parents=True, exist_ok=True)
            mf.write_bytes(json.dumps(manifest, indent=1).encode())
            record_fit({"arm": arm, "target": tnet, "seed": seed, "seconds": round(sec, 2), "model_sha256": msha,
                        "git_sha": sha, "dirty_tree": False, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "peak_rss_mb": peak_rss_mb(),
                        "null_vs_saved_member_max_abs_diff": None if null_diff is None else max(null_diff.values())})  # fmt: skip
            print(arm, tnet, seed, round(sec, 1), "s", flush=True)


def stage_eval(tag: str) -> None:
    from sklearn.metrics import average_precision_score, roc_auc_score

    TO, FG = OF.TO, OF.FG  # noqa: N806
    names = sorted(p.stem.replace("__", "/") for p in OF.BM.AUDIT.glob("*.parquet"))
    dom = {n: OF.load(n) for n in names}
    is_att = {n: FG.domain_data(n)["is_att"] for n in names}

    def metrics(name: str, sh: np.ndarray, se: np.ndarray) -> dict:
        d = dom[name]
        pos, neg = d["pos"], d["neg"]
        ben_h = ~is_att[name]
        if sh.size != ben_h.size or se.size != pos.size:
            raise RuntimeError(f"{name}: score and population sizes differ")
        yv = np.r_[np.ones(pos.sum()), np.zeros(neg.sum())]
        sv = np.r_[se[pos], se[neg]]
        t_or = TO.global_threshold(se[neg], int(math.floor(0.01 * neg.sum())))
        t_cal = float(np.sort(sh[ben_h])[min(ben_h.sum(), math.ceil((ben_h.sum() + 1) * 0.99)) - 1])
        return {"roc_auc": float(roc_auc_score(yv, sv)), "pr_auc": float(average_precision_score(yv, sv)),
                "pauc_1pct": LF.partial_auc_exact(se[pos], se[neg]),  # exact step ROC (Phase 8u U-1)
                "oracle_1pct": OF.metrics(d, se, se > t_or), "cal_T": OF.metrics(d, se, se > t_cal)}  # fmt: skip

    def scores_of(arm: str, seed: int, sc: str, name: str):
        p = DER / "scores" / arm / f"{name.replace('/', '__')}__s{seed}.npz"
        if not p.exists():
            return None
        z = np.load(p)
        k = "NA" if arm == "R0" else sc
        return (z[f"s_hold_{k}"], z[f"s_ev_{k}"]) if f"s_ev_{k}" in z.files else None

    seeds = sorted({int(f.stem.split("__s")[-1]) for a in ARMS for f in (DER / "scores" / a).glob("*.npz")})  # fmt: skip
    per, cache = {sc: {} for sc in SCENARIOS}, {}
    for sc in SCENARIOS:
        for arm in ARMS:
            for s in seeds:
                key = (arm, s) if arm == "R0" else (arm, s, sc)
                if key not in cache:
                    got = {n: scores_of(arm, s, sc, n) for n in names}
                    cache[key] = None if any(v is None for v in got.values()) else {n: metrics(n, *v) for n, v in got.items()}  # fmt: skip
                if cache[key] is not None:
                    per[sc].setdefault(arm, {})[str(s)] = cache[key]
        print("eval", sc, {a: sorted(v) for a, v in per[sc].items()}, flush=True)
    saved = {str(s): {n: metrics(n, *saved_member(n, s)) for n in names} for s in G.ALL_SEEDS}
    summary = {sc: {a: {s: X.aggregate(v) for s, v in d.items()} for a, d in arms.items()} for sc, arms in per.items()}  # fmt: skip
    saved_summary = {s: X.aggregate(v) for s, v in saved.items()}
    null_check = {s: {"macro_pauc_refit": summary["Z1"]["R0"][s]["macro_pauc_1pct"],
                      "macro_pauc_saved": saved_summary[s]["macro_pauc_1pct"],
                      "max_abs_pauc_diff_by_domain": float(max(abs(per["Z1"]["R0"][s][n]["pauc_1pct"] - saved[s][n]["pauc_1pct"])
                                                               for n in names))}
                  for s in summary["Z1"].get("R0", {})}  # fmt: skip
    ens = {}
    for sc in SCENARIOS:  # exploratory: mean of member probabilities, five seeds only
        for arm in ARMS:
            got = {n: [scores_of(arm, s, sc, n) for s in G.ALL_SEEDS] for n in names}
            if all(v is not None for vs in got.values() for v in vs):
                ens.setdefault(sc, {})[arm] = X.aggregate({n: metrics(n, np.mean([_sig(v[0]) for v in vs], axis=0),
                                                                      np.mean([_sig(v[1]) for v in vs], axis=0))
                                                           for n, vs in got.items()})  # fmt: skip
    m2 = X.aggregate({n: metrics(n, *(np.mean([saved_member(n, s)[i] for s in G.ALL_SEEDS], axis=0) for i in (0, 1)))
                      for n in names})  # fmt: skip
    sha, dirty = git_state()
    res = {"status": "Phase 8w evaluation (development data; consumed networks; exact partial AUC). "
                     "One block per reference scenario; scenarios are never pooled.",
           "git_sha": sha, "dirty_tree": dirty, "scenario_kind": SCENARIO_KIND, "summary": summary,
           "saved_member": saved_summary, "null_control_vs_saved_member": null_check,
           "decisions": G.decide(summary), "ensemble_exploratory": ens, "frozen_m2_ensemble": m2,
           "per_domain": per}  # fmt: skip
    body = json.dumps(res, indent=1, default=float).encode()
    p = REP / f"evaluation{tag}.json"
    if p.exists():
        raise FileExistsError(p)
    tmp = p.with_suffix(".partial")
    tmp.write_bytes(body)
    os.replace(tmp, p)
    (REP / f"evaluation{tag}.sha256").write_text(hashlib.sha256(body).hexdigest())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("dryrun", "train", "eval"))
    ap.add_argument("--seed", type=int, default=SEED0)
    ap.add_argument("--arms", default="R0,S,A")
    ap.add_argument("--targets", default=",".join(NETS))
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    arms = a.arms.split(",")
    if any(x not in ARMS for x in arms) or a.seed not in G.ALL_SEEDS:
        sys.exit("unregistered arm or seed")
    if a.stage == "dryrun":
        stage_dryrun(a.seed, a.targets.split(","))
    elif a.stage == "train":
        stage_train(a.seed, arms, a.targets.split(","))
    else:
        stage_eval(a.tag)


if __name__ == "__main__":
    main()
