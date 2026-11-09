"""Phase 8v registered experiment (docs/phase8v/PREREGISTRATION.md): enriched flow-window
representations in the frozen M2 member recipe, leave-one-network-out (one fit per target
network; the six NF-CIC days share a fit), exactly as Phase 8u's A0.

Variants add columns to the 12 original features and change nothing else:
- `FLOW`, `TIME`, `BIDIR`: the registered feature families (`REGISTERED`);
- `INV`: the 12 original features plus all three families, minus every column whose univariate
  direction conflicts between source networks (`selection.invariant_columns`; training rows only);
- `ALL`: the three together (not planned in this budget);
- `PERM:<family>`: the family's columns permuted across windows within each domain, in training
  and in the target (shortcut control: keeps every domain's marginal distribution and destroys
  the relation between the feature and the window).

The baseline is the saved Phase 8o F0 base r6 member with the same seed (Phase 8u gate R0 showed
the refit reproduces it exactly). `rows()` re-checks that the original 12-feature training
matrix is unchanged, row for row.

Stages: `train --variant V --seed s`, `eval --tag T`.
Ledger: reports/phase8v/fit_ledger.json; the run refuses to exceed 24 fits or 7,200 s.
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


X = _load("phase8u_x", "scripts/phase8u/experiment.py")
FF = _load("phase8v_ff", "scripts/phase8v/flow_features.py")
SEL = _load("phase8v_sel", "scripts/phase8v/selection.py")
LF, C, S, LA, FR, CA = X.LF, X.C, X.S, X.LA, X.FR, X.CA
ENR = ROOT / "data" / "derived" / "phase8v" / "enriched"
DER = ROOT / "data" / "derived" / "phase8v"
REP = ROOT / "reports" / "phase8v"
LEDGER = REP / "fit_ledger.json"
MAX_FITS, MAX_SECONDS = 24, 7200.0
SEED0 = X.SEED0  # 1060
# registered families: the audit removed retrans_frac and mean_log_fwd_iat (TELEMETRY_AUDIT § 4)
REGISTERED = {
    "FLOW": ("tiny_flow_frac", "mean_log_pkts", "sd_log_up", "p90_log_dur", "small_pkt_share"),
    "TIME": ("active_sec_frac", "peak_sec_share", "gap_cv", "long_flow_frac", "prev4_mean_log_flows",
             "d_log_flows", "active_prev4"),
    "BIDIR": ("syn_only_frac", "srv_rst_frac", "cli_fin_frac", "mean_log_ratio"),
}  # fmt: skip
REGISTERED["ALL"] = tuple(f for k in ("FLOW", "TIME", "BIDIR") for f in REGISTERED[k])
REGISTERED["INV"] = REGISTERED["ALL"]
NETS = SEL.NETS


def columns_of(variant: str) -> tuple[tuple[str, ...], bool]:
    perm = variant.startswith("PERM:")
    return REGISTERED[variant.split(":")[-1]], perm


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
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()
    )
    return sha, dirty


# ----------------------------------------------------------------------------- data
def enriched(
    network: str, dom: str, key: np.ndarray, win: np.ndarray, cols: tuple[str, ...]
) -> np.ndarray:
    """Enriched columns for the given (key, win) rows, in row order. NaN = missing (kept)."""
    e = pl.read_parquet(ENR / network / f"{dom}.parquet", columns=["key", "win", *cols])
    q = pl.DataFrame({"key": key.astype(str), "win": win.astype(np.int64)})
    j = q.join(e, on=["key", "win"], how="left", maintain_order="left")
    if j.height != q.height:
        raise RuntimeError(f"{network}/{dom}: join changed the rows")
    present = q.join(
        e.select("key", "win", pl.lit(True).alias("_p")),
        on=["key", "win"],
        how="left",
        maintain_order="left",
    )
    if present["_p"].null_count():
        raise RuntimeError(
            f"{network}/{dom}: {present['_p'].null_count()} windows have no enriched features"
        )
    return j.select([pl.col(c).cast(pl.Float64) for c in cols]).to_numpy()


def rows(d: dict, seed: int) -> dict:
    """The Phase 8h training rows of a source domain after the CAP subsample, with identities."""
    ev = d["ev"].filter(~pl.col("noisy"))
    cal = d["cal"]
    x = np.vstack([S._x(cal), S._x(ev)])
    y = np.concatenate([np.zeros(cal.height), ev["y"].to_numpy()]).astype(int)
    key = np.concatenate([cal["key"].to_numpy(), ev["key"].to_numpy()]).astype(str)
    win = np.concatenate([cal["win"].to_numpy(), ev["win"].to_numpy()]).astype(np.int64)
    idx = X.subsample_idx(y, seed)
    x0, y0, k0 = FR.train_rows(d, seed)
    if not (
        np.array_equal(x[idx], x0) and np.array_equal(y[idx], y0) and np.array_equal(key[idx], k0)
    ):
        raise RuntimeError(f"{d['name']}: training rows differ from the frozen recipe")
    return {"x": x[idx], "y": y[idx], "key": key[idx], "win": win[idx]}


def fit_variant(srcs: dict, seed: int, variant: str):
    import lightgbm as lgb

    cols, perm = columns_of(variant)
    names = list(srcs)
    dw = C.network_weights([srcs[n]["network"] for n in names])
    xs, ys, ws, nets = [], [], [], []
    for n, w_dom in zip(names, dw, strict=True):
        d = srcs[n]
        r = rows(d, seed)
        e = enriched(d["network"], d["name"], r["key"], r["win"], cols)
        if perm:
            e = SEL.permute_columns(e, f"train|{n}|{seed}")
        y = r["y"]
        xs.append(np.hstack([r["x"], e]))
        ys.append(y)
        ws.append(w_dom * np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
        nets.append(np.full(y.size, d["network"]))
    x, y, w = np.vstack(xs), np.concatenate(ys), np.concatenate(ws)
    keep, table = np.ones(x.shape[1], bool), None
    if variant == "INV":
        keep, table = SEL.invariant_columns(x, y, np.concatenate(nets))
    model = lgb.LGBMClassifier(random_state=seed, **C.LGB).fit(
        x[:, keep], y, sample_weight=w * len(y) / w.sum()
    )
    return model, int(x.shape[0]), keep, table


def score_targets(model, items: list, variant: str, keep: np.ndarray) -> dict:
    cols, perm = columns_of(variant)
    out = {}
    for name, d, _ in items:
        cu, eu = LA.unlabelled(d)
        hold = (cu["win"] >= S.split_cut(cu)).to_numpy()
        ch = cu.filter(pl.Series(hold))
        eh = enriched(d["network"], d["name"], ch["key"].to_numpy(), ch["win"].to_numpy(), cols)
        ee = enriched(d["network"], d["name"], eu["key"].to_numpy(), eu["win"].to_numpy(), cols)
        if perm:
            eh = SEL.permute_columns(eh, f"hold|{name}")
            ee = SEL.permute_columns(ee, f"eval|{name}")
        out[name] = {"s_hold_u": model.predict(np.hstack([S._x(ch), eh])[:, keep], raw_score=True),
                     "s_ev_u": model.predict(np.hstack([S._x(eu), ee])[:, keep], raw_score=True)}  # fmt: skip
    return out


def stage_train(variant: str, seed: int, targets: list[str]) -> None:
    from netsentinel.resources import peak_rss_mb

    budget_ok(len(targets))
    sha, dirty = git_state()
    if dirty:
        sys.exit("refusing to train on a dirty tree (registered fits must record a clean commit)")
    _, groups = X.load_groups()
    safe = variant.replace(":", "_")
    for tnet in targets:
        items = groups[tnet]
        outs = [DER / "scores" / safe / f"{n.replace('/', '__')}__s{seed}.npz" for n, _, _ in items]
        if any(o.exists() for o in outs):
            sys.exit(
                f"{variant} {tnet} seed {seed}: scores exist; completed results are never overwritten"
            )
        budget_ok(1)
        t0 = time.perf_counter()
        model, n_rows, keep, table = fit_variant(items[0][2], seed, variant)
        all_cols = [*S.FEATS, *columns_of(variant)[0]]
        kept = [c for c, k in zip(all_cols, keep, strict=True) if k]
        sec = time.perf_counter() - t0
        txt = model.booster_.model_to_string()
        msha = hashlib.sha256(txt.encode()).hexdigest()
        mp = DER / "models" / f"{safe}__{tnet}__s{seed}.txt"
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(txt, encoding="utf-8")
        t1 = time.perf_counter()
        sc = score_targets(model, items, variant, keep)
        n_scored = sum(v["s_hold_u"].size + v["s_ev_u"].size for v in sc.values())
        score_s = time.perf_counter() - t1
        for o, (_name, s) in zip(outs, sc.items(), strict=True):
            o.parent.mkdir(parents=True, exist_ok=True)
            CA.save_atomic(o, **s)
        manifest = {"variant": variant, "target": tnet, "seed": seed, "git_sha": sha, "feature_schema": FF.SCHEMA_VERSION,
                    "added_columns": list(columns_of(variant)[0]), "lgb_params": dict(C.LGB), "train_rows": n_rows,
                    "train_columns": kept, "dropped_columns": [c for c in all_cols if c not in kept],
                    "source_direction_auc": None if table is None else {all_cols[j]: a for j, a in table.items()},
                    "model_sha256": msha, "fit_seconds": round(sec, 2),
                    "windows_scored": n_scored, "score_seconds_incl_feature_join": round(score_s, 2),
                    "score_sha256": {n: hashlib.sha256(v["s_ev_u"].tobytes()).hexdigest() for n, v in sc.items()}}  # fmt: skip
        mf = DER / "manifests" / f"{safe}__{tnet}__s{seed}.json"
        mf.parent.mkdir(parents=True, exist_ok=True)
        mf.write_bytes(json.dumps(manifest, indent=1).encode())
        record_fit({"variant": variant, "target": tnet, "seed": seed, "seconds": round(sec, 2), "model_sha256": msha,
                    "git_sha": sha, "dirty_tree": dirty, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "peak_rss_mb": peak_rss_mb()})  # fmt: skip
        print(variant, tnet, seed, round(sec, 1), "s", flush=True)


# ----------------------------------------------------------------------------- evaluation
def stage_eval(tag: str) -> None:
    OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")  # noqa: N806
    TO, FG = OF.TO, OF.FG
    from sklearn.metrics import average_precision_score, roc_auc_score

    names = sorted(p.stem.replace("__", "/") for p in OF.BM.AUDIT.glob("*.parquet"))
    dom = {n: OF.load(n) for n in names}
    is_att = {n: FG.domain_data(n)["is_att"] for n in names}

    def scores_of(variant: str, seed: int, name: str):
        if variant == "M2member":
            z = np.load(
                ROOT
                / "data/derived/phase8o/experiment_d/F0/base"
                / f"{name.replace('/', '__')}__r6.npz"
            )
            return z["s_hold_u"][seed - SEED0], z["s_ev_u"][seed - SEED0]
        p = DER / "scores" / variant / f"{name.replace('/', '__')}__s{seed}.npz"
        if not p.exists():
            return None
        z = np.load(p)
        return z["s_hold_u"], z["s_ev_u"]

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

    runs = {}
    combos = [("M2member", s) for s in (SEED0, SEED0 + 1, SEED0 + 2)]
    sdir = DER / "scores"
    for vdir in sorted(sdir.iterdir()) if sdir.exists() else []:
        for s in sorted({int(f.stem.split("__s")[-1]) for f in vdir.glob("*.npz")}):
            combos.append((vdir.name, s))
    for v, s in combos:
        per = {}
        for name in names:
            sc = scores_of(v, s, name)
            if sc is None:
                break
            per[name] = metrics(name, *sc)
        else:
            runs[f"{v}|{s}"] = per
            print("eval", v, s, flush=True)
    summary = {k: X.aggregate(v) for k, v in runs.items()}
    sha, dirty = git_state()
    res = {"status": "Phase 8v evaluation (development data; consumed networks; exact partial AUC)", "git_sha": sha,
           "dirty_tree": dirty, "summary": summary, "decisions": SEL.decide(summary), "per_domain": runs}  # fmt: skip
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
    ap.add_argument("stage", choices=("train", "eval"))
    ap.add_argument("--variant")
    ap.add_argument("--seed", type=int, default=SEED0)
    ap.add_argument("--targets", default=",".join(NETS))
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    if a.stage == "train":
        columns_of(a.variant)
        stage_train(a.variant, a.seed, a.targets.split(","))
    else:
        stage_eval(a.tag)


if __name__ == "__main__":
    main()
