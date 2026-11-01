"""Phase 8i Experiment A (I1): label-budget adaptation on a target network
(docs/phase8i/PREREGISTRATION.md section 4).

For each cross-network target unit and seed: the source model (B-raw, network-balanced, trained
on the OTHER networks) gives A0 (source threshold) and A1 (target T0 threshold). For each budget
Ka in {5, 25, 100} and draw 0..19, Ka labelled attack windows from the target's calibration
period plus the target benign-train windows fit A3 (logistic correction), A4 (continued boosting)
and A5 (target-only LightGBM); every method is thresholded by T0 on the same hold-out.
A single-entity variant (all Ka windows from one attacker) runs at Ka = 25.
A1 scores are also saved (npz) for the Experiment B secondary analysis.

Output: reports/phase8i/exp_a/<target>.json, reports/phase8i/exp_a/<target>__seed<k>_A1.npz
Usage: uv run python scripts/phase8i/exp_a.py [--targets nfunsw/all,...] [--seeds 0,1,2]
       [--draws 20] [--confirm]   (--confirm: target N4 = nfbot, after the freeze only)
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

BUDGETS = (5, 25, 100)
OUT = Path("reports/phase8i/exp_a")
_SRC_CACHE: dict = {}


def logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def fit_corrections(src, tgt: dict, xpos: np.ndarray, xneg: np.ndarray, seed: int) -> dict:
    """A3, A4, A5 fitted on labelled target attack windows + benign-train negatives."""
    import lightgbm as lgb
    from sklearn.linear_model import LogisticRegression

    X = np.vstack([xpos, xneg])  # noqa: N806
    y = np.concatenate([np.ones(len(xpos)), np.zeros(len(xneg))]).astype(int)
    w = np.where(y == 1, 0.5 / len(xpos), 0.5 / len(xneg)) * len(y)
    sc = tgt["_scaler"]
    s_src = src.predict_proba(X)[:, 1]

    def a3_feats(x, s):
        return np.column_stack([logit(s), C.L.clip_local(sc, x)])

    a3 = LogisticRegression(C=1.0, max_iter=2000).fit(a3_feats(X, s_src), y, sample_weight=w)
    a4 = lgb.LGBMClassifier(n_estimators=50, learning_rate=0.05, num_leaves=7, min_child_samples=5,
                            random_state=seed, n_jobs=2, verbose=-1)  # fmt: skip
    a4.fit(X, y, sample_weight=w, init_model=src.booster_)
    a5 = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.05, num_leaves=7, min_child_samples=5,
                            random_state=seed, n_jobs=2, verbose=-1).fit(X, y, sample_weight=w)  # fmt: skip
    out = {}
    n_src = src.booster_.num_trees()
    for name, part in (("ev", tgt["_xev"]), ("hold", tgt["_xhold"])):
        s = tgt[f"_src_{name}"]
        out[("A3", name)] = a3.predict_proba(a3_feats(part, s))[:, 1]
        # A4 = the source trees + 50 new trees: add the stored source margin to the new trees'
        # margin instead of re-evaluating the source trees (identical up to float rounding;
        # checked against predict_proba in tests/unit/test_phase8i_calc.py)
        new = a4.booster_.predict(part, raw_score=True, start_iteration=n_src)
        out[("A4", name)] = expit(tgt[f"_src_{name}_raw"] + new)
        out[("A5", name)] = a5.predict_proba(part)[:, 1]
    return out


def expit(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


def summarize(per: list[dict]) -> dict:
    keys = ("window_recall", "fpr", "roc_auc", "pr_auc", "oracle_recall_at_fpr1",
            "entity_recall", "false_alerts_per_h", "median_delay_s")  # fmt: skip
    out = {"n": len(per)}
    for k in keys:
        v = np.array([p[k] for p in per if p.get(k) is not None], dtype=float)
        if len(v):
            out[k] = {"median": float(np.median(v)), "p025": float(np.quantile(v, 0.025)),
                      "p975": float(np.quantile(v, 0.975)), "mean": float(v.mean())}  # fmt: skip
    return out


def run_target(name: str, tgt: dict, sources: dict, seeds: list[int], draws: int,
               correction_seeds: tuple[int, ...] = (0,)) -> dict:
    t0 = time.perf_counter()
    C.prepare(tgt)
    btrain, hold = tgt["_btrain"], tgt["_hold"]
    tgt["_scaler"] = C.S.local_scaler(btrain)
    tgt["_xev"], tgt["_xhold"] = C.S._x(tgt["ev"]), C.S._x(hold)
    xneg_all = C.S._x(btrain)
    pool = tgt["pool"]
    xpool = C.S._x(pool) if pool.height else np.zeros((0, len(C.FEATS)))
    pkeys = pool["key"].to_numpy() if pool.height else np.array([], dtype=object)
    pslots = pool["win"].to_numpy() if pool.height else np.array([], dtype=int)
    res = {"target": name, "eval_windows": tgt["ev"].height,
           "attack_windows": int(tgt["ev"]["y"].sum()), "benign_windows": int(tgt["ev"]["benign"].sum()),
           "attackers": sorted(tgt["attackers"]), "eval_hours": tgt["hours"],
           "n_btrain": btrain.height, "n_hold": hold.height, "pool_windows": pool.height,
           "pool_entities": int(len(np.unique(pkeys))), "sources": sorted(sources),
           "seeds": {}}  # fmt: skip
    for seed in seeds:
        key = (tuple(sorted(sources)), seed)  # same sources and seed -> same model: fit once
        if key not in _SRC_CACHE:
            _SRC_CACHE[key] = C.fit_source(sources, seed, C.Rep("raw"))
        src, src_thr, n_train = _SRC_CACHE[key]
        for part in ("ev", "hold"):
            tgt[f"_src_{part}_raw"] = src.booster_.predict(tgt[f"_x{part}"], raw_score=True)
            tgt[f"_src_{part}"] = expit(tgt[f"_src_{part}_raw"])
        thr1, rel1 = C.t0(tgt["_src_hold"])
        sr = {"train_rows": n_train, "source_threshold": src_thr, "T0": thr1, "T0_reliable": rel1,
              "A0": C.evaluate(tgt, tgt["_src_ev"], src_thr),
              "A1": C.evaluate(tgt, tgt["_src_ev"], thr1), "budgets": {}}  # fmt: skip
        OUT.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(OUT / f"{name.replace('/', '__')}__seed{seed}_A1.npz",
                            s_ev=tgt["_src_ev"], s_hold=tgt["_src_hold"])  # fmt: skip
        rng = np.random.default_rng(seed)
        neg_idx = (np.sort(rng.choice(len(xneg_all), C.NEG_CAP, replace=False))
                   if len(xneg_all) > C.NEG_CAP else np.arange(len(xneg_all)))  # fmt: skip
        xneg = xneg_all[neg_idx]
        variants = [(ka, False) for ka in BUDGETS] + [(25, True)]
        if seed not in correction_seeds:  # amendment A3: A3-A5 for seed 0 only
            variants = []
        for ka, single in variants:
            per = {"A3": [], "A4": [], "A5": []}
            info = []
            for r in range(draws):
                idx = C.draw_pool(pkeys, ka, r, single)
                if len(idx) == 0:
                    break
                sc = fit_corrections(src, tgt, xpool[idx], xneg, seed)
                for m in per:
                    thr, _ = C.t0(sc[(m, "hold")])
                    e = C.evaluate(tgt, sc[(m, "ev")], thr)
                    per[m].append(e)
                info.append({"windows": len(idx), "entities": int(len(np.unique(pkeys[idx]))),
                             "slots": int(len(np.unique(pslots[idx])))})  # fmt: skip
            key = f"Ka{ka}" + ("_single" if single else "")
            sr["budgets"][key] = {"draw_info": info,
                                  "pool_short": bool(info and info[0]["windows"] < ka),
                                  **{m: {"summary": summarize(v), "per_draw": v}
                                     for m, v in per.items()}}  # fmt: skip
            print(name, seed, key, {m: sr["budgets"][key][m]["summary"].get("window_recall", {})
                                    .get("median") for m in per}, flush=True)  # fmt: skip
        res["seeds"][seed] = sr
    res["seconds"] = time.perf_counter() - t0
    res["peak_rss_mb"] = peak_rss_mb()
    return res


def folds(confirm: bool) -> list[tuple[str, dict, dict]]:
    """(target name, target domain, sources) for every cross-network unit."""
    nets = {n: C.load_network(n) for n in C.DEV_NETWORKS}
    out = []
    if confirm:
        tg = C.load_network("nfbot")
        srcs = {k: v for n in C.DEV_NETWORKS for k, v in nets[n].items()}
        return [(k, v, srcs) for k, v in tg.items()]
    for tnet in C.DEV_NETWORKS:
        srcs = {k: v for n in C.DEV_NETWORKS if n != tnet for k, v in nets[n].items()}
        for k, v in nets[tnet].items():
            day = k.split("/")[1]
            if tnet == "nfcic" and day not in C.PRIMARY_N1 + C.SECONDARY_N1:
                continue
            if C.attack_eligible(v):
                out.append((k, v, srcs))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets")
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--draws", type=int, default=20)
    ap.add_argument("--correction-seeds", default="0", help="seeds for A3-A5 (amendment A3)")
    ap.add_argument("--confirm", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    global OUT
    if a.out:
        OUT = Path(a.out)
    if a.confirm and not Path("docs/phase8i/FREEZE.md").exists():
        sys.exit("confirmatory run refused: docs/phase8i/FREEZE.md does not exist")
    seeds = [int(s) for s in a.seeds.split(",")]
    for name, tgt, srcs in folds(a.confirm):
        if a.targets and name not in a.targets.split(","):
            continue
        res = run_target(name, tgt, srcs, seeds, a.draws,
                         tuple(int(x) for x in a.correction_seeds.split(",")))
        C.dump(OUT / f"{name.replace('/', '__')}.json", res)


if __name__ == "__main__":
    main()
