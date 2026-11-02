"""Phase 8i Experiment C (I3): less network-identifying representations
(docs/phase8i/PREREGISTRATION.md section 6).

Cross-network folds (target network vs the other networks), no target labels, T0 threshold:
  raw        B-raw (= A1 of Experiment A, refitted here so every variant shares the fit code)
  no_volume  B-raw without the 4 volume features (the Phase 8h ablation)
  C1_k1..3   B-raw without the top-k features of a network classifier trained on SOURCE
             benign-train windows (total gain)
  C2         relative volume: volume features minus the domain's benign-train median
  B-rz       the deployed robust baseline (target calibration only)
Negative control: cross-validated macro ROC-AUC of a network classifier on development benign
windows under raw / C1(k) / C2.
Within-network check: NF-CIC leave-one-day-out (sources = the other NF-CIC days) for raw,
C1_k2 and C2 (C1 ranking from all development networks' benign-train windows, amendment A1).

Output: reports/phase8i/exp_c/{cross,within,control}.json
Usage: uv run python scripts/phase8i/exp_c.py [--part cross,within,control] [--seeds 0,1,2]
       [--confirm]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812
from exp_a import folds  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("reports/phase8i/exp_c")
PER_NET = 5_000  # benign-train windows per domain for the network classifier


def benign_sample(doms: dict, seed: int) -> tuple[np.ndarray, np.ndarray, list[dict]]:
    rng = np.random.default_rng(seed)
    xs, ys, ds = [], [], []
    for d in doms.values():
        C.prepare(d)
        x = C.S._x(d["_btrain"])
        if len(x) > PER_NET:
            x = x[rng.choice(len(x), PER_NET, replace=False)]
        xs.append(x)
        ys.append(np.full(len(x), d["network"], dtype=object))
        ds.append(d)
    return xs, ys, ds


def network_ranking(doms: dict, seed: int = 0) -> list[int]:
    """Feature indices ordered by the gain of a network classifier on benign-train windows."""
    import lightgbm as lgb

    xs, ys, _ = benign_sample(doms, seed)
    X, y = np.vstack(xs), np.concatenate(ys)  # noqa: N806
    m = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.1, num_leaves=15, random_state=seed,
                           n_jobs=2, verbose=-1, importance_type="gain").fit(X, y)  # fmt: skip
    return [int(i) for i in np.argsort(-m.feature_importances_, kind="stable")]


def reps(rank: list[int]) -> dict[str, C.Rep]:
    allf = list(range(len(C.FEATS)))
    out = {"raw": C.Rep("raw"),
           "no_volume": C.Rep("no_volume", [i for i in allf if i not in C.VOL_IDX]),
           "C2": C.Rep("C2", relvol=True)}  # fmt: skip
    for k in (1, 2, 3):
        out[f"C1_k{k}"] = C.Rep(f"C1_k{k}", [i for i in allf if i not in rank[:k]])
    return out


def score_variant(model, rep: C.Rep, tgt: dict) -> tuple[np.ndarray, np.ndarray]:
    C.prepare(tgt)
    s_ev = model.predict_proba(rep.apply(C.S._x(tgt["ev"]), tgt))[:, 1]
    s_hold = model.predict_proba(rep.apply(C.S._x(tgt["_hold"]), tgt))[:, 1]
    return s_ev, s_hold


def robust(tgt: dict) -> dict:
    C.prepare(tgt)
    fit, hold = tgt["_btrain"], tgt["_hold"]
    s_hold, _ = C.S.product(fit, hold)
    s_ev, _ = C.S.product(fit, tgt["ev"])
    thr, rel = C.t0(s_hold)
    return {**C.evaluate(tgt, s_ev, thr), "T0_reliable": rel, "n_hold": hold.height}


def cross(seeds: list[int], confirm: bool, only: set | None, net: str = "nfbot") -> dict:
    res = {}
    groups: dict[tuple, list] = {}
    for name, tgt, srcs in folds(confirm, net):
        groups.setdefault(tuple(sorted(srcs)), []).append((name, tgt, srcs))
    for _, units in groups.items():
        srcs = units[0][2]
        rank = network_ranking(srcs)
        variants = reps(rank)
        if only:
            variants = {k: v for k, v in variants.items() if k in only}
        for name, tgt, _ in units:
            res[name] = {"ranking": [C.FEATS[i] for i in rank], "B-rz": robust(tgt), "seeds": {}}
        for seed in seeds:
            for vname, rep in variants.items():
                t = time.perf_counter()
                model, _, n = C.fit_source(srcs, seed, rep)
                for name, tgt, _ in units:
                    s_ev, s_hold = score_variant(model, rep, tgt)
                    thr, rel = C.t0(s_hold)
                    e = {**C.evaluate(tgt, s_ev, thr), "T0_reliable": rel, "train_rows": n,
                         "fit_s": time.perf_counter() - t}  # fmt: skip
                    res[name]["seeds"].setdefault(str(seed), {})[vname] = e
                print(seed, vname, {u[0]: round(res[u[0]]["seeds"][str(seed)][vname]
                                                .get("window_recall") or 0, 3) for u in units},
                      flush=True)  # fmt: skip
    return res


def within(seeds: list[int]) -> dict:
    n1 = C.load_network("nfcic")
    alld = {k: v for n in C.DEV_NETWORKS for k, v in
            (n1.items() if n == "nfcic" else C.load_network(n).items())}  # fmt: skip
    rank = network_ranking(alld)
    variants = {k: v for k, v in reps(rank).items() if k in ("raw", "C1_k2", "C2")}
    res = {"ranking": [C.FEATS[i] for i in rank], "units": {}}
    for day in C.PRIMARY_N1:
        name = f"nfcic/{day}"
        if name not in n1 or not C.attack_eligible(n1[name]):
            continue
        srcs = {k: v for k, v in n1.items() if k != name}
        out = {}
        for seed in seeds:
            for vname, rep in variants.items():
                model, _, n = C.fit_source(srcs, seed, rep)
                s_ev, s_hold = score_variant(model, rep, n1[name])
                thr, rel = C.t0(s_hold)
                out.setdefault(str(seed), {})[vname] = {**C.evaluate(n1[name], s_ev, thr),
                                                        "T0_reliable": rel}  # fmt: skip
        res["units"][name] = out
        print("within", name, {v: round(out[str(seeds[0])][v].get("window_recall") or 0, 3)
                               for v in variants}, flush=True)  # fmt: skip
    return res


def control(seed: int = 0) -> dict:
    """Network identifiability of benign windows under each representation (3-fold CV)."""
    import lightgbm as lgb
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    alld = {k: v for n in C.DEV_NETWORKS for k, v in C.load_network(n).items()}
    rank = network_ranking(alld, seed)
    xs, ys, ds = benign_sample(alld, seed)
    y = np.concatenate(ys)
    out = {"ranking": [C.FEATS[i] for i in rank], "n": int(len(y)),
           "per_network": {n: int((y == n).sum()) for n in sorted(set(y))}}  # fmt: skip
    for vname, rep in reps(rank).items():
        X = np.vstack([rep.apply(x, d) for x, d in zip(xs, ds, strict=True)])  # noqa: N806
        m = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.1, num_leaves=15,
                               random_state=seed, n_jobs=2, verbose=-1)  # fmt: skip
        p = cross_val_predict(m, X, y, cv=StratifiedKFold(3, shuffle=True, random_state=seed),
                              method="predict_proba")  # fmt: skip
        out[vname] = float(roc_auc_score(y, p, multi_class="ovr", average="macro"))
        print("control", vname, round(out[vname], 4), flush=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", default="cross,within,control")
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--variants")
    C.confirm_args(ap)
    a = ap.parse_args()
    out = Path(a.out) if a.out else OUT
    C.confirm_guard(a)
    seeds = [int(s) for s in a.seeds.split(",")]
    only = set(a.variants.split(",")) if a.variants else None
    for part in a.part.split(","):
        t = time.perf_counter()
        r = {"cross": lambda: cross(seeds, a.confirm, only, a.stand_in or "nfbot"),
             "within": lambda: within(seeds),
             "control": control}[part]()  # fmt: skip
        r = {"result": r, "seconds": time.perf_counter() - t, "peak_rss_mb": peak_rss_mb()}
        C.dump(out / f"{part}.json", r)


if __name__ == "__main__":
    main()
