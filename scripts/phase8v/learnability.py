"""Phase 8v Stages 2-3: attack observability and EXPLORATORY learnability diagnostics.

Everything here uses development labels descriptively (V2 documented attackers vs historical
benign, Phase 8q audit) and is EXPLORATORY: it informs which candidates are registered, and the
later registered results on the same networks are development evidence only.

Per target domain (evaluation windows, joined with the enriched features):

A. **Univariate separability.** ROC-AUC of each feature (attack vs benign; missing values
   dropped, their share reported), for the 12 original and the 18 new features.
   - Cross-network direction consistency: a feature "transfers in direction" when |AUC − 0.5| ≥ 0.1
     with the same sign on ≥ 3 of the 4 networks (NF-CIC = mean over its days with attacks).
B. **Benign shift between networks** (no labels beyond benign): for each feature, the mean over
   network pairs of |2·AUC − 1| between the two networks' benign evaluation windows (0 = same
   distribution, 1 = disjoint), on ≤ 20k sampled windows per network.
C. **Within-network learnability** (small diagnostic LightGBM fits, NOT registered fits):
   - chronological: train on the first half of the evaluation period, test on the second;
   - host-grouped (domains with ≥ 4 attacker hosts): 2 folds of hosts by a fixed hash.
   Feature sets: F0, F0+FLOW, F0+TIME, F0+BIDIR, F0+ALL (host-grouped: F0 and F0+ALL).
   Metric: exact partial AUC (FPR ≤ 1 %) and recall at the retrospective 1 % FPR on the test part.
D. **Domain-origin diagnostic:** a 4-class LightGBM predicting the network from benign windows
   (5k per network, half train / half test) per feature set. Chance = 0.25.

Output: reports/phase8v/learnability.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8v/learnability.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
import time
import zlib
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


FF = _load("phase8v_ff", "scripts/phase8v/flow_features.py")
LF = _load("phase8u_lf", "scripts/phase8u/lowfpr.py")
LA = _load("phase8q_la", "scripts/phase8q/label_audit.py")
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402

F0 = list(WINDOW_FEATURES)
AUDIT = ROOT / "data/derived/phase8q/label_audit"
I8 = ROOT / "data/derived/phase8i"
ENR = ROOT / "data/derived/phase8v/enriched"
OUT = ROOT / "reports/phase8v/learnability.json"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
V2 = LA.VIEWS["V2_documented_attackers"]
BENIGN = ("benign_uninvolved", "benign_involved_host")
SETS = {"F0": [], "F0+FLOW": list(FF.FAMILIES["FLOW"]), "F0+TIME": list(FF.FAMILIES["TIME"]),
        "F0+BIDIR": list(FF.FAMILIES["BIDIR"]), "F0+ALL": list(FF.ALL)}  # fmt: skip
PARAMS = dict(n_estimators=100, learning_rate=0.05, num_leaves=15, subsample=0.8, subsample_freq=1,
              colsample_bytree=0.8, n_jobs=2, verbose=-1, random_state=0)  # fmt: skip
MAX_TRAIN = 30_000
MAX_DIAG_SECONDS = 110.0


def load(name: str) -> dict:
    net, dom = name.split("/")
    a = pl.read_parquet(
        AUDIT / f"{name.replace('/', '__')}.parquet",
        columns=["key", "win", "category", "attack_labels"],
    )
    ev = pl.read_parquet(I8 / net / dom / "eval_unlabelled.parquet", columns=["key", "win", *F0])
    en = pl.read_parquet(ENR / net / f"{dom}.parquet", columns=["key", "win", *FF.ALL])
    j = a.join(ev, on=["key", "win"], how="left", maintain_order="left").join(
        en, on=["key", "win"], how="left", maintain_order="left"
    )
    if j["log_flows"].null_count() or j["tiny_flow_frac"].null_count():
        raise RuntimeError(f"{name}: evaluation windows without features")
    cat = j["category"].to_numpy().astype(str)
    x0 = np.nan_to_num(j.select([pl.col(f).cast(pl.Float64) for f in F0]).to_numpy())
    x1 = j.select([pl.col(f).cast(pl.Float64) for f in FF.ALL]).to_numpy()  # NaN = missing, kept
    fam = j["attack_labels"].fill_null("").to_numpy().astype(str)
    return {"key": j["key"].to_numpy().astype(str), "win": j["win"].to_numpy(), "pos": np.isin(cat, V2),
            "neg": np.isin(cat, BENIGN), "x0": x0, "x1": x1, "family": fam}  # fmt: skip


def auc(pos: np.ndarray, neg: np.ndarray) -> float:
    """Mann-Whitney AUC with average ranks (ties count 0.5)."""
    if pos.size == 0 or neg.size == 0:
        return float("nan")
    v = np.r_[pos, neg]
    o = np.argsort(v, kind="mergesort")
    r = np.empty(v.size)
    sv = v[o]
    starts = np.r_[0, np.flatnonzero(np.diff(sv)) + 1]
    ends = np.r_[starts[1:], sv.size]
    avg = (starts + ends - 1) / 2 + 1
    r[o] = np.repeat(avg, ends - starts)
    return float((r[: pos.size].sum() - pos.size * (pos.size + 1) / 2) / (pos.size * neg.size))


def matrix(d: dict, extra: list[str]) -> np.ndarray:
    idx = [FF.ALL.index(f) for f in extra]
    return np.hstack([d["x0"], d["x1"][:, idx]]) if idx else d["x0"]


def low_fpr(s: np.ndarray, pos: np.ndarray, neg: np.ndarray) -> dict:
    if pos.sum() == 0 or neg.sum() < 100:
        return {"pauc": None, "recall_1pct": None}
    b = np.sort(s[neg])[::-1]
    t = b[int(math.floor(0.01 * b.size))]
    return {"pauc": LF.partial_auc_exact(s[pos], s[neg]), "recall_1pct": float((s[pos] > t).mean())}


def fit_predict(xtr, ytr, xte, seed: int = 0) -> np.ndarray:
    import lightgbm as lgb

    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(ytr == 1), np.flatnonzero(ytr == 0)
    if pos.size + neg.size > MAX_TRAIN:
        pos = rng.choice(pos, min(pos.size, MAX_TRAIN // 2), replace=False)
        neg = rng.choice(neg, min(neg.size, MAX_TRAIN - pos.size), replace=False)
    idx = np.r_[pos, neg]
    w = np.where(ytr[idx] == 1, 0.5 / max(pos.size, 1), 0.5 / max(neg.size, 1))
    m = lgb.LGBMClassifier(**PARAMS).fit(xtr[idx], ytr[idx], sample_weight=w * idx.size)
    return m.predict(xte, raw_score=True)


def main() -> None:
    from netsentinel.resources import peak_rss_mb

    names = sorted(p.stem.replace("__", "/") for p in AUDIT.glob("*.parquet"))
    data = {n: load(n) for n in names}
    res: dict = {"status": "EXPLORATORY (development labels used descriptively; diagnostic fits are not registered fits)",
                 "features": {"F0": F0, **{k: list(v) for k, v in FF.FAMILIES.items()}}}  # fmt: skip
    feats = F0 + list(FF.ALL)

    # A. univariate separability
    uni: dict = {}
    for n, d in data.items():
        x = np.hstack([d["x0"], d["x1"]])
        row = {}
        for j, f in enumerate(feats):
            col = x[:, j]
            ok = ~np.isnan(col)
            row[f] = {"auc": auc(col[d["pos"] & ok], col[d["neg"] & ok]),
                      "missing_pos": float((~ok)[d["pos"]].mean()) if d["pos"].any() else None,
                      "missing_neg": float((~ok)[d["neg"]].mean())}  # fmt: skip
        uni[n] = {"positives": int(d["pos"].sum()), "benign": int(d["neg"].sum()), "features": row}
    res["univariate"] = uni
    net_auc = {f: {} for f in feats}
    for f in feats:
        for net in NETWORKS:
            v = [
                uni[n]["features"][f]["auc"]
                for n in names
                if n.startswith(net + "/") and uni[n]["positives"] > 0
            ]
            v = [a for a in v if not math.isnan(a)]
            net_auc[f][net] = float(np.mean(v)) if v else None
    direction = {}
    for f in feats:
        a = [v for v in net_auc[f].values() if v is not None]
        up, down = sum(x >= 0.6 for x in a), sum(x <= 0.4 for x in a)
        direction[f] = {"network_auc": net_auc[f], "networks_up": up, "networks_down": down,
                        "consistent_direction": bool(max(up, down) >= 3 and min(up, down) == 0),
                        "conflicting_direction": bool(up >= 1 and down >= 1)}  # fmt: skip
    res["direction"] = direction

    # per attack family: best single feature among F0 and among the new ones
    fam: dict = {}
    for n, d in data.items():
        x = np.hstack([d["x0"], d["x1"]])
        for label in np.unique(d["family"][d["pos"]]):
            m = d["pos"] & (d["family"] == label)
            if m.sum() < 20:
                continue
            best = {}
            for grp, cols in (("F0", range(len(F0))), ("new", range(len(F0), len(feats)))):
                sc = []
                for j in cols:
                    ok = ~np.isnan(x[:, j])
                    a = auc(x[m & ok, j], x[d["neg"] & ok, j])
                    sc.append((abs(a - 0.5) if not math.isnan(a) else 0.0, feats[j], a))
                top = max(sc)
                best[grp] = {"feature": top[1], "auc": top[2]}
            fam[f"{n}|{label}"] = {"windows": int(m.sum()), **best}
    res["family_best_single_feature"] = fam

    # B. benign shift between networks
    rng = np.random.default_rng(0)
    ben = {}
    for net in NETWORKS:
        xs = [
            np.hstack([data[n]["x0"], data[n]["x1"]])[data[n]["neg"]]
            for n in names
            if n.startswith(net + "/")
        ]
        x = np.vstack(xs)
        ben[net] = x[rng.choice(x.shape[0], min(20_000, x.shape[0]), replace=False)]
    shift = {}
    for j, f in enumerate(feats):
        vals = []
        for i, a in enumerate(NETWORKS):
            for b in NETWORKS[i + 1 :]:
                ca, cb = ben[a][:, j], ben[b][:, j]
                ca, cb = ca[~np.isnan(ca)], cb[~np.isnan(cb)]
                if ca.size and cb.size:
                    vals.append(abs(2 * auc(ca, cb) - 1))
        shift[f] = float(np.mean(vals)) if vals else None
    res["benign_shift"] = shift

    # C. within-network learnability (diagnostic fits)
    # warm-up: the first LightGBM fit in a process costs about 100 s on this machine (library
    # start-up, as in Phase 8u's first fit); it is excluded from the diagnostic time guard
    tw = time.perf_counter()
    wx = np.random.default_rng(0).random((200, 3))
    fit_predict(wx, (wx[:, 0] > 0.5).astype(int), wx)
    res["lightgbm_warmup_seconds"] = round(time.perf_counter() - tw, 1)
    t0 = time.perf_counter()
    fits = 0
    within: dict = {}
    for n, d in data.items():
        y = d["pos"].astype(int)
        use = d["pos"] | d["neg"]
        half = d["win"] < np.median(np.unique(d["win"]))
        row: dict = {"chronological": {}, "host_grouped": {}}
        tr, te = use & half, use & ~half
        if y[tr].sum() >= 20 and y[te].sum() >= 20:
            for sname, extra in SETS.items():
                if time.perf_counter() - t0 > MAX_DIAG_SECONDS:
                    break
                x = matrix(d, extra)
                s = fit_predict(x[tr], y[tr], x[te])
                fits += 1
                row["chronological"][sname] = low_fpr(s, d["pos"][te], d["neg"][te])
        hosts_pos = np.unique(d["key"][d["pos"]])
        if hosts_pos.size >= 4:
            fold = np.array([zlib.crc32(k.encode()) % 2 for k in d["key"]])
            for sname in ("F0", "F0+ALL"):
                acc = []
                for f in (0, 1):
                    tr, te = use & (fold == f), use & (fold != f)
                    if (
                        y[tr].sum() < 20
                        or y[te].sum() < 20
                        or time.perf_counter() - t0 > MAX_DIAG_SECONDS
                    ):
                        continue
                    x = matrix(d, SETS[sname])
                    s = fit_predict(x[tr], y[tr], x[te])
                    fits += 1
                    acc.append(low_fpr(s, d["pos"][te], d["neg"][te]))
                acc = [a for a in acc if a["pauc"] is not None]
                if acc:
                    row["host_grouped"][sname] = {"pauc": float(np.mean([a["pauc"] for a in acc])),
                                                  "recall_1pct": float(np.mean([a["recall_1pct"] for a in acc])), "folds": len(acc)}  # fmt: skip
        within[n] = row
        print(n, "within done", fits, round(time.perf_counter() - t0, 1), flush=True)
    res["within_network"] = within

    # D. domain-origin diagnostic
    import lightgbm as lgb

    origin = {}
    xs, ys = [], []
    for c, net in enumerate(NETWORKS):
        x = ben[net][:5000]
        xs.append(x)
        ys.append(np.full(x.shape[0], c))
    x, yv = np.vstack(xs), np.concatenate(ys)
    perm = np.random.default_rng(1).permutation(yv.size)
    tr, te = perm[: yv.size // 2], perm[yv.size // 2 :]
    for sname, extra in {**SETS, "FLOW only": list(FF.FAMILIES["FLOW"]), "TIME only": list(FF.FAMILIES["TIME"]),
                         "BIDIR only": list(FF.FAMILIES["BIDIR"])}.items():  # fmt: skip
        cols = ([] if sname.endswith("only") else list(range(len(F0)))) + [
            len(F0) + FF.ALL.index(f) for f in extra
        ]
        m = lgb.LGBMClassifier(**{**PARAMS, "n_estimators": 60}).fit(x[tr][:, cols], yv[tr])
        fits += 1
        origin[sname] = float((m.predict(x[te][:, cols]) == yv[te]).mean())
    res["domain_origin_accuracy"] = origin
    res["diagnostic_fits"] = fits
    res["diagnostic_fit_seconds"] = round(time.perf_counter() - t0, 1)
    res["peak_rss_mb"] = peak_rss_mb()
    OUT.write_bytes(json.dumps(res, indent=1, default=float).encode())
    print("fits", fits, "seconds", res["diagnostic_fit_seconds"], flush=True)


if __name__ == "__main__":
    main()
