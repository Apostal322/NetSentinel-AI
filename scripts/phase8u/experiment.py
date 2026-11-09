"""Phase 8u registered experiment (docs/phase8u/PREREGISTRATION.md): low-FPR training variants of
the frozen M2 member recipe, trained leave-one-network-out exactly as Phase 8o F0 (one fit per
target network: the six NF-CIC days share a training set).

Stages (each fit is logged in reports/phase8u/fit_ledger.json; the run refuses to exceed the
authorised 30 fits / 7,200 s):

- `mine`: three single-network models plus A0 (the M2 member recipe, seed 1060) for targets NF-CIC,
  NF-UNSW and NF-ToN.
  - A0 is checked against the saved Phase 8o F0 base r6 member-0 scores (reproduction gate R0).
  - Cross-fitted mining scores: a source window of network S, in the training set for target T,
    is scored by a model trained on neither S nor T.
  - Mined hard negatives are frozen to data/derived/phase8u/mining/.
- `train --variant V --seed s`: A1 / A2 / B / C1 / C1ns for all four target groups.
- `eval`: metrics for all saved variants and the saved Phase 8o baselines.

Scores are raw margins (sigmoid-monotone for log-loss models). Every metric is rank- or
threshold-based within one model.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
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


ED = _load("phase8o_ed", "scripts/phase8o/experiment_d.py")
LF = _load("phase8u_lf", "scripts/phase8u/lowfpr.py")
CA, FR, C, S, LA = ED.CA, ED.FR, ED.C, ED.S, ED.LA
DER = ROOT / "data" / "derived" / "phase8u"
REP = ROOT / "reports" / "phase8u"
LEDGER = REP / "fit_ledger.json"
MAX_FITS, MAX_SECONDS = 30, 7200.0
SEED0 = 1060  # = Phase 8o member_seed(6, 0); base regime
HN_TOP, HN_CAP, HN_MULT = 0.05, 50, 5.0
VARIANTS = ("A0", "A1", "A2", "B", "C1", "C1ns")
SVC_IDX = [list(S.FEATS).index(f) for f in LF.SERVICE_FEATURES]


# ----------------------------------------------------------------------------- ledger
def ledger() -> dict:
    return json.loads(LEDGER.read_text("utf-8")) if LEDGER.exists() else {"fits": []}


def record_fit(entry: dict) -> None:
    lg = ledger()
    lg["fits"].append(entry)
    lg["total_fits"] = len(lg["fits"])
    lg["total_seconds"] = round(sum(f["seconds"] for f in lg["fits"]), 1)
    REP.mkdir(parents=True, exist_ok=True)
    tmp = LEDGER.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(lg, indent=1).encode())
    os.replace(tmp, LEDGER)


def budget_ok(n_new: int) -> None:
    lg = ledger()
    if len(lg["fits"]) + n_new > MAX_FITS or sum(f["seconds"] for f in lg["fits"]) > MAX_SECONDS:
        sys.exit(
            f"authorisation boundary: {len(lg['fits'])} fits used, {n_new} more requested (max {MAX_FITS})"
        )


# ----------------------------------------------------------------------------- data
def load_groups() -> tuple[dict, dict]:
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    todo = LA.targets(nets)
    groups = {}
    for items in ED.groups(todo).values():
        groups[items[0][0].split("/")[0]] = items  # target network -> [(name, d, srcs)]
    return nets, groups


def full_rows(d: dict) -> dict:
    """Phase 8h train rows of a source domain before subsampling, with identities."""
    ev = d["ev"].filter(~pl.col("noisy"))
    cal = d["cal"]
    x = np.vstack([S._x(cal), S._x(ev)])
    y = np.concatenate([np.zeros(cal.height), ev["y"].to_numpy()]).astype(int)
    keys = np.concatenate([cal["key"].to_numpy(), ev["key"].to_numpy()]).astype(str)
    udp = np.concatenate([cal["udp_share"].to_numpy(), ev["udp_share"].to_numpy()]).astype(float)
    ports = np.concatenate([cal["dst_ports"].to_numpy(), ev["dst_ports"].to_numpy()]).astype(float)
    attackers = set(keys[y == 1].tolist())
    eligible = (y == 0) & ~np.isin(keys, np.array(sorted(attackers), dtype=str))
    return {
        "x": x,
        "y": y,
        "keys": keys,
        "profile": LF.service_profile(udp, ports),
        "eligible": eligible,
    }


def subsample_idx(y: np.ndarray, seed: int) -> np.ndarray:
    """Exactly Phase 8n fragility.train_rows' CAP subsample, returning the indices."""
    if len(y) <= C.CAP:
        return np.arange(len(y))
    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    pos = rng.choice(pos, min(len(pos), C.CAP // 2), replace=False)
    neg = rng.choice(neg, min(len(neg), C.CAP - len(pos)), replace=False)
    return np.sort(np.concatenate([pos, neg]))


def calib_medians(d: dict) -> dict:
    cu, _ = LA.unlabelled(d)
    return LF.service_medians(
        S._x(cu)[:, SVC_IDX],
        LF.service_profile(cu["udp_share"].to_numpy(), cu["dst_ports"].to_numpy()),
    )


def augment(x: np.ndarray, profile: np.ndarray, med: dict, use_service: bool) -> np.ndarray:
    prof = profile if use_service else np.full(profile.size, -1)
    return np.hstack([x, LF.service_relative(x[:, SVC_IDX], prof, med)])


# ----------------------------------------------------------------------------- training
def fit_variant(
    srcs: dict, seed: int, variant: str, mined: dict | None, rows_cache: dict, med_cache: dict
):
    import lightgbm as lgb

    names = list(srcs)
    dw = C.network_weights([srcs[n]["network"] for n in names])
    X, Y, W, D, E = [], [], [], [], []  # noqa: N806
    for j, (n, w_dom) in enumerate(zip(names, dw, strict=True)):
        r = rows_cache.setdefault(n, full_rows(srcs[n]))
        idx = subsample_idx(r["y"], seed)
        x, y = r["x"][idx], r["y"][idx]
        w = w_dom * np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1))
        if variant in ("A1", "A2"):
            hard = mined[n][idx]
            mult = np.where(hard, HN_MULT, 1.0)
            if variant == "A2":
                w = w * mult
            else:  # uniform negative upweighting with the same extra negative weight
                neg = y == 0
                f = (w[neg] * mult[neg]).sum() / max(w[neg].sum(), 1e-12)
                w = np.where(neg, w * f, w)
        if variant in ("C1", "C1ns"):
            med = med_cache.setdefault(n, calib_medians(srcs[n]))
            x = augment(x, r["profile"][idx], med, variant == "C1")
        X.append(x)
        Y.append(y)
        W.append(w)
        D.append(np.full(y.size, j))
        E.append(r["eligible"][idx])
    X, y, w = np.vstack(X), np.concatenate(Y), np.concatenate(W)  # noqa: N806
    w = w * len(y) / w.sum()
    params = dict(C.LGB)
    if variant == "B":
        params["objective"] = LF.PairwiseTailObjective(
            np.concatenate(D), np.concatenate(E), np.asarray(dw), beta=0.05
        )
    return lgb.LGBMClassifier(random_state=seed, **params).fit(X, y, sample_weight=w)


def model_sha(model) -> str:
    return hashlib.sha256(model.booster_.model_to_string().encode()).hexdigest()


def score_targets(model, items: list, variant: str, med_cache: dict) -> dict:
    out = {}
    for name, d, _ in items:
        cu, eu = LA.unlabelled(d)
        hold = (cu["win"] >= S.split_cut(cu)).to_numpy()
        xh, xe = S._x(cu.filter(pl.Series(hold))), S._x(eu)
        if variant in ("C1", "C1ns"):
            med = med_cache.setdefault(name + "|target", calib_medians(d))
            ph = LF.service_profile(
                cu["udp_share"].to_numpy()[hold], cu["dst_ports"].to_numpy()[hold]
            )
            pe = LF.service_profile(eu["udp_share"].to_numpy(), eu["dst_ports"].to_numpy())
            xh, xe = augment(xh, ph, med, variant == "C1"), augment(xe, pe, med, variant == "C1")
        out[name] = {
            "s_hold_u": model.predict(xh, raw_score=True),
            "s_ev_u": model.predict(xe, raw_score=True),
        }
    return out


def save_scores(variant: str, seed: int, target: str, scores: dict, meta: dict) -> None:
    for name, s in scores.items():
        p = DER / "scores" / variant / f"{name.replace('/', '__')}__s{seed}.npz"
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            raise FileExistsError(p)
        CA.save_atomic(p, **s)
    m = DER / "manifests" / f"{variant}__{target}__s{seed}.json"
    m.parent.mkdir(parents=True, exist_ok=True)
    m.write_bytes(json.dumps(meta, indent=1).encode())


def git_sha() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()


def train_and_save(variant: str, seed: int, target: str, items: list, mined: dict | None,
                   rows_cache: dict, med_cache: dict, purpose: str) -> object:  # fmt: skip
    from netsentinel.resources import peak_rss_mb

    budget_ok(1)
    srcs = items[0][2]
    t0 = time.perf_counter()
    model = fit_variant(srcs, seed, variant, mined, rows_cache, med_cache)
    sec = time.perf_counter() - t0
    sha = model_sha(model)
    mdir = DER / "models"
    mdir.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(mdir / f"{variant}__{target}__s{seed}.txt"))
    record_fit({"variant": variant, "target": target, "seed": seed, "seconds": round(sec, 2), "purpose": purpose,
                "model_sha256": sha, "sources": len(srcs), "git_sha": git_sha(), "peak_rss_mb": peak_rss_mb()})  # fmt: skip
    if target != "single":
        sc = score_targets(model, items, variant, med_cache)
        save_scores(variant, seed, target, sc, {"variant": variant, "seed": seed, "target": target, "model_sha256": sha,
                                                "lgb_params": {k: v for k, v in C.LGB.items()}, "git_sha": git_sha(),
                                                "hard_negatives": {"top": HN_TOP, "cap": HN_CAP, "mult": HN_MULT},
                                                "score_sha256": {n: hashlib.sha256(v["s_ev_u"].tobytes()).hexdigest() for n, v in sc.items()}})  # fmt: skip
    print(variant, target, seed, round(sec, 1), "s", flush=True)
    return model


# ----------------------------------------------------------------------------- mining
def stage_mine() -> None:
    _, groups = load_groups()
    rows_cache, med_cache = {}, {}
    all_src = groups["nfbot"][0][2]  # every CIC / UNSW / ToN source domain
    single = {}
    for net in ("nfcic", "nfunsw", "nfton"):
        sub = {n: d for n, d in all_src.items() if d["network"] == net}
        single[net] = train_and_save("A0", SEED0, "single", [("single:" + net, None, sub)], None, rows_cache, med_cache,
                                     f"mining model trained on {net} only")  # fmt: skip
    a0 = {}
    for tnet in ("nfcic", "nfunsw", "nfton"):
        a0[tnet] = train_and_save("A0", SEED0, tnet, groups[tnet], None, rows_cache, med_cache,
                                  "baseline refit (reproduction gate R0) and BoT-target mining model")  # fmt: skip
    # reproduction gate R0: A0 refit vs saved Phase 8o F0 base r6 member 0
    r0 = {}
    for tnet in ("nfcic", "nfunsw", "nfton"):
        for name, _, _ in groups[tnet]:
            new = np.load(DER / "scores" / "A0" / f"{name.replace('/', '__')}__s{SEED0}.npz")
            old = np.load(
                ROOT
                / "data/derived/phase8o/experiment_d/F0/base"
                / f"{name.replace('/', '__')}__r6.npz"
            )
            r0[name] = max(
                float(np.abs(1 / (1 + np.exp(-new[k])) - old[k][0]).max())
                for k in ("s_hold_u", "s_ev_u")
            )
    # cross-fitted mining
    comp = {}
    for tnet, items in groups.items():
        mined = {}
        for n, d in items[0][2].items():
            snet = d["network"]
            if tnet == "nfbot":
                model = a0[snet]  # trained on the other two source networks
            else:
                other = ({"nfcic", "nfunsw", "nfton"} - {snet, tnet}).pop()
                model = single[other]
            r = rows_cache.setdefault(n, full_rows(d))
            s = model.predict(r["x"], raw_score=True)
            m = LF.select_hard_negatives(s, r["eligible"], r["keys"], HN_TOP, HN_CAP)
            mined[n] = m
            hk, hc = np.unique(r["keys"][m], return_counts=True)
            comp[f"{tnet}|{n}"] = {"rows": int(r["y"].size), "eligible_neg": int(r["eligible"].sum()), "mined": int(m.sum()),
                                   "mined_hosts": int(hk.size), "top_host_share": float(hc.max() / hc.sum()) if hc.size else None,
                                   "profile_mined": {int(p): int((r["profile"][m] == p).sum()) for p in range(6)},
                                   "profile_eligible": {int(p): int((r["profile"][r["eligible"]] == p).sum()) for p in range(6)},
                                   "mining_score_q50_q95_mined": [float(np.quantile(s[m], q)) for q in (0.5, 0.95)] if m.any() else None}  # fmt: skip
        buf = io.BytesIO()
        np.savez_compressed(
            buf, **{k.replace("/", "__"): np.flatnonzero(v) for k, v in mined.items()}
        )
        p = DER / "mining" / f"mined__{tnet}.npz"
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            raise FileExistsError(p)
        p.write_bytes(buf.getvalue())
    REP.mkdir(parents=True, exist_ok=True)
    (REP / "mining.json").write_bytes(json.dumps({"reproduction_R0_max_abs_diff": r0, "composition": comp,
                                                   "rule": {"top_frac": HN_TOP, "per_host_cap": HN_CAP, "multiplier": HN_MULT}}, indent=1).encode())  # fmt: skip
    print("R0 max abs diff", max(r0.values()), flush=True)


def load_mined(tnet: str, items: list) -> dict:
    z = np.load(DER / "mining" / f"mined__{tnet}.npz")
    out = {}
    for n, d in items[0][2].items():
        y = full_rows(d)["y"]
        m = np.zeros(y.size, bool)
        m[z[n.replace("/", "__")]] = True
        out[n] = m
    return out


def stage_train(variant: str, seed: int, targets: list[str]) -> None:
    _, groups = load_groups()
    budget_ok(len(targets))
    rows_cache, med_cache = {}, {}
    for tnet in targets:
        items = groups[tnet]
        mined = load_mined(tnet, items) if variant in ("A1", "A2") else None
        train_and_save(
            variant, seed, tnet, items, mined, rows_cache, med_cache, f"registered {variant}"
        )


# ----------------------------------------------------------------------------- evaluation
def stage_eval(tag: str) -> None:
    OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")  # noqa: N806
    TO, FG = OF.TO, OF.FG
    from sklearn.metrics import average_precision_score, roc_auc_score

    names = sorted(p.stem.replace("__", "/") for p in OF.BM.AUDIT.glob("*.parquet"))
    dom = {n: OF.load(n) for n in names}
    is_att = {n: FG.domain_data(n)["is_att"] for n in names}

    def scores_of(variant: str, seed: int, name: str):
        if variant == "M2member":  # saved Phase 8o F0 base r6 member (seed 1060 + m)
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
        if sh.size != is_att[name].size:
            raise RuntimeError(f"{name}: hold-out size differs")
        yv = np.r_[np.ones(pos.sum()), np.zeros(neg.sum())]
        sv = np.r_[se[pos], se[neg]]
        budget = int(math.floor(0.01 * neg.sum()))
        t_or = TO.global_threshold(se[neg], budget)
        t_cal = float(
            np.sort(sh[~is_att[name]])[
                min((~is_att[name]).sum(), math.ceil(((~is_att[name]).sum() + 1) * 0.99)) - 1
            ]
        )
        t_u = float(np.sort(sh)[min(sh.size, math.ceil((sh.size + 1) * 0.99)) - 1])
        return {"roc_auc": float(roc_auc_score(yv, sv)), "pr_auc": float(average_precision_score(yv, sv)),
                "pauc_1pct": TO.partial_auc(se[pos], se[neg]), "oracle_1pct": OF.metrics(d, se, se > t_or),
                "cal_T": OF.metrics(d, se, se > t_cal), "cal_U": OF.metrics(d, se, se > t_u)}  # fmt: skip

    runs = {}
    combos = [("M2member", s) for s in (SEED0, SEED0 + 1, SEED0 + 2)]
    for v in VARIANTS:
        for f in (
            sorted((DER / "scores" / v).glob("*.npz")) if (DER / "scores" / v).exists() else []
        ):
            combos.append((v, int(f.stem.split("__s")[-1])))
    for v, s in sorted(set(combos)):
        per = {}
        for name in names:
            sc = scores_of(v, s, name)
            if sc is None and v == "A0" and name.startswith("nfbot"):
                sc = scores_of(
                    "M2member", s, name
                )  # BoT A0 = the saved member (R0 shown on the other targets)
            if sc is None:
                break
            per[name] = metrics(name, *sc)
        else:
            runs[f"{v}|{s}"] = per
            print("eval", v, s, flush=True)
    summary = {k: aggregate(v) for k, v in runs.items()}
    res = {"status": "Phase 8u evaluation (development data; consumed networks)", "git_sha": git_sha(),
           "summary": summary, "per_domain": runs, "decisions": decide(summary)}  # fmt: skip
    body = json.dumps(res, indent=1, default=float).encode()
    p = REP / f"evaluation{tag}.json"
    if p.exists():
        raise FileExistsError(p)
    tmp = p.with_suffix(".partial")
    tmp.write_bytes(body)
    os.replace(tmp, p)
    (REP / f"evaluation{tag}.sha256").write_text(hashlib.sha256(body).hexdigest())


def _mean(ds: list, f) -> float:
    return float(np.nanmean([f(x) for x in ds]))


def aggregate(per: dict) -> dict:
    nets = {}
    for net in ("nfcic", "nfunsw", "nfton", "nfbot"):
        ds = [v for k, v in per.items() if k.startswith(net + "/")]
        nets[net] = {"roc_auc": _mean(ds, lambda x: x["roc_auc"]), "pr_auc": _mean(ds, lambda x: x["pr_auc"]),
                     "pauc_1pct": _mean(ds, lambda x: x["pauc_1pct"]),
                     "recall_1pct": _mean(ds, lambda x: x["oracle_1pct"]["recall"]),
                     "calT_recall": _mean(ds, lambda x: x["cal_T"]["recall"]), "calT_fpr": _mean(ds, lambda x: x["cal_T"]["fpr"]),
                     "calT_fa_per_h": _mean(ds, lambda x: x["cal_T"]["fa_per_h"]),
                     "calT_top_host": _mean(ds, lambda x: x["cal_T"]["top_host_fa_share"])}  # fmt: skip
    out = {"networks": nets}
    for k in ("roc_auc", "pr_auc", "pauc_1pct", "recall_1pct", "calT_recall"):
        out[f"macro_{k}"] = float(np.mean([nets[n][k] for n in nets]))
    out.update({"R20_oracle": sum(x["oracle_1pct"]["r20"] for x in per.values()),
                "missed_oracle": sum(x["oracle_1pct"]["missed"] for x in per.values()),
                "R20_calT": sum(x["cal_T"]["r20"] for x in per.values()),
                "missed_calT": sum(x["cal_T"]["missed"] for x in per.values())})  # fmt: skip
    return out


def screen(cand: dict, base: dict) -> dict:
    dp = cand["macro_pauc_1pct"] - base["macro_pauc_1pct"]
    dr = cand["macro_recall_1pct"] - base["macro_recall_1pct"]
    worst_p = min(
        cand["networks"][n]["pauc_1pct"] - base["networks"][n]["pauc_1pct"]
        for n in base["networks"]
    )
    worst_r = min(
        cand["networks"][n]["recall_1pct"] - base["networks"][n]["recall_1pct"]
        for n in base["networks"]
    )
    ok = dp >= 0.02 and dr >= 0.02 and worst_p >= -0.02 and worst_r >= -0.05
    return {
        "d_macro_pauc": dp,
        "d_macro_recall_1pct": dr,
        "worst_net_d_pauc": worst_p,
        "worst_net_d_recall": worst_r,
        "passes": ok,
    }


def guardrails(cand: dict, base: dict) -> dict:
    g = {}
    for n in base["networks"]:
        c, b = cand["networks"][n], base["networks"][n]
        g[n] = {"fpr": c["calT_fpr"] <= b["calT_fpr"] + 0.01, "fa_h": c["calT_fa_per_h"] <= 1.2 * b["calT_fa_per_h"] + 1.0,
                "recall_1pct": c["recall_1pct"] >= b["recall_1pct"] - 0.05}  # fmt: skip
    return {"per_network": g, "missed_calT": cand["missed_calT"] <= base["missed_calT"] + 2,
            "all": all(all(v.values()) for v in g.values()) and cand["missed_calT"] <= base["missed_calT"] + 2}  # fmt: skip


def decide(summary: dict) -> dict:
    base0 = summary.get(f"M2member|{SEED0}")
    out: dict = {"screening": {}}
    if base0 is None:
        return out
    for v in ("A1", "A2", "B", "C1"):
        k = f"{v}|{SEED0}"
        if k in summary:
            out["screening"][v] = screen(summary[k], base0)
            out["screening"][v]["guardrails"] = guardrails(summary[k], base0)
    reps = {}
    for v in ("A2", "B", "C1"):
        seeds = [
            s
            for s in (SEED0, SEED0 + 1, SEED0 + 2)
            if f"{v}|{s}" in summary and f"M2member|{s}" in summary
        ]
        if len(seeds) >= 2:
            d = [screen(summary[f"{v}|{s}"], summary[f"M2member|{s}"]) for s in seeds]
            gr = [guardrails(summary[f"{v}|{s}"], summary[f"M2member|{s}"]) for s in seeds]
            reps[v] = {"seeds": seeds, "mean_d_pauc": float(np.mean([x["d_macro_pauc"] for x in d])),
                       "mean_d_recall": float(np.mean([x["d_macro_recall_1pct"] for x in d])),
                       "all_seeds_positive": all(x["d_macro_pauc"] > 0 for x in d),
                       "worst_net_d_recall_min": min(x["worst_net_d_recall"] for x in d), "guardrails_all_seeds": all(x["all"] for x in gr)}  # fmt: skip
            reps[v]["replicated"] = (reps[v]["mean_d_pauc"] >= 0.02 and reps[v]["mean_d_recall"] >= 0.02 and reps[v]["all_seeds_positive"]
                                     and reps[v]["worst_net_d_recall_min"] >= -0.05 and reps[v]["guardrails_all_seeds"])  # fmt: skip
    out["replication"] = reps
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("mine", "train", "eval"))
    ap.add_argument("--variant", choices=VARIANTS)
    ap.add_argument("--seed", type=int, default=SEED0)
    ap.add_argument("--targets", default="nfcic,nfunsw,nfton,nfbot")
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    if a.stage == "mine":
        stage_mine()
    elif a.stage == "train":
        stage_train(a.variant, a.seed, a.targets.split(","))
    else:
        stage_eval(a.tag)


if __name__ == "__main__":
    main()
