"""Phase 8w registered analyses that need no new registered fit (PREREGISTRATION § 7).

Re-scores the saved boosters; never refits a registered model.
- `stress`: contamination stress. Reference = the oracle-benign rows plus injected attack windows
  (the domain's evaluation attack windows: the worst case, the evaluated attack already running
  in the history) at the registered shares. Diagnostic only.
- `z2`: simulated-review sensitivity: five draws of 800 windows, with a perfect reviewer and
  with one that passes 10 % of attack windows as benign.
- `entities`: documented attacker entities gained and lost against the null control.
- `scale`: exploratory mechanism view (size of |z| per reference; booster feature use);
- `review`: sensitivity checks requested by the independent review (exploratory);
- `shortcut`: benign-only network classifier (three small diagnostic fits), between-network
  feature divergence and benign score levels.

Output: reports/phase8w/posthoc_<stage>.json.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
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


E = _load("phase8w_exp", "scripts/phase8w/experiment.py")
REF, RL, X, OF, S, G, LF = E.REF, E.RL, E.X, E.OF, E.S, E.G, E.LF
FEATS, NETS, DER, REP = E.FEATS, E.NETS, E.DER, E.REP
SHARES = (0.0, 0.05, 0.10, 0.20, 0.30, 0.45, 0.60)
NOISE = 0.10


def save(stage: str, res: dict) -> None:
    body = json.dumps(res, indent=1, default=float).encode()
    p = REP / f"posthoc_{stage}.json"
    if p.exists():  # write-once (review F2): saved outputs are never overwritten
        raise FileExistsError(p)
    tmp = p.with_suffix(".partial")
    tmp.write_bytes(body)
    os.replace(tmp, p)
    (REP / f"posthoc_{stage}.sha256").write_text(hashlib.sha256(body).hexdigest())


_ITEMS: list = []


def environment() -> dict:
    _, groups = X.load_groups()
    env = {}
    for tnet, items in groups.items():
        for name, d, _ in items:
            p = REF.calibration_parts(d, name)
            ev = OF.load(name)
            REF.aligned(ev, p["eu"], name)
            fit = ~p["hold"]
            _ITEMS.append((name, d, None))
            env[name] = {"tnet": tnet, "p": p, "ev": ev,
                         "xh": S._x(p["cu"].filter(pl.Series(p["hold"]))), "xe": S._x(p["eu"]),
                         "xfit": S._x(p["cu"].filter(pl.Series(fit))), "fit_att": p["att_win"][fit],
                         "is_att": OF.FG.domain_data(name)["is_att"]}  # fmt: skip
    return env


def available(arm: str) -> list[int]:
    return sorted({int(f.stem.split("__s")[-1]) for f in (DER / "scores" / arm).glob("*.npz")})


_BOOSTERS: dict = {}


def booster(arm: str, tnet: str, seed: int):
    import lightgbm as lgb

    k = (arm, tnet, seed)
    if k not in _BOOSTERS:
        raw = (DER / "models" / f"{arm}__{tnet}__s{seed}.txt").read_bytes()
        mf = json.loads((DER / "manifests" / f"{arm}__{tnet}__s{seed}.json").read_text("utf-8"))
        if hashlib.sha256(raw).hexdigest() != mf["model_sha256"]:
            raise RuntimeError(f"{k}: saved model does not match its manifest")
        _BOOSTERS[k] = lgb.Booster(model_str=raw.decode("utf-8"))
    return _BOOSTERS[k]


def metrics(e: dict, sh: np.ndarray, se: np.ndarray) -> dict:
    d = e["ev"]
    pos, neg = d["pos"], d["neg"]
    ben_h = ~e["is_att"]
    t_or = OF.TO.global_threshold(se[neg], int(math.floor(0.01 * neg.sum())))
    t_cal = float(np.sort(sh[ben_h])[min(ben_h.sum(), math.ceil((ben_h.sum() + 1) * 0.99)) - 1])
    return {"roc_auc": float("nan"), "pr_auc": float("nan"),
            "pauc_1pct": LF.partial_auc_exact(se[pos], se[neg]),
            "oracle_1pct": OF.metrics(d, se, se > t_or), "cal_T": OF.metrics(d, se, se > t_cal)}  # fmt: skip


def run(env: dict, arm: str, seed: int, refs: dict) -> dict:
    """Aggregate metrics of one member with the given per-domain references."""
    per = {}
    for name, e in env.items():
        m = booster(arm, e["tnet"], seed)
        sh = m.predict(E.transform(e["xh"], refs[name], arm), raw_score=True)
        se = m.predict(E.transform(e["xe"], refs[name], arm), raw_score=True)
        per[name] = metrics(e, sh, se)
    a = X.aggregate(per)
    return {"macro_pauc": a["macro_pauc_1pct"], "hard_pauc": float(np.mean([a["networks"][n]["pauc_1pct"] for n in G.HARD])),
            "pauc": {n: a["networks"][n]["pauc_1pct"] for n in NETS},
            "recall_1pct": {n: a["networks"][n]["recall_1pct"] for n in NETS},
            "calT_fpr": {n: a["networks"][n]["calT_fpr"] for n in NETS},
            "calT_recall": {n: a["networks"][n]["calT_recall"] for n in NETS},
            "missed_calT": a["missed_calT"], "missed_oracle": a["missed_oracle"]}  # fmt: skip


def null_runs(seeds: list[int]) -> dict:
    ev = json.loads((REP / "evaluation_final.json").read_text("utf-8")) if (REP / "evaluation_final.json").exists() \
        else json.loads((REP / "evaluation_screening.json").read_text("utf-8"))  # fmt: skip
    out = {}
    for s in seeds:
        a = ev["summary"]["Z1"]["R0"][str(s)]
        out[str(s)] = {"macro_pauc": a["macro_pauc_1pct"],
                       "hard_pauc": float(np.mean([a["networks"][n]["pauc_1pct"] for n in G.HARD])),
                       "pauc": {n: a["networks"][n]["pauc_1pct"] for n in NETS}}  # fmt: skip
    return out


def stage_stress(arms: list[str]) -> None:
    env = environment()
    refs0 = {
        n: RL.fit_reference(e["xfit"][~e["fit_att"]], FEATS, "oracle_benign")
        for n, e in env.items()
    }
    shift, refs = {}, {}
    for share in SHARES:
        refs[share] = {}
        for name, e in env.items():
            rng = np.random.default_rng([zlib.crc32(name.encode()), int(round(share * 100))])
            rows = RL.contaminated_rows(
                e["xfit"][~e["fit_att"]], e["xe"][e["ev"]["pos"]], share, rng
            )
            r = RL.fit_reference(rows, FEATS, "unlabelled_history")
            refs[share][name] = r
            d = np.abs(r.location - refs0[name].location) / refs0[name].scale
            shift.setdefault(name, {})[str(share)] = {"max_location_shift": float(d.max()),
                                                      "features_shifted_over_1": int((d > 1).sum()),
                                                      "median_scale_ratio": float(np.median(r.scale / refs0[name].scale))}  # fmt: skip
    res = {"status": "contamination stress (diagnostic; contaminants are evaluation attack windows)",
           "shares": list(SHARES), "reference_shift": shift, "runs": {}}  # fmt: skip
    for arm in arms:
        seeds = available(arm)
        res["runs"][arm] = {
            str(s): {str(sh): run(env, arm, s, refs[sh]) for sh in SHARES} for s in seeds
        }
        res.setdefault("null", null_runs(seeds))
        print("stress", arm, seeds, flush=True)
    save("stress", res)


def stage_z2(arms: list[str], seeds: list[int]) -> None:
    env = environment()
    res = {"status": "simulated review sensitivity (Z2; simulated reviewer, not analyst evidence)",
           "budget": REF.REVIEW_BUDGET, "noise": NOISE, "kept": {}, "runs": {}}  # fmt: skip
    for noisy in (False, True):
        for draw in range(5):
            refs, tag = {}, f"{'noisy' if noisy else 'perfect'}|{draw}"
            for name, e in env.items():
                p = e["p"]
                rev = REF.reviewed(p, name, draw=draw)
                ok = ~p["att_win"]
                if noisy:
                    rng = np.random.default_rng([zlib.crc32(name.encode()), draw, 7])
                    ok = ok | (p["att_win"] & (rng.random(ok.size) < NOISE))
                rows = S._x(p["cu"].filter(pl.Series(rev & ok)))
                refs[name] = RL.fit_reference(rows, FEATS, "vetted_benign_simulated")
                res["kept"].setdefault(tag, {})[name] = {"n": refs[name].n, "status": refs[name].status,
                                                         "attack_windows_kept": int((rev & ok & p["att_win"]).sum())}  # fmt: skip
            if any(r.status != "ok" for r in refs.values()):
                res["runs"][tag] = "insufficient_history in at least one domain; not scored"
                continue
            res["runs"][tag] = {a: {str(s): run(env, a, s, refs) for s in seeds} for a in arms}
            print("z2", tag, flush=True)
    res["null"] = null_runs(seeds)
    save("z2", res)


def stage_entities(arms: list[str]) -> None:
    names = sorted(p.stem.replace("__", "/") for p in OF.BM.AUDIT.glob("*.parquet"))
    dom = {n: OF.load(n) for n in names}
    is_att = {n: OF.FG.domain_data(n)["is_att"] for n in names}

    def detected(arm: str, seed: int, sc: str) -> dict:
        out = {}
        for n in names:
            z = np.load(DER / "scores" / arm / f"{n.replace('/', '__')}__s{seed}.npz")
            k = "NA" if arm == "R0" else sc
            sh, se = z[f"s_hold_{k}"], z[f"s_ev_{k}"]
            d, ben_h = dom[n], ~is_att[n]
            t_cal = float(
                np.sort(sh[ben_h])[min(ben_h.sum(), math.ceil((ben_h.sum() + 1) * 0.99)) - 1]
            )
            t_or = OF.TO.global_threshold(se[d["neg"]], int(math.floor(0.01 * d["neg"].sum())))
            for ent, idx in d["ents"]:
                if idx.size >= 5:
                    out[f"{n}|{ent}"] = {"windows": int(idx.size), "cal": float((se[idx] > t_cal).mean()),
                                         "oracle": float((se[idx] > t_or).mean())}  # fmt: skip
        return out

    res = {
        "status": "documented attacker entities (>= 5 positive windows) against the null control",
        "runs": {},
    }
    for arm in arms:
        for sc in ("Z1", "Z3"):
            rows = {}
            for s in available(arm):
                a, b = detected(arm, s, sc), detected("R0", s, sc)
                row = {"entities": len(b)}
                for view in ("cal", "oracle"):
                    row[f"missed_{view}_null"] = sorted(k for k, v in b.items() if v[view] == 0)
                    row[f"missed_{view}_arm"] = sorted(k for k, v in a.items() if v[view] == 0)
                    row[f"lost_{view}"] = sorted(k for k in b if b[k][view] > 0 and a[k][view] == 0)
                    row[f"gained_{view}"] = sorted(
                        k for k in b if b[k][view] == 0 and a[k][view] > 0
                    )
                    row[f"r20_{view}_null"] = int(sum(v[view] >= 0.2 for v in b.values()))
                    row[f"r20_{view}_arm"] = int(sum(v[view] >= 0.2 for v in a.values()))
                rows[str(s)] = row
            res["runs"][f"{arm}|{sc}"] = rows
            print("entities", arm, sc, flush=True)
    save("entities", res)


def stage_shortcut() -> None:
    import lightgbm as lgb
    from scipy.stats import ks_2samp

    env = environment()
    rng = np.random.default_rng(0)
    xs, net = {a: [] for a in E.ARMS}, []
    for name, e in env.items():
        neg = np.flatnonzero(e["ev"]["neg"])
        take = rng.choice(neg, size=min(2000, neg.size), replace=False)
        ref = RL.fit_reference(e["xfit"], FEATS, "unlabelled_history")
        for a in E.ARMS:
            xs[a].append(E.transform(e["xe"][take], ref, a))
        net.append(np.full(take.size, name.split("/")[0]))
    y = np.concatenate(net)
    codes = np.array([NETS.index(v) for v in y])
    perm = rng.permutation(y.size)
    tr, te = perm[: int(0.7 * y.size)], perm[int(0.7 * y.size) :]
    res = {"status": "domain-shortcut diagnostics on benign evaluation windows (Z1 reference); three small diagnostic "
                     "fits; lower accuracy is not by itself an improvement",
           "windows": {n: int((y == n).sum()) for n in NETS}, "majority_share": float(max((y == n).mean() for n in NETS)),
           "representations": {}}  # fmt: skip
    for a in E.ARMS:
        x = np.vstack(xs[a])
        m = lgb.LGBMClassifier(
            n_estimators=100, num_leaves=15, random_state=0, n_jobs=2, verbose=-1
        ).fit(x[tr], codes[tr])
        acc = float((m.predict(x[te]) == codes[te]).mean())
        ks = [ks_2samp(x[y == p][:, j], x[y == q][:, j]).statistic
              for j in range(len(FEATS)) for i, p in enumerate(NETS) for q in NETS[i + 1:]]  # fmt: skip
        res["representations"][a] = {"network_classifier_accuracy": acc, "mean_pairwise_ks": float(np.mean(ks)),
                                     "max_pairwise_ks": float(np.max(ks))}  # fmt: skip
        print("shortcut", a, round(acc, 3), flush=True)
    save("shortcut", res)


def stage_scale(arms: list[str]) -> None:
    """Exploratory mechanism view, no model fitted: how large deviations are under each target
    reference, and which features the saved boosters use."""
    env = environment()
    vol = [FEATS.index(f) for f in ("log_flows", "log_up_bytes", "log_down_bytes", "log_pkts")]
    res = {
        "status": "exploratory: size of |z| by reference, and booster feature use",
        "domains": {},
        "importance": {},
    }
    for name, e in env.items():
        p, pos, neg = e["p"], e["ev"]["pos"], e["ev"]["neg"]
        refs = REF.target_references(next(d for n, d, _ in _ITEMS if n == name), name, p)
        row = {}
        for sc in ("T", "Z1", "Z3"):
            a = np.abs(RL.zscore(e["xe"], refs[sc]))
            row[sc] = {"scale_log_flows": float(refs[sc].scale[vol[0]]),
                       "median_scale_volume": float(np.median(refs[sc].scale[vol])),
                       "floored_features": int(refs[sc].floored.sum()),
                       "attack_median_absz_volume": float(np.median(a[pos][:, vol])),
                       "benign_median_absz_volume": float(np.median(a[neg][:, vol])),
                       "benign_p99_absz_log_flows": float(np.quantile(a[neg][:, vol[0]], 0.99)),
                       "attack_clipped_share_volume": float((a[pos][:, vol] >= RL.CLIP).mean()),
                       "benign_clipped_share_volume": float((a[neg][:, vol] >= RL.CLIP).mean()),
                       "benign_clipped_share_any": float((a[neg] >= RL.CLIP).any(axis=1).mean()),
                       "attack_clipped_share_any": float((a[pos] >= RL.CLIP).any(axis=1).mean())}  # fmt: skip
        res["domains"][name] = row
    for arm in ("R0", *arms):
        g = []
        for s in available(arm):
            for tnet in NETS:
                v = booster(arm, tnet, s).feature_importance("gain").astype(float)
                g.append(v / v.sum())
        res["importance"][arm] = dict(zip(FEATS, np.mean(g, axis=0).round(4).tolist(), strict=True))
    save("scale", res)


def stage_review(arms: list[str]) -> None:
    """Sensitivity checks requested by the independent review (exploratory; outcomes were visible).
    From the saved score arrays only, under the unlabelled reference `Z1`:
    - partial AUC without the benign host that holds most of the top benign scores (review B1);
    - realised false alerts at the retrospective 1 % threshold (B6);
    - a label-free threshold `cal_U` from every hold-out window (A2);
    - alerts per hour over every evaluation window, not only the audited benign ones (E2)."""
    names = sorted(p.stem.replace("__", "/") for p in OF.BM.AUDIT.glob("*.parquet"))
    dom = {n: OF.load(n) for n in names}
    is_att = {n: OF.FG.domain_data(n)["is_att"] for n in names}

    def rank_threshold(v: np.ndarray) -> float:
        return float(np.sort(v)[min(v.size, math.ceil((v.size + 1) * 0.99)) - 1])

    res = {"status": "review sensitivity checks (exploratory; Z1 reference; saved scores only)",
           "git": dict(zip(("sha", "dirty"), E.git_state(), strict=True)), "runs": {}}  # fmt: skip
    for arm in ("R0", *arms):
        for s in available(arm):
            per = {}
            for n in names:
                z = np.load(DER / "scores" / arm / f"{n.replace('/', '__')}__s{s}.npz")
                k = "NA" if arm == "R0" else "Z1"
                sh, se = z[f"s_hold_{k}"], z[f"s_ev_{k}"]
                d = dom[n]
                pos, neg, key = d["pos"], d["neg"], d["key"].astype(str)
                budget = int(math.floor(0.01 * neg.sum()))
                t_or = OF.TO.global_threshold(se[neg], budget)
                sb, kb = se[neg], key[neg]
                tail = sb >= np.sort(sb)[::-1][min(budget, sb.size - 1)]
                hosts, cnt = np.unique(kb[tail], return_counts=True)
                top = hosts[cnt.argmax()]
                keep = neg & (key != top)
                t_cal, t_u = rank_threshold(sh[~is_att[n]]), rank_threshold(sh)
                row = {"pauc": LF.partial_auc_exact(se[pos], se[neg]),
                       "pauc_without_top_benign_host": LF.partial_auc_exact(se[pos], se[keep]),
                       "top_benign_host": str(top), "top_host_share_of_benign_tail": float(cnt.max() / tail.sum()),
                       "benign_tail_windows": int(tail.sum()), "benign_hosts": int(np.unique(kb).size),
                       "benign_windows": int(neg.sum()), "budget": budget,
                       "false_alerts_at_retrospective_threshold": int((sb > t_or).sum()),
                       "holdout_windows": int(sh.size), "holdout_label_benign_windows": int((~is_att[n]).sum()),
                       "windows_outside_audited_population": int((~pos & ~neg).sum())}  # fmt: skip
                for tag, t in (("cal_T", t_cal), ("cal_U", t_u)):
                    a = se > t
                    row[tag] = {"fpr": float(a[neg].mean()), "recall": float(a[pos].mean()) if pos.any() else float("nan"),
                                "benign_false_alerts_per_h": float(a[neg].sum() / d["hours"]),
                                "all_alerts_per_h": float(a.sum() / d["hours"]),
                                "alerts_outside_audited_per_h": float(a[~pos & ~neg].sum() / d["hours"])}  # fmt: skip
                per[n] = row
            res["runs"].setdefault(arm, {})[str(s)] = per
        print("review", arm, flush=True)
    save("review", res)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("stress", "z2", "entities", "shortcut", "scale", "review"))
    ap.add_argument("--arms", default="S,A")
    ap.add_argument("--seeds", default="1060,1061")
    a = ap.parse_args()
    arms = a.arms.split(",")
    if a.stage == "stress":
        stage_stress(arms)
    elif a.stage == "z2":
        stage_z2(arms, [int(s) for s in a.seeds.split(",")])
    elif a.stage == "review":
        stage_review(arms)
    elif a.stage == "scale":
        stage_scale(arms)
    elif a.stage == "entities":
        stage_entities(arms)
    else:
        stage_shortcut()


if __name__ == "__main__":
    main()
