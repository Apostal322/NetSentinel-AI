"""Phase 8b confirmatory evaluation - implements docs/phase8b/RESEARCH_PLAN.md exactly.

Usage:
  uv run --extra torch python scripts/phase8b/confirm.py <out.json> <name>=<conn.log.labeled> ...
Fresh windows are cached under data/derived/phase8b_fresh/<name> (separate from development).
LightGBM is trained once on the 22 development captures (data/derived/phase8b, built by
dev_compare.py); 49-1 is never used.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scorers as S  # noqa: E402, N812
from dev_compare import dev_captures  # noqa: E402
from harness import domain_shift, load, operational, with_truth, zeek_windows  # noqa: E402

from netsentinel.incidents import IncidentTracker  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

FRESH = Path("data/derived/phase8b_fresh")
DEV = Path("data/derived/phase8b")
EXCLUDED = {"CTU-IoT-Malware-Capture-49-1"}


def clopper_pearson(k: int, n: int, a: float = 0.05):
    from scipy.stats import beta

    if n == 0:
        return None, None
    lo = 0.0 if k == 0 else float(beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a / 2, k + 1, n - k))
    return lo, hi


def boot_delta(end_ms, y, s1, s2, B=2000, block_ms=3_600_000, seed=0) -> dict:
    from sklearn.metrics import average_precision_score as ap

    blocks = ((end_ms - end_ms.min()) // block_ms).astype(np.int64)
    ids = np.unique(blocks)
    idx = [np.where(blocks == b)[0] for b in ids]
    rng = np.random.default_rng(seed)
    ds, skipped = [], 0
    for _ in range(B):
        pick = np.concatenate([idx[i] for i in rng.integers(0, len(ids), len(ids))])
        yy = y[pick]
        if yy.sum() == 0 or yy.sum() == len(yy):
            skipped += 1
            continue
        ds.append(ap(yy, s1[pick]) - ap(yy, s2[pick]))
    d = np.array(ds)
    return {"delta": float(ap(y, s1) - ap(y, s2)),
            "ci95": [float(np.quantile(d, 0.025)), float(np.quantile(d, 0.975))] if len(d) else None,
            "blocks": int(len(ids)), "resamples": int(len(d)), "skipped": skipped}  # fmt: skip


def ci_verdict(ci) -> str:
    if ci is None:
        return "not_testable"
    return "supported" if ci[0] > 0 else "refuted" if ci[1] < 0 else "inconclusive"


def testable(cal, ev, tr) -> dict:
    y = with_truth(ev.select("key", "win"), tr)["y"]
    return {"cal_windows": cal.height, "attack": int(y.sum()), "benign": int((~y).sum()),
            "ok": cal.height >= 60 and int(y.sum()) >= 5 and int((~y).sum()) >= 30}  # fmt: skip


def incidents(ev, tr, s, thr, hours) -> dict:
    w = with_truth(ev.select("key", "win", "window_start_ms", "window_end_ms", "n_flows"), tr)
    w = w.with_columns(pl.Series("score", s), pl.lit(thr).alias("threshold"),
                       pl.Series("anomalous", s > thr), pl.lit("device").alias("level"),
                       pl.lit(None, dtype=pl.List(pl.Utf8)).alias("explanation"))  # fmt: skip
    t = IncidentTracker("b6", "b6", 30, gap_s=300)
    t.add_windows(w)
    a = w.filter(pl.col("anomalous"))
    lab: dict[str, list[bool]] = {}
    for r in a.iter_rows(named=True):
        iid = t._by_window[("device", str(r["key"]), int(r["window_end_ms"]))]
        lab.setdefault(iid, []).append(bool(r["y"]))
    incs = list(lab.values())
    n_al = a.height
    ww = sum(sum(x) for x in incs) / n_al if n_al else None
    return {"alerts": n_al, "incidents": len(incs),
            "alert_reduction": n_al / len(incs) if incs else None,
            "window_weighted_purity": ww,
            "incident_mean_purity": float(np.mean([np.mean(x) for x in incs])) if incs else None,
            "benign_only_incidents_per_h": sum(not any(x) for x in incs) / hours if hours else None,
            "single_window_incidents": sum(len(x) == 1 for x in incs)}  # fmt: skip


def dev_sources() -> list[dict]:
    out = []
    for name in dev_captures():
        p = DEV / name
        if name in EXCLUDED or not (p / "meta.json").exists():
            continue
        d = load(p)
        if d["cal_clean"].height:
            out.append({"cal": d["cal_clean"], "ev": d["eval_clean"], "truth": d["truth"]})
    return out


def evaluate(name: str, d: dict, models: dict, src_benign: pl.DataFrame) -> dict:
    tr, hours, fa = d["truth"], d["meta"]["eval_hours"], d["meta"]["first_attack_ms"]
    out: dict = {"meta": {k: d["meta"][k] for k in ("flows", "eval_hours", "records", "stream")
                          if k in d["meta"]}}  # fmt: skip
    for variant in ("clean", "unlabelled"):
        cal, ev = d[f"cal_{variant}"], d[f"eval_{variant}"]
        t = testable(cal, ev, tr)
        r: dict = {"testability": t, "scores": {}}
        if cal.height >= 60 and ev.height:
            sc = dict(S.unsupervised(cal, ev, tr, hours))
            sc["robust_z_product"] = S.product(cal, ev)
            for key, (model, src_thr) in models.items():
                s, loc_thr = S.lgbm_score(model, cal, ev, key == "lgbm_local")
                sc[f"{key}@source"] = (s, src_thr)
                sc[f"{key}@local"] = (s, loc_thr)
            r["metrics"] = {k: operational(ev, tr, s, thr, hours, fa) for k, (s, thr) in sc.items()}
            r["scores"] = sc
        out[variant] = r
    # ---------------------------------------------------------------- hypotheses
    H: dict = {}
    ev_c = with_truth(d["eval_clean"].select("key", "win", "window_end_ms"), tr)
    ev_u = with_truth(d["eval_unlabelled"].select("key", "win", "window_end_ms"), tr)

    def boot(variant, a, b):
        r = out[variant]
        if not r["testability"]["ok"] or a not in r["scores"] or b not in r["scores"]:
            return None
        e = ev_c if variant == "clean" else ev_u
        return boot_delta(e["window_end_ms"].to_numpy(), e["y"].to_numpy().astype(int),
                          r["scores"][a][0], r["scores"][b][0])  # fmt: skip

    b1 = boot("clean", "lgbm_raw@source", "robust_z")
    H["B1"] = {**(b1 or {}), "verdict": ci_verdict(b1["ci95"]) if b1 else "not_testable"}
    b2 = boot("unlabelled", "lgbm_raw@source", "robust_z_product")
    H["B2"] = {**(b2 or {}), "verdict": ci_verdict(b2["ci95"]) if b2 else "not_testable"}
    g, t_ = boot("clean", "robust_z", "gru"), boot("clean", "robust_z", "tcn")
    if g and t_ and g["ci95"] and t_["ci95"]:
        v = ("supported" if g["ci95"][0] > 0 and t_["ci95"][0] > 0 else
             "refuted" if g["ci95"][1] < 0 or t_["ci95"][1] < 0 else "inconclusive")  # fmt: skip
    else:
        v = "not_testable"
    H["B3"] = {"gru": g, "tcn": t_, "verdict": v}
    for hid, key, rule in (
        ("B4", "robust_z_product", "keeps"),
        ("B5", "lgbm_raw@source", "breaks"),
    ):
        r = out["clean"]
        if not r["testability"]["ok"]:
            H[hid] = {"verdict": "not_testable"}
            continue
        s, thr = r["scores"][key]
        y = ev_c["y"].to_numpy()
        a = s > thr
        k, n = int((a & ~y).sum()), int((~y).sum())
        lo, hi = clopper_pearson(k, n)
        fpr = k / n
        if rule == "keeps":
            v = ("supported" if fpr <= 0.03 and hi <= 0.05 else "refuted" if lo > 0.03
                 else "inconclusive")  # fmt: skip
        else:
            v = "supported" if lo > 0.01 else "refuted" if hi <= 0.01 else "inconclusive"
        H[hid] = {"fpr": fpr, "ci95": [lo, hi], "false_alerts": k, "benign_windows": n,
                  "false_alerts_per_h": k / hours if hours else None, "verdict": v}  # fmt: skip
    r = out["clean"]
    if r["testability"]["ok"]:
        s, thr = r["scores"]["robust_z_product"]
        inc = incidents(d["eval_clean"], tr, s, thr, hours)
        if inc["incidents"] < 5:
            v = "not_testable"
        else:
            v = ("supported" if (inc["window_weighted_purity"] or 0) >= 0.8
                 and (inc["alert_reduction"] or 0) >= 5 else "refuted")  # fmt: skip
        H["B6"] = {**inc, "verdict": v}
    else:
        H["B6"] = {"verdict": "not_testable"}
    ben = ev_c.filter(~pl.col("y"))
    feats = d["eval_clean"].join(ben.select("key", "win"), on=["key", "win"], how="inner")
    out["domain_shift"] = domain_shift(src_benign, feats) if feats.height else None
    for variant in ("clean", "unlabelled"):
        out[variant].pop("scores", None)
    out["hypotheses"] = H
    return out


def aggregate(per: dict) -> dict:
    agg = {}
    for h in ("B1", "B2", "B3", "B4", "B5", "B6"):
        vs = [per[c]["hypotheses"][h]["verdict"] for c in per]
        tested = [v for v in vs if v != "not_testable"]
        sup, ref = tested.count("supported"), tested.count("refuted")
        if sup >= 2 and ref == 0:
            overall = "replicated"
        elif len(tested) == 1 and sup == 1:
            overall = "supported, n = 1"
        elif tested and ref > len(tested) / 2:
            overall = "refuted"
        elif not tested:
            overall = "not_testable"
        else:
            overall = "mixed"
        agg[h] = {"per_capture": dict(zip(per, vs, strict=True)), "overall": overall}
    return agg


def main() -> None:
    out_path = Path(sys.argv[1])
    caps = dict(a.split("=", 1) for a in sys.argv[2:])
    t0 = time.perf_counter()
    sources = dev_sources()
    models = {"lgbm_raw": S.lgbm_fit(sources, False), "lgbm_local": S.lgbm_fit(sources, True)}
    src_benign = pl.concat([s["cal"] for s in sources], how="diagonal_relaxed")
    per = {}
    for name, path in caps.items():
        p = FRESH / name
        d = load(p) if (p / "meta.json").exists() else zeek_windows(Path(path), p)
        per[name] = evaluate(name, d, models, src_benign)
        print(name, {h: v["verdict"] for h, v in per[name]["hypotheses"].items()}, flush=True)
    res = {"plan": "docs/phase8b/RESEARCH_PLAN.md", "dev_sources": len(sources),
           "per_capture": per, "aggregate": aggregate(per),
           "meta": {"seconds": round(time.perf_counter() - t0, 1),
                    "peak_rss_mb": peak_rss_mb()}}  # fmt: skip
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps(res["aggregate"], indent=1), res["meta"])


if __name__ == "__main__":
    main()
