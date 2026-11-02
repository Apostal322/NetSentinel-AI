"""Phase 8j data-integrity audit [E]: how much do labels shape the Phase 8i calibration?

The registered Phase 8i calibration (PREREGISTRATION.md section 2) uses labels in three places:
  L1  flow labels of the calibration period: the "clean" variant keeps benign-labelled flows only;
  L2  entity labels of BOTH periods: hosts that attack in calibration OR evaluation are dropped
      (future evaluation labels choose the calibration hosts);
  L3  evaluation features: `new_dst_frac` in evaluation is computed against destination sets
      learned on the clean calibration, so the evaluation windows also inherit L1.
A deployed detector has none of them. This script scores the same target windows under four
calibration protocols with one source model per target network (seed 0, the Phase 8i B-raw
setup) and reports the T0 threshold, the realised FPR on verified-benign evaluation windows,
recall, and how many attack windows and attacker hosts each hold-out contains:

  P0_oracle   clean calibration, drop attackers of either period, clean evaluation (Phase 8i)
  P1_past     clean calibration, drop calibration-period attackers only, clean evaluation
              (labels of the past only: what an analyst-vetted calibration period would give)
  P2_none     unlabelled calibration, no exclusion, unlabelled evaluation (no labels at all)
  P3_screen   P2, minus hosts whose median calibration source score exceeds the source model's
              own 99th-percentile benign score (label-free screening by the source model)

The evaluation labels (verified benign = hosts that never attack; attack = attack windows) are
identical across protocols and are used for metrics only. The deployable protocol P1u
(all-flow windows minus calibration-period attackers) is derived from the saved P2 scores by
leakage_p1u.py. NF-BoT-IoT-v3 is consumed: it is a
development network in Phase 8j and never confirmation. P0 must reproduce the Phase 8i seed-0
A1 numbers; the script checks that.

Output: reports/phase8j/leakage_audit.json, data/derived/phase8j/scores/<domain>__<protocol>.npz
(--seed k > 0: leakage_audit_seed<k>.json and <domain>__<protocol>__seed<k>.npz)
Usage: uv run python scripts/run_capped.py -- uv run python scripts/phase8j/leakage_audit.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
import common as C  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
PROTOCOLS = ("P0_oracle", "P1_past", "P2_none", "P3_screen")
OUT = Path("reports/phase8j/leakage_audit.json")
SCORES = Path("data/derived/phase8j/scores")
PHASE8I = {"nfbot": Path("reports/phase8i/confirm/exp_a")}
SEED = 0  # set by --seed


def out_path(seed: int) -> Path:
    return OUT if seed == 0 else OUT.with_name(f"leakage_audit_seed{seed}.json")


def score_path(name: str, protocol: str, seed: int) -> Path:
    tail = "" if seed == 0 else f"__seed{seed}"
    return SCORES / f"{name.replace('/', '__')}__{protocol}{tail}.npz"


def targets(nets: dict[str, dict[str, dict]]) -> list[tuple[str, dict, dict]]:
    """The Phase 8i A1 targets (exp_a.folds) plus N4; sources = every other DEVELOPMENT network."""
    out = []
    for tnet in NETWORKS:
        srcs = {k: v for n in C.DEV_NETWORKS if n != tnet for k, v in nets[n].items()}
        for k, v in nets[tnet].items():
            if tnet == "nfcic" and k.split("/")[1] not in C.PRIMARY_N1 + C.SECONDARY_N1:
                continue
            if C.attack_eligible(v):
                out.append((k, v, srcs))
    return out


def unlabelled(d: dict) -> tuple[pl.DataFrame, pl.DataFrame]:
    """(calibration, evaluation) windows built from all flows, with the evaluation labels of the
    registered evaluation joined on (key, win) for the metrics only."""
    base = C.DERIVED / d["network"] / d["name"]
    cal = pl.read_parquet(base / "cal_unlabelled.parquet").sort("win", "key")
    ev = pl.read_parquet(base / "eval_unlabelled.parquet")
    lab = d["ev"].select("key", "win", "y", "benign", "noisy")
    ev = ev.join(lab, on=["key", "win"], how="inner").sort("win", "key")
    if ev.height != d["ev"].height:
        raise SystemExit(
            f"{d['name']}: unlabelled evaluation windows do not match the labelled ones"
        )
    return cal, ev


def composition(hold: pl.DataFrame, cal_truth: pl.DataFrame, ev_attackers: set[str]) -> dict:
    """Hold-out size, hosts, effective hosts, and (audit only) its attack content."""
    m = hold.group_by("key").len()["len"].to_numpy().astype(float)
    y = hold.join(cal_truth, on=["key", "win"], how="left")["y"].fill_null(False).to_numpy()
    keys = set(hold["key"].unique().to_list())
    return {"n_hold": hold.height, "hosts": len(m),
            "eff_hosts": float(m.sum() ** 2 / (m**2).sum()) if len(m) else 0.0,
            "top_host_share": float(m.max() / m.sum()) if len(m) else None,
            "attack_windows": int(y.sum()), "attack_share": float(y.mean()) if len(y) else None,
            "future_attacker_hosts": len(keys & ev_attackers),
            "future_attacker_windows": int(hold["key"].is_in(list(ev_attackers)).sum())}  # fmt: skip


def run_domain(name: str, d: dict, model, src_thr: float) -> dict:
    base = C.DERIVED / d["network"] / d["name"]
    ct = pl.read_parquet(base / "cal_truth.parquet") if (base / "cal_truth.parquet").exists() \
        else pl.DataFrame(schema={"key": pl.Utf8, "win": pl.Int64, "y": pl.Boolean})  # fmt: skip
    cal_att = set(ct.filter(pl.col("y"))["key"].unique().to_list())
    clean = pl.read_parquet(base / "cal_clean.parquet").sort("win", "key")
    cal_u, ev_u = unlabelled(d)

    def score(df: pl.DataFrame) -> np.ndarray:
        return model.predict_proba(C.S._x(df))[:, 1]

    s_cal_u = score(cal_u)
    med = cal_u.with_columns(pl.Series("s", s_cal_u)).group_by("key").agg(pl.col("s").median())
    screened = set(med.filter(pl.col("s") > src_thr)["key"].to_list())
    cal = {"P0_oracle": d["cal"], "P1_past": clean.filter(~pl.col("key").is_in(list(cal_att))),
           "P2_none": cal_u, "P3_screen": cal_u.filter(~pl.col("key").is_in(list(screened)))}  # fmt: skip
    ev = {"P0_oracle": d["ev"], "P1_past": d["ev"], "P2_none": ev_u, "P3_screen": ev_u}
    out = {"cal_attackers": sorted(cal_att), "eval_attackers": sorted(d["attackers"]),
           "screened_hosts": len(screened), "screened_attackers": len(screened & cal_att),
           "protocols": {}}  # fmt: skip
    SCORES.mkdir(parents=True, exist_ok=True)
    for p in PROTOCOLS:
        c = cal[p]
        hold = c.filter(pl.col("win") >= C.S.split_cut(c))
        s_hold, s_ev = score(hold), score(ev[p])
        thr, _ = C.t0(s_hold)
        tgt = {**d, "ev": ev[p]}
        met = C.evaluate(tgt, s_ev, thr)
        out["protocols"][p] = {**composition(hold, ct, d["attackers"]),
                               **{k: met.get(k) for k in ("threshold", "fpr", "window_recall",
                                  "false_alerts_per_h", "entity_recall", "roc_auc",
                                  "oracle_recall_at_fpr1")}}  # fmt: skip
        np.savez_compressed(score_path(name, p, SEED),
                            s_hold=s_hold, hold_key=hold["key"].to_numpy().astype(str),
                            hold_win=hold["win"].to_numpy(), s_ev=s_ev)  # fmt: skip
    ref = (
        PHASE8I.get(d["network"], Path("reports/phase8i/exp_a")) / f"{name.replace('/', '__')}.json"
    )
    a1 = json.loads(ref.read_text("utf-8"))["seeds"][str(SEED)]
    p0 = out["protocols"]["P0_oracle"]
    out["reproduces_phase8i"] = bool(np.isclose(p0["threshold"], a1["T0"], rtol=1e-6)
                                     and np.isclose(p0["fpr"], a1["A1"]["fpr"]))  # fmt: skip
    return out


def main() -> None:
    import argparse

    global SEED
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    SEED = ap.parse_args().seed
    t0 = time.perf_counter()
    nets = {n: C.load_network(n) for n in NETWORKS}
    cache: dict[tuple, tuple] = {}
    res = {"seed": SEED, "domains": {}}
    for name, d, srcs in targets(nets):
        key = tuple(sorted(srcs))
        if key not in cache:
            model, src_thr, _ = C.fit_source(srcs, SEED, C.Rep("raw"))
            cache[key] = (model, src_thr)
        res["domains"][name] = run_domain(name, d, *cache[key])
        print(name, {p: round(v["fpr"], 4) for p, v in res["domains"][name]["protocols"].items()},
              res["domains"][name]["reproduces_phase8i"], flush=True)  # fmt: skip
    res["seconds"] = round(time.perf_counter() - t0, 1)
    res["peak_rss_mb"] = peak_rss_mb()
    C.dump(out_path(SEED), res)


if __name__ == "__main__":
    main()
