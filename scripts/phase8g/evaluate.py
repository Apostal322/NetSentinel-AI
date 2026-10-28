"""Phase 8g step 2: frozen evaluation of CTU-13 scenarios 9 and 10 (docs/phase8f/PREREG_CTU13.md).

Product components only:
- calibrate_windows (crossfit) -> BehaviorProfile -> save_profile;
- AnalysisPipeline (assessment context);
- profile.score, monitor.baseline_state, validity.assess_validity / shift_test;
- assessment.assess;
- the S5 gate of scripts/phase8f/recalibration_sim.py.

Truth comes from the README design documents only (configs/phase8g/ctu13.yaml):
- attack windows = test device windows of an initiator starting at or after its documented
  infection time;
- benign = test device windows of the documented normal hosts;
- everything else is unverified (pre-infection windows of initiators included).
No flow label is read here (provenance_audit.py does that afterwards).

A real run refuses to start unless scripts/phase8g, configs/phase8g and src are unchanged since
the frozen SHA recorded in reports/phase8g/registry.json.
Usage: uv run python scripts/phase8g/evaluate.py [--config path]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import polars as pl

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "phase8f"))
from windows import LEVELS, initiators, load_config, load_windows  # noqa: E402

from netsentinel.behavior import validity as V  # noqa: E402
from netsentinel.behavior.calibrate import calibrate_windows, save_profile  # noqa: E402
from netsentinel.behavior.monitor import baseline_state  # noqa: E402
from netsentinel.behavior.profile import (  # noqa: E402
    BehaviorProfile,
    _zs,
    fit_level_crossfit,
    window_scores,
)
from netsentinel.inference.assessment import assess  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

FROZEN_PATHS = ("scripts/phase8g", "configs/phase8g", "src")
MODES = ("vetted_benign", "unlabelled")  # primary, sensitivity (same calibration data)


def utc_ms(s: str) -> int:
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [float(max(0.0, c - h)), float(min(1.0, c + h))]


def check_frozen(registry: Path) -> str:
    """The frozen SHA must exist and the frozen paths must not differ from it."""
    reg = json.loads(registry.read_text("utf-8"))
    sha = reg.get("frozen_evaluation_code_sha")
    if not sha:
        raise SystemExit("registry has no frozen_evaluation_code_sha: refusing to run")
    diff = subprocess.run(["git", "diff", "--quiet", sha, "--", *FROZEN_PATHS])
    dirty = subprocess.run(["git", "status", "--porcelain", "--", *FROZEN_PATHS],
                           capture_output=True, text=True).stdout.strip()  # fmt: skip
    if diff.returncode != 0 or dirty:
        raise SystemExit(f"code differs from frozen {sha} in {FROZEN_PATHS}: refusing to run")
    return sha


# ----------------------------------------------------------------------------- calibration
def make_profile(cfg: dict, key: str, cal: dict, mode: str, meta: dict, out: Path):
    from netsentinel.inference.pipeline import AnalysisPipeline

    levels = calibrate_windows(cal, 0, target_fpr=cfg["target_fpr"],
                               min_windows=cfg["min_windows"], mode=mode,
                               threshold_method="crossfit")  # fmt: skip
    n_global = cal["global"]["win"].n_unique() if cal["global"].height else 0
    status = "baseline_ready" if n_global >= cfg["min_windows"] else "insufficient_history"
    g = levels.get("global")
    if status == "baseline_ready" and g is not None and not g.threshold_diag.get("reliable"):
        status = "baseline_provisional"
    known = set(pl.read_parquet(Path(cfg["derived_root"]) / key / "calibration_dst.parquet")[
        "dst"].to_list())  # fmt: skip
    period = {"start_utc_ms": meta["first_start_ms"], "end_utc_ms": meta["cut_ms"],
              "fit_end_utc_ms": meta["cut_ms"], "global_windows": n_global,
              "flows": meta["flows"]["cal_kept"]}  # fmt: skip
    prof = BehaviorProfile(window_s=cfg["window_s"], mode=mode, target_fpr=cfg["target_fpr"],
                           min_windows=cfg["min_windows"], top_k=2, levels=levels,
                           known_dst=known, status=status, period=period,
                           diagnostics={"threshold_method": "crossfit",
                                        "split": "PREREG_CTU13 option (a)"})  # fmt: skip
    statement = ("vetted by the documented experiment design: every flow to or from the "
                 "documented infected VMs excluded (PREREG_CTU13)")  # fmt: skip
    cal_dir = save_profile(prof, out, sources=[{"scenario": key, "id": meta["id"]}],
                           operator_statement=statement)  # fmt: skip
    pipe = AnalysisPipeline(None, cal_dir)
    return prof, pipe


# ----------------------------------------------------------------------------- metrics
def truth(cfg: dict, key: str, dev: pl.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    sc = cfg["scenarios"][key]
    inf = {cfg["initiator_names"][n]: utc_ms(t) for n, t in sc["infected_utc"].items()}
    keys = dev["key"].to_list()
    start = dev["window_start_ms"].to_numpy()
    y = np.array([k in inf and s >= inf[k] for k, s in zip(keys, start, strict=True)])
    ben = np.array([k in set(sc["benign"]) for k in keys])
    return y, ben, np.array(keys, dtype=object)


def detection(alert, y, ben, keys, end, inf_ms, hours, costs) -> dict:
    unv = ~y & ~ben
    ents = sorted({k for k in keys[y]})
    det, delays = [], {}
    for a in ents:
        hit = (keys == a) & y & alert
        if hit.any():
            det.append(a)
            delays[a] = float((end[hit].min() - inf_ms[a]) / 1000)
    fa = int((alert & ben).sum())
    missed = int((y & ~alert).sum())
    return {"initiators_with_attack_windows": len(ents), "initiators_detected": len(det),
            "initiators_ci95": wilson(len(det), len(ents)),
            "attack_windows": int(y.sum()), "attack_windows_detected": int((alert & y).sum()),
            "attack_window_recall": float(alert[y].mean()) if y.any() else None,
            "delay_s_from_infection": delays,
            "median_delay_s": float(np.median(list(delays.values()))) if delays else None,
            "benign_windows": int(ben.sum()), "benign_false_alerts": fa,
            "benign_fpr": float(fa / ben.sum()) if ben.any() else None,
            "benign_false_alerts_per_h": fa / hours if hours else None,
            "unverified_windows": int(unv.sum()),
            "unverified_alerts_per_h": float((alert & unv).sum() / hours) if hours else None,
            "cost": {str(c): missed * c + fa for c in costs}}  # fmt: skip


def bootstrap(alert, y, ben, end, cut, cfg) -> dict:
    blk = (end - cut) // int(cfg["bootstrap_block_minutes"] * 60_000)
    ids = np.unique(blk)
    out = {"blocks": int(len(ids)), "status": "inference" if len(ids) >= 10 else "descriptive"}
    rng = np.random.default_rng(cfg["seed"])
    idx = {b: np.where(blk == b)[0] for b in ids}
    rec, fpr = [], []
    for _ in range(cfg["bootstrap_resamples"]):
        take = np.concatenate([idx[b] for b in rng.choice(ids, len(ids), replace=True)])
        yy, bb, aa = y[take], ben[take], alert[take]
        if yy.any():
            rec.append(aa[yy].mean())
        if bb.any():
            fpr.append(aa[bb].mean())
    for name, v in (("attack_window_recall_ci95", rec), ("benign_fpr_ci95", fpr)):
        out[name] = [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None
    return out


def s1_s5(cfg, prof_dev, dev, y, ben, keys, seg, hours) -> dict:
    """S1 fixed vs S5 candidate + gate (Phase 8f), device level, 1 h segments."""
    from recalibration_sim import gate  # the frozen Phase 8f gate

    res = {}
    for strat in ("S1", "S5"):
        prof = prof_dev
        alert = np.zeros(dev.height, bool)
        absorbed = acts = reviews = 0
        for k in np.unique(seg):
            m = seg == k
            part = dev.filter(pl.Series(m))
            alert[m] = window_scores(_zs(prof, part), 2) > prof.threshold
            if strat == "S5" and (k + 1) % cfg["refit_every_segments"] == 0:
                recent = (seg > k - cfg["refit_every_segments"]) & (seg <= k)
                cand_df = dev.filter(pl.Series(recent))
                cand = fit_level_crossfit(cand_df, "device", cfg["target_fpr"],
                                          cfg["min_windows"], "vetted_benign")  # fmt: skip
                ok, _ = gate(prof, cand_df)
                if ok and cand.pooled is not None and cand.threshold_diag.get("reliable"):
                    prof, acts = cand, acts + 1
                    absorbed += int((recent & y).sum())
                else:
                    reviews += 1
        ents = sorted({k for k in keys[y]})
        det = sum(bool(((keys == a) & y & alert).any()) for a in ents)
        fa = int((alert & ben).sum())
        res[strat] = {"initiators_detected": det, "initiators": len(ents),
                      "benign_false_alerts_per_h": fa / hours if hours else None,
                      "attack_window_recall": float(alert[y].mean()) if y.any() else None,
                      "absorbed_attack_windows": absorbed,
                      "absorbed_share": absorbed / y.sum() if y.any() else 0.0,
                      "activations": acts, "reviews_required": reviews}  # fmt: skip
    a, b = res["S1"], res["S5"]
    res["V4_success"] = bool(b["initiators_detected"] >= a["initiators_detected"]
                             and b["absorbed_share"] <= 0.01
                             and (b["benign_false_alerts_per_h"] or 0)
                             <= (a["benign_false_alerts_per_h"] or 0))  # fmt: skip
    return res


def split_ref(ref: dict) -> tuple[dict, dict]:
    idx = np.arange(len(ref["block"]))
    return tuple({k: np.asarray(v)[idx % 2 == r] for k, v in ref.items()} for r in (0, 1))


# ----------------------------------------------------------------------------- per scenario
def scenario(cfg: dict, key: str, workdir: Path) -> dict:
    mp = Path(cfg["derived_root"]) / key / "meta.json"
    if not mp.exists():
        return {"status": "declared failed: window build did not complete"}
    meta = json.loads(mp.read_text("utf-8"))
    if str(meta.get("acceptance", "")).startswith("failed"):  # amendment A2
        return {"status": f"declared failed (A2): {meta['acceptance']}",
                "lateness_s": meta.get("lateness_s")}  # fmt: skip
    sc = cfg["scenarios"][key]
    t0 = time.perf_counter()
    cal = {lv: load_windows(cfg, key, "cal", lv) for lv in LEVELS}
    test = {lv: load_windows(cfg, key, "test", lv) for lv in LEVELS}
    cut, hours = meta["cut_ms"], meta["test_hours"]
    align = abs(meta["first_start_ms"] - utc_ms(sc["capture_start_utc"])) / 1000
    aligned = align <= cfg["time_alignment_tolerance_s"]
    inf_ms = {cfg["initiator_names"][n]: utc_ms(t) for n, t in sc["infected_utc"].items()}
    out: dict = {"id": sc["id"], "botnet": sc["botnet"], "test_hours": hours,
                 "calibration_flows": meta["flows"], "telemetry_health": meta["telemetry_health"],
                 "time_alignment_s": align, "time_aligned": aligned,
                 "calibration_has_initiator_keys": bool(
                     cal["device"].height and cal["device"]["key"].is_in(
                         list(initiators(cfg))).any()),
                 "modes": {}}  # fmt: skip
    test_all = pl.concat([d for d in test.values() if d.height], how="diagonal_relaxed")
    for mode in MODES:
        tm = time.perf_counter()
        prof, pipe = make_profile(cfg, key, cal, mode, meta, workdir / f"{key}_{mode}")
        scored = prof.score(test_all)
        dev = scored.filter(pl.col("level") == "device").sort("win", "key")
        devw = test["device"].join(dev.select("key", "win"), on=["key", "win"], how="semi").sort(
            "win", "key")  # fmt: skip
        y, ben, keys = truth(cfg, key, dev)
        end = dev["window_end_ms"].to_numpy()
        alert = dev["anomalous"].to_numpy().astype(bool)
        seg = (end - cut) // int(cfg["segment_hours"] * 3.6e6)
        r: dict = {"profile_status": prof.status, "levels": {
            lv: {"threshold": p.threshold, "threshold_reliable": p.threshold_diag.get("reliable"),
                 "own_profiles": len(p.keys), "tail_fallback_share": p.tail_fallback_share,
                 "validity_reference_blocks": 0 if p.validity_ref is None
                 else len(p.validity_ref["block"])}
            for lv, p in prof.levels.items()}}  # fmt: skip
        d = detection(alert, y, ben, keys, end, inf_ms, hours, cfg["costs"])
        if not aligned:
            for k in ("initiators_detected", "attack_window_recall", "delay_s_from_infection"):
                d[k] = "not evaluable: time alignment failed"
        r["V3"] = d
        r["Z_never_alert"] = detection(np.zeros_like(alert), y, ben, keys, end, inf_ms, hours,
                                       cfg["costs"])  # fmt: skip
        for lv in ("global", "service"):
            s = scored.filter(pl.col("level") == lv)
            r[f"{lv}_alerts_per_h"] = float(s["anomalous"].sum() / hours) if hours else None
        if mode == MODES[0]:
            r["bootstrap"] = bootstrap(alert, y, ben, end, cut, cfg)
            ctx = pipe.assessment_context(meta["telemetry_health"])
            segs = []
            for k in np.unique(seg):
                lo = cut + int(k * cfg["segment_hours"] * 3.6e6)
                hi = lo + int(cfg["segment_hours"] * 3.6e6)
                ss = scored.filter((pl.col("window_end_ms") >= lo) & (pl.col("window_end_ms") < hi))
                ts = test_all.filter((pl.col("window_end_ms") >= lo)
                                     & (pl.col("window_end_ms") < hi))  # fmt: skip
                bs = baseline_state(prof, ss)["state"]
                v = V.assess_validity(prof, windows=ts, now_ms=hi,
                                      telemetry_health=meta["telemetry_health"], seed=int(k))  # fmt: skip
                m = seg == k
                shift_only = ("confirmed_shift" if v["drift_detected"] else "possible_shift"
                              if "possible_shift" in v["conditions"] else
                              ("valid" if v["shift_test"] == "tested" else "untestable"))  # fmt: skip
                norm = [assess(ctx, "unusual" if a else "benign", None,
                               "anomalous" if a else "normal", bs, int(e))["normality_supported"]
                        for a, e in zip(alert[m], end[m], strict=True)]  # fmt: skip
                segs.append({"segment": int(k), "baseline_state": bs, "validity": v["status"],
                             "shift_test_only": shift_only, "benign": int((m & ben).sum()),
                             "benign_false_alerts": int((m & ben & alert).sum()),
                             "attack_windows": int((m & y).sum()),
                             "normality_supported": int(sum(norm)), "device_windows": int(m.sum())})  # fmt: skip
            r["segments"] = segs
            r["normality_supported_share"] = (sum(s["normality_supported"] for s in segs)
                                              / max(1, sum(s["device_windows"] for s in segs)))  # fmt: skip
            ps = {}
            for lv, p in prof.levels.items():
                if p.validity_ref is not None:
                    a, b = split_ref(p.validity_ref)
                    t = V.shift_test(a, b, seed=1)
                    if t["status"] == "tested":
                        ps[lv] = t["p"]
            r["C1_null"] = {"levels_tested": len(ps), "confirmed": bool(ps) and
                            min(V.holm(ps).values()) < V.ALPHA_CONFIRMED}  # fmt: skip
            r["V4"] = s1_s5(cfg, prof.levels["device"], devw, y, ben, keys, seg, hours)
        r["seconds"] = time.perf_counter() - tm
        out["modes"][mode] = r
    out["seconds"] = time.perf_counter() - t0
    out["peak_rss_mb"] = peak_rss_mb()
    return out


def pooled_segments(res: dict) -> dict:
    """V1 and the descriptive V2 (C2/C3) over both scenarios' segments (primary mode);
    scenarios declared failed (A2) contribute nothing."""
    res = {k: r for k, r in res.items() if "modes" in r}
    segs = [s for r in res.values() for s in r["modes"][MODES[0]]["segments"]]
    out = {}
    for name, key, ok, flag in (("V1_baseline_state", "baseline_state", "monitoring",
                                 "drift_suspected"),
                                ("V2_full_assessor", "validity", "valid", "confirmed_shift"),
                                ("V2_shift_test_only", "shift_test_only", "valid",
                                 "confirmed_shift")):  # fmt: skip
        e = {}
        for st in (ok, flag):
            ss = [s for s in segs if s[key] == st]
            b, fa = sum(s["benign"] for s in ss), sum(s["benign_false_alerts"] for s in ss)
            e[st] = {"segments": len(ss), "benign": b, "false_alerts": fa,
                     "pooled_fpr": fa / b if b else None, "fpr_ci95": wilson(fa, b)}  # fmt: skip
        e["all_states"] = dict(zip(*np.unique([s[key] for s in segs], return_counts=True),
                                   strict=True)) if segs else {}  # fmt: skip
        e["all_states"] = {str(k): int(v) for k, v in e["all_states"].items()}
        out[name] = e
    v1 = out["V1_baseline_state"]["monitoring"]
    if v1["segments"] < 3:
        out["V1_verdict"] = "not evaluable (fewer than 3 monitoring segments)"
    else:
        ok = (v1["pooled_fpr"] or 0) <= 0.02 and v1["fpr_ci95"] and v1["fpr_ci95"][1] <= 0.03
        out["V1_verdict"] = "success" if ok else "failure"
    v = out["V2_shift_test_only"]
    c2 = v["valid"]["pooled_fpr"]
    c3 = (v["confirmed_shift"]["pooled_fpr"] / c2) if c2 and v["confirmed_shift"][
        "pooled_fpr"] is not None else None  # fmt: skip
    out["V2_descriptive"] = {"C1_null_confirmed": [r["modes"][MODES[0]]["C1_null"]
                                                   for r in res.values()],
                             "C2_valid_fpr": c2, "C3_ratio": c3,
                             "verdict": "not evaluable for adoption (no benign-only segments)"}  # fmt: skip
    return out


def run(cfg: dict, allow_unfrozen: bool = False) -> dict:
    reports = Path(cfg["reports_root"])
    sha = None if allow_unfrozen else check_frozen(reports / "registry.json")
    res = {}
    with tempfile.TemporaryDirectory(prefix="ns-8g-", ignore_cleanup_errors=True) as tmp:
        for key in cfg["scenarios"]:
            res[key] = scenario(cfg, key, Path(tmp))
    out = {"registration": "docs/phase8f/PREREG_CTU13.md", "frozen_code_sha": sha,
           "status": "complete", "scenarios": res, "pooled": pooled_segments(res),
           "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "results.json").write_text(json.dumps(out, indent=1, default=str), "utf-8")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/phase8g/ctu13.yaml")
    a = ap.parse_args()
    r = run(load_config(a.config))
    print(json.dumps(r["pooled"], indent=1, default=str))
