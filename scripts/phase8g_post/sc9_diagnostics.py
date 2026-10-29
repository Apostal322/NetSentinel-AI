"""Phase 8g post-hoc [R]: diagnosis of the frozen scenario 9 result (consumed CTU-13 data).

Works on the FROZEN window parts (data/derived/phase8g/scenario_9, code 121acbf) and the frozen
evaluation functions, so it explains the published numbers; it changes none of them. The
profile code is unchanged since 121acbf (git diff 121acbf -- src/netsentinel/behavior is
empty), so the profile is rebuilt identically; the run first checks that it reproduces the
published V3 / V4 numbers exactly.

Sections (docs/phase8g/ALERT_BURDEN_ANALYSIS.md, V4_FAILURE_ANALYSIS.md, FINAL_REPORT.md s.6):
  reproduction    published V3 / V4 numbers recomputed
  population      device windows by evidence category (verified benign, confirmed attack,
                  initiator before infection, label-only normal host, internal / external
                  background, unclassifiable)
  burden          alerts per hour, unique sources and destinations, ports, per-source
                  concentration, incidents (gap merge), temporal clustering, explanations,
                  severity, model scope (own profile vs pooled fallback)
  timeline        initiators before / after the documented infection
  v4              the S5 activation: gate statistics, candidate composition, own profiles
                  learned for initiators, segment-2 effect, per-entity admission alternatives
Usage: uv run python scripts/phase8g_post/sc9_diagnostics.py -> reports/phase8g_post/
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import numpy as np
import polars as pl
from scipy.stats import binom

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8g"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8f"))
from evaluate import detection, make_profile, truth, utc_ms  # noqa: E402
from recalibration_sim import T, gate  # noqa: E402
from windows import LEVELS, initiators, load_config, load_windows  # noqa: E402

from netsentinel.behavior.profile import (  # noqa: E402
    POOLED,
    _zs,
    fit_level_crossfit,
    window_scores,
)
from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.live import END  # noqa: E402

KEY = "scenario_9"
OUT = Path("reports/phase8g_post")
ARRIVAL = Path("data/derived/phase8g_post") / KEY / "arrival"
LABEL_ONLY_NORMAL = {"147.32.1.20"}  # From-Normal in the labels, not in the README design
INTERNAL = "147.32."
GAP_WINDOWS = 10  # incident gap 300 s (IncidentTracker default) / 30 s windows


def holm_flags(p: dict[str, float], alpha: float) -> set[str]:
    out, m = set(), len(p)
    for i, (k, v) in enumerate(sorted(p.items(), key=lambda x: x[1])):
        if v > alpha / (m - i):
            break
        out.add(k)
    return out


def categories(cfg: dict, dev: pl.DataFrame) -> np.ndarray:
    sc = cfg["scenarios"][KEY]
    y, ben, keys = truth(cfg, KEY, dev)
    init = initiators(cfg)
    cat = np.empty(len(keys), dtype=object)
    for i, k in enumerate(keys):
        if y[i]:
            cat[i] = "confirmed_attack"
        elif ben[i]:
            cat[i] = "verified_benign"
        elif k in init:
            cat[i] = "initiator_before_infection"
        elif k in LABEL_ONLY_NORMAL:
            cat[i] = "label_only_normal"
        elif not isinstance(k, str) or k.count(".") != 3:
            cat[i] = "unclassifiable"
        elif k.startswith(INTERNAL):
            cat[i] = "background_internal"
        else:
            cat[i] = "background_external"
    assert set(sc["benign"]) and len(cat) == dev.height
    return cat


def incidents(a: pl.DataFrame) -> pl.DataFrame:
    """Alerted windows -> incidents per key (a new one after a gap of > 300 s)."""
    return (a.sort("key", "win")
            .with_columns(((pl.col("win").diff().over("key").fill_null(GAP_WINDOWS + 1))
                           > GAP_WINDOWS).cum_sum().over("key").alias("inc"))
            .group_by("key", "inc")
            .agg(pl.len().alias("windows"), pl.col("win").min().alias("first"),
                 pl.col("win").max().alias("last"), pl.col("cat").first()))  # fmt: skip


def burden(dev: pl.DataFrame, hours: float, cut: int) -> dict:
    out: dict = {}
    a = dev.filter(pl.col("anomalous"))
    for c, g in sorted(dev.group_by("cat"), key=lambda x: x[0][0]):
        al = g.filter(pl.col("anomalous"))
        inc = incidents(al) if al.height else None
        expl = (al.select(pl.col("explanation").list.first()).to_series().value_counts()
                .sort("count", descending=True).head(5).to_dicts() if al.height else [])  # fmt: skip
        out[c[0]] = {
            "windows": g.height, "sources": g["key"].n_unique(), "alerts": al.height,
            "alert_rate": al.height / g.height if g.height else None,
            "alerts_per_h": al.height / hours, "alerted_sources": al["key"].n_unique(),
            "incidents": inc.height if inc is not None else 0,
            "incidents_per_h": (inc.height if inc is not None else 0) / hours,
            "windows_per_incident_median": float(inc["windows"].median()) if inc is not None
            else None,
            "pooled_fallback_share_of_alerts": float((al["model_scope"] == POOLED).mean())
            if al.height else None,
            "pooled_fallback_share_of_windows": float((g["model_scope"] == POOLED).mean()),
            "score_to_threshold_median": float((al["score"] / al["threshold"]).median())
            if al.height else None,
            "top_first_explanation": expl}  # fmt: skip
    unv = a.filter(pl.col("cat").is_in(["background_internal", "background_external",
                                        "initiator_before_infection", "label_only_normal",
                                        "unclassifiable"]))  # fmt: skip
    per_src = unv.group_by("key").len().sort("len", descending=True)
    tot = max(1, unv.height)
    minute = ((unv["window_end_ms"] - cut) // 60_000).to_numpy()
    n_min = int(np.ceil(hours * 60))
    cnt = np.bincount(minute.clip(0, n_min - 1), minlength=n_min) if len(minute) else np.zeros(1)
    out["unverified_alerts"] = {
        "alerts": unv.height, "alerts_per_h": unv.height / hours,
        "sources": per_src.height,
        "share_from_top_10_sources": float(per_src.head(10)["len"].sum() / tot),
        "share_from_top_100_sources": float(per_src.head(100)["len"].sum() / tot),
        "sources_with_one_alert": int((per_src["len"] == 1).sum()),
        "top_sources": per_src.head(10).to_dicts(),
        "incidents": incidents(unv).height if unv.height else 0,
        "per_minute": {"mean": float(cnt.mean()), "var": float(cnt.var()),
                       "fano": float(cnt.var() / cnt.mean()) if cnt.mean() else None,
                       "p50": float(np.median(cnt)), "p99": float(np.quantile(cnt, 0.99)),
                       "max": int(cnt.max())}}  # fmt: skip
    return out


def flows_of(alerted: pl.DataFrame, cut: int, init: set[str]) -> dict:
    """Destinations / ports of the flows inside alerted unverified device windows."""
    if not ARRIVAL.exists():
        return {"status": "arrival cache missing (stream_audit.py cache scenario_9)"}
    keys = alerted.select(pl.col("key").alias("IPV4_SRC_ADDR"), "win")
    f = (pl.scan_parquet(str(ARRIVAL / "part_*.parquet"))
         .filter(pl.col(END) >= cut)
         .select("IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL",
                 (pl.col(END) // 30_000).alias("win"))
         .join(keys.lazy(), on=["IPV4_SRC_ADDR", "win"], how="semi").collect())  # fmt: skip
    ports = (f.group_by("PROTOCOL", "L4_DST_PORT").len().sort("len", descending=True)
             .head(10).to_dicts())  # fmt: skip
    return {"flows": f.height, "unique_destinations": f["IPV4_DST_ADDR"].n_unique(),
            "share_to_internal_destinations": float(
                f["IPV4_DST_ADDR"].str.starts_with(INTERNAL).mean()) if f.height else None,
            "flows_to_initiators": int(f["IPV4_DST_ADDR"].is_in(list(init)).sum()),
            "sources_contacting_initiators": int(f.filter(
                pl.col("IPV4_DST_ADDR").is_in(list(init)))["IPV4_SRC_ADDR"].n_unique()),
            "top_protocol_ports": ports,
            "note": "flows of the 1,039 records the frozen stream dropped are included here"}  # fmt: skip


def timeline(cfg: dict, dev: pl.DataFrame, cut: int) -> dict:
    sc = cfg["scenarios"][KEY]
    inf = {cfg["initiator_names"][n]: utc_ms(t) for n, t in sc["infected_utc"].items()}
    out = {}
    for ip, t in sorted(inf.items(), key=lambda x: x[1]):
        g = dev.filter(pl.col("key") == ip)
        pre = g.filter(pl.col("window_start_ms") < t)
        post = g.filter(pl.col("window_start_ms") >= t)
        fa = g.filter(pl.col("anomalous"))
        out[ip] = {"infected_utc_ms": t, "infected_before_test": t < cut,
                   "windows_before_infection": pre.height,
                   "alerts_before_infection": int(pre["anomalous"].sum()),
                   "windows_after_infection": post.height,
                   "alert_rate_after": float(post["anomalous"].mean()) if post.height else None,
                   "first_alert_minus_infection_s": float((fa["window_end_ms"].min() - t) / 1000)
                   if fa.height else None,
                   "model_scope": g["model_scope"].unique().to_list()}  # fmt: skip
    pre_all = dev.filter(pl.col("cat") == "initiator_before_infection")
    newhost = dev.filter((pl.col("cat") == "background_internal")
                         & (pl.col("model_scope") == POOLED))  # fmt: skip
    out["summary"] = {
        "initiator_windows_before_infection": pre_all.height,
        "alert_rate_before_infection": float(pre_all["anomalous"].mean()) if pre_all.height
        else None,
        "alert_rate_after_infection": float(dev.filter(pl.col("cat") == "confirmed_attack")[
            "anomalous"].mean()),
        "internal_background_pooled_alert_rate": float(newhost["anomalous"].mean())
        if newhost.height else None,
        "internal_background_pooled_windows": newhost.height}  # fmt: skip
    return out


def v4(cfg: dict, prof, devw: pl.DataFrame, dev: pl.DataFrame, cut: int, hours: float) -> dict:
    """The S5 activation of the frozen run, step by step (evaluate.s1_s5 logic)."""
    end = dev["window_end_ms"].to_numpy()
    seg = (end - cut) // int(cfg["segment_hours"] * 3.6e6)
    y, ben, keys = truth(cfg, KEY, dev)
    cat = dev["cat"].to_numpy()
    p0 = prof.levels["device"]
    every = cfg["refit_every_segments"]
    k = every - 1  # the first (and only) due refit in 2.69 h: end of segment 1
    recent = (seg > k - every) & (seg <= k)
    cand_df = devw.filter(pl.Series(recent))
    s = window_scores(_zs(p0, cand_df), 2)
    n, al = len(s), int((s > p0.threshold).sum())
    pval = float(binom.sf(al - 1, n, T)) if al else 1.0
    hmax = float(np.max(p0.holdout_scores))
    ok, why = gate(p0, cand_df)
    cand = fit_level_crossfit(cand_df, "device", cfg["target_fpr"], cfg["min_windows"],
                              "vetted_benign")  # fmt: skip
    init = initiators(cfg)
    cur_alert = s > p0.threshold
    later = seg > k
    part = devw.filter(pl.Series(later))  # feature windows (dev holds the scores)
    a1 = window_scores(_zs(p0, part), 2) > p0.threshold
    a5 = window_scores(_zs(cand, part), 2) > cand.threshold
    yl, bl, kl = y[later], ben[later], keys[later]
    per_init = {}
    for ip in sorted(init):
        m = (kl == ip) & yl
        per_init[ip] = {"attack_windows": int(m.sum()),
                        "recall_S1": float(a1[m].mean()) if m.any() else None,
                        "recall_S5": float(a5[m].mean()) if m.any() else None,
                        "own_profile_in_S5": ip in cand.keys}  # fmt: skip
    # per-entity admission under the CURRENT baseline (one-sided binomial, Holm)
    ck = np.array(cand_df["key"].to_list(), dtype=object)
    per_key = (pl.DataFrame({"key": cand_df["key"], "a": cur_alert})
               .group_by("key").agg(pl.len().alias("n"), pl.col("a").sum().alias("x"))
               .filter(pl.col("n") >= cfg["min_windows"]))  # fmt: skip
    pv = {k_: float(binom.sf(x - 1, n_, T)) if x else 1.0
          for k_, n_, x in per_key.iter_rows()}  # fmt: skip
    flagged = holm_flags(pv, 0.01)
    keep = ~cand_df["key"].is_in(list(flagged)).to_numpy()
    q = fit_level_crossfit(cand_df.filter(pl.Series(keep)), "device", cfg["target_fpr"],
                           cfg["min_windows"], "vetted_benign")  # fmt: skip
    q = replace(q, keys={**q.keys, **{x: p0.keys[x] for x in flagged if x in p0.keys}})
    # QKC (as in v4_synthetic.py): a persistent entity WITHOUT an own profile in the current
    # baseline may not obtain one from unvetted data; transient sources stay in the pool
    new_persistent = set(per_key["key"].to_list()) - set(p0.keys)
    known = ~cand_df["key"].is_in(list(new_persistent)).to_numpy()
    kn = fit_level_crossfit(cand_df.filter(pl.Series(known & keep)), "device",
                            cfg["target_fpr"], cfg["min_windows"], "vetted_benign")  # fmt: skip
    kn = replace(kn, keys={**kn.keys, **{x: p0.keys[x] for x in flagged if x in p0.keys}})

    seg_hours = float((end[later].max() - end[later].min()) / 3.6e6) if later.any() else 0.0

    def seg2(p) -> dict:
        a = window_scores(_zs(p, part), 2) > p.threshold
        return {"attack_window_recall": float(a[yl].mean()),
                "initiators_detected": int(sum(bool((a & yl & (kl == ip)).any()) for ip in init)),
                "benign_false_alerts": int((a & bl).sum()),
                "unverified_alerts_per_h": float((a & ~yl & ~bl).sum() / max(seg_hours, 1e-9)),
                "own_profiles": len(p.keys), "threshold": p.threshold}  # fmt: skip

    cat_of = dict(zip(ck.tolist(), cat[recent].tolist(), strict=True))
    res = {
        "refit_after_segment": int(k), "candidate_windows": n,
        "gate": {"passed": ok, "reason": why, "alerts_under_current": al,
                 "alert_rate_under_current": al / n, "rate_limit": 2 * T,
                 "binomial_p": pval, "holdout_max": hmax, "strong_outlier_limit": 2 * hmax,
                 "max_candidate_score": float(s.max()), "current_threshold": p0.threshold},
        "candidate_composition": {c: int((cat[recent] == c).sum()) for c in np.unique(cat)},
        "attack_windows_in_candidate": int((recent & y).sum()),
        "attack_windows_in_candidate_alerted_by_current": int(cur_alert[y[recent]].sum()),
        "attack_share_of_candidate": float((recent & y).sum() / n),
        "initiator_alert_rate_under_current": float(cur_alert[np.isin(ck, list(init))].mean()),
        "own_profiles": {"current": len(p0.keys), "candidate": len(cand.keys),
                         "initiators_with_own_profile_current": sum(i in p0.keys for i in init),
                         "initiators_with_own_profile_candidate": sum(i in cand.keys
                                                                      for i in init)},
        "thresholds": {"current": p0.threshold, "candidate": cand.threshold,
                       "candidate_reliable": cand.threshold_diag.get("reliable"),
                       "candidate_tail_fallback_share": cand.tail_fallback_share},
        "later_segment": {"windows": int(later.sum()), "hours": seg_hours,
                          "attack_windows": int(yl.sum()), "per_initiator": per_init,
                          "S1_alerts_on_attack": int((a1 & yl).sum()),
                          "S5_alerts_on_attack": int((a5 & yl).sum()),
                          "S1_unverified_alerts": int((a1 & ~yl & ~bl).sum()),
                          "S5_unverified_alerts": int((a5 & ~yl & ~bl).sum())},
        "evidence_before_activation_unchanged": True,  # S5 scores segments 0-1 with p0
        "per_entity_admission": {
            "entities_tested": len(pv), "flagged_holm_0.01": len(flagged),
            "initiators_flagged": sorted(set(init) & flagged),
            "non_initiators_flagged": len(flagged - set(init)),
            "QKC_new_persistent_entities_left_out": len(new_persistent),
            "QKC_initiators_left_out": len(new_persistent & set(init)),
            "flagged_categories": {c: sum(cat_of[f] == c for f in flagged)
                                   for c in sorted({cat_of[f] for f in flagged})}},
        "alternatives_on_later_segment": {"S1_fixed": seg2(p0), "S5": seg2(cand),
                                          "QC_entity_quarantine_carry_over": seg2(q),
                                          "QKC_known_entities_only": seg2(kn)},
        "label": "[R] diagnosis on consumed data; alternatives are NOT validated here"}  # fmt: skip
    return res


def main() -> None:
    cfg = load_config(ROOT / "configs/phase8g/ctu13.yaml")
    meta = json.loads((Path(cfg["derived_root"]) / KEY / "meta.json").read_text("utf-8"))
    pub = json.loads(Path("reports/phase8g/results.json").read_text("utf-8"))
    pub = pub["scenarios"][KEY]["modes"]["vetted_benign"]
    cut, hours = meta["cut_ms"], meta["test_hours"]
    cal = {lv: load_windows(cfg, KEY, "cal", lv) for lv in LEVELS}
    test_dev = load_windows(cfg, KEY, "test", "device")
    with tempfile.TemporaryDirectory(prefix="ns-8g-diag-", ignore_cleanup_errors=True) as tmp:
        prof, _ = make_profile(cfg, KEY, cal, "vetted_benign", meta, Path(tmp) / "p")
    del cal
    dev = prof.score(test_dev).sort("win", "key")
    devw = test_dev.join(dev.select("key", "win"), on=["key", "win"], how="semi").sort(
        "win", "key")  # fmt: skip
    del test_dev
    y, ben, keys = truth(cfg, KEY, dev)
    end = dev["window_end_ms"].to_numpy()
    alert = dev["anomalous"].to_numpy().astype(bool)
    sc = cfg["scenarios"][KEY]
    inf_ms = {cfg["initiator_names"][n]: utc_ms(t) for n, t in sc["infected_utc"].items()}
    d = detection(alert, y, ben, keys, end, inf_ms, hours, cfg["costs"])
    rep = {k: (d[k], pub["V3"][k]) for k in ("initiators_detected", "attack_windows_detected",
                                             "benign_false_alerts", "unverified_alerts_per_h",
                                             "median_delay_s")}  # fmt: skip
    reproduced = all(a == b for a, b in rep.values())
    dev = dev.with_columns(pl.Series("cat", categories(cfg, dev)))
    unv_alerted = dev.filter(pl.col("anomalous") & ~pl.col("cat").is_in(
        ["confirmed_attack", "verified_benign"]))  # fmt: skip
    out = {"label": "[R] post-hoc diagnosis of the frozen scenario 9 result (consumed data)",
           "reproduction": {"published_vs_recomputed": rep, "exact": reproduced},
           "test_hours": hours,
           "population_and_burden": burden(dev, hours, cut),
           "unverified_alert_flows": flows_of(unv_alerted, cut, initiators(cfg)),
           "timeline": timeline(cfg, dev, cut),
           "v4": v4(cfg, prof, devw, dev, cut, hours),
           "peak_rss_mb": peak_rss_mb()}  # fmt: skip
    v = out["v4"]
    out["v4"]["reproduces_published"] = {
        "absorbed_attack_windows": (v["attack_windows_in_candidate"],
                                    pub["V4"]["S5"]["absorbed_attack_windows"]),
        "gate_passed": (v["gate"]["passed"], pub["V4"]["S5"]["activations"] == 1)}  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sc9_diagnostics.json").write_text(json.dumps(out, indent=1, default=str), "utf-8")
    print(json.dumps({"reproduction": out["reproduction"],
                      "v4_reproduces": out["v4"]["reproduces_published"]}, indent=1,
                     default=str))  # fmt: skip


if __name__ == "__main__":
    main()
