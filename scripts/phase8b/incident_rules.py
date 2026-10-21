"""Phase 8b: why did incident aggregation fail (P8-H3), and which reportability rule is best on
DEVELOPMENT data? Selection rule: docs/phase8b/DEVELOPMENT_LOG.md (fixed before running).

Per development capture (cached windows, clean calibration, product robust_z scores):
alerts -> incidents (gap 300 s) -> for each rule R(k, r): reportable incidents, benign-only
reportable incidents per hour, purity (incident-mean and window-weighted), attacking-entity
recall, delay from the entity's first attack flow to its first reportable incident.

Usage: uv run python scripts/phase8b/incident_rules.py
"""

from __future__ import annotations

import itertools
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scorers as S  # noqa: E402, N812
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402

from netsentinel.incidents import IncidentTracker  # noqa: E402

OUT = Path("reports/phase8b/incident_rules.json")
RULES = list(itertools.product((1, 2, 3), (1.5, 2.0, 3.0, 5.0, math.inf)))
GAP_S = 300


def incidents_for(d: dict):
    cal, ev, tr = d["cal_clean"], d["eval_clean"], d["truth"]
    if cal.height < 60 or not ev.height:
        return None
    s, thr = S.product(cal, ev)
    w = with_truth(ev.select("key", "win", "window_start_ms", "window_end_ms", "n_flows"), tr)
    w = w.with_columns(pl.Series("score", s), pl.lit(thr).alias("threshold"),
                       pl.Series("anomalous", s > thr), pl.lit("device").alias("level"),
                       pl.lit(None, dtype=pl.List(pl.Utf8)).alias("explanation"))  # fmt: skip
    t = IncidentTracker("dev", "dev", 30, gap_s=GAP_S)
    t.add_windows(w)
    y = {(str(k), int(wi)): bool(v) for k, wi, v in w.select("key", "win", "y").iter_rows()}
    rows = []
    for inc in t.incidents():
        # anomalous windows of this incident, in time order, with labels and ratios
        a = w.filter(pl.col("anomalous") & (pl.col("key") == inc.entity)
                     & (pl.col("window_start_ms") >= inc.first_window_start_ms)
                     & (pl.col("window_end_ms") <= inc.last_window_end_ms)).sort("win")  # fmt: skip
        labels = [y[(inc.entity, int(x))] for x in a["win"].to_list()]
        ratios = (a["score"] / thr).to_list()
        rows.append({"entity": inc.entity, "ends": a["window_end_ms"].to_list(), "labels": labels,
                     "ratios": ratios})  # fmt: skip
    return {"incidents": rows, "hours": d["meta"]["eval_hours"],
            "first_attack": d["meta"]["first_attack_ms"], "alerts": int(w["anomalous"].sum()),
            "attack_entities": set(d["meta"]["first_attack_ms"])}  # fmt: skip


def apply_rule(info: dict, k: int, r: float) -> dict:
    rep, benign_only, purity, ww_num, ww_den = 0, 0, [], 0, 0
    first_rep: dict[str, int] = {}
    for inc in info["incidents"]:
        when = None  # end of the window at which the incident becomes reportable
        for i, (end, ratio) in enumerate(zip(inc["ends"], inc["ratios"], strict=True)):
            if i + 1 >= k or ratio >= r:
                when = end
                break
        if when is None:
            continue
        rep += 1
        lab = inc["labels"]
        purity.append(float(np.mean(lab)))
        ww_num += sum(lab)
        ww_den += len(lab)
        if not any(lab):
            benign_only += 1
        elif inc["entity"] in info["first_attack"]:
            e = inc["entity"]
            first_rep[e] = min(first_rep.get(e, when), when)
    delays = [(first_rep[e] - int(info["first_attack"][e])) / 1000 for e in first_rep]
    return {"reportable": rep, "benign_only": benign_only, "purity_mean": purity,
            "ww": (ww_num, ww_den), "entities_detected": len(first_rep), "delays": delays}  # fmt: skip


def main() -> None:
    caps = dev_captures()
    infos = {}
    for name in caps:
        out = Path("data/derived/phase8b") / name
        if (out / "meta.json").exists():
            info = incidents_for(load(out))
            if info:
                infos[name] = info
    # diagnosis of the R(1, inf) incidents (Phase 8 behaviour)
    diag = defaultdict(lambda: {"incidents": 0, "benign_only": 0})
    for info in infos.values():
        for inc in info["incidents"]:
            n = len(inc["labels"])
            b = "1" if n == 1 else "2-3" if n <= 3 else "4+"
            diag[b]["incidents"] += 1
            diag[b]["benign_only"] += int(not any(inc["labels"]))
    hours_benign = sum(i["hours"] for i in infos.values())
    ents = sum(len(i["attack_entities"]) for i in infos.values())
    res = {}
    for k, r in RULES:
        agg = {"reportable": 0, "benign_only": 0, "purity": [], "ww": [0, 0], "det": 0,
               "delays": []}  # fmt: skip
        per = {}
        for name, info in infos.items():
            a = apply_rule(info, k, r)
            per[name] = {"reportable": a["reportable"], "benign_only": a["benign_only"],
                         "per_h": a["benign_only"] / info["hours"] if info["hours"] else None}  # fmt: skip
            agg["reportable"] += a["reportable"]
            agg["benign_only"] += a["benign_only"]
            agg["purity"] += a["purity_mean"]
            agg["ww"][0] += a["ww"][0]
            agg["ww"][1] += a["ww"][1]
            agg["det"] += a["entities_detected"]
            agg["delays"] += a["delays"]
        res[f"R({k},{r})"] = {
            "k": k, "r": r, "reportable": agg["reportable"],
            "benign_only_per_h_pooled": agg["benign_only"] / hours_benign,
            "mean_purity": float(np.mean(agg["purity"])) if agg["purity"] else None,
            "window_weighted_purity": agg["ww"][0] / agg["ww"][1] if agg["ww"][1] else None,
            "entity_recall": agg["det"] / ents if ents else None,
            "median_delay_s": float(np.median(agg["delays"])) if agg["delays"] else None,
            "per_capture": per}  # fmt: skip
    base = res["R(1,inf)"]
    ok = {n: v for n, v in res.items()
          if v["entity_recall"] >= 0.95 * base["entity_recall"]
          and (v["median_delay_s"] or 0) - (base["median_delay_s"] or 0) <= 60}  # fmt: skip
    chosen = min(ok, key=lambda n: (ok[n]["benign_only_per_h_pooled"], ok[n]["k"], -ok[n]["r"]))
    out = {"diagnosis_R1inf_by_size": dict(diag), "captures": sorted(infos),
           "eval_hours_pooled": hours_benign, "attacking_entities": ents, "rules": res,
           "selected": chosen,
           "rule_text": "docs/phase8b/DEVELOPMENT_LOG.md"}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, default=str), "utf-8")
    print("diagnosis (Phase 8 behaviour):", dict(diag))
    for n, v in sorted(res.items(), key=lambda kv: kv[1]["benign_only_per_h_pooled"]):
        print(f"{n:10s} benign/h={v['benign_only_per_h_pooled']:.3f} reportable={v['reportable']} "
              f"purity={v['mean_purity']} ww={v['window_weighted_purity']} "
              f"recall={v['entity_recall']} delay={v['median_delay_s']}")  # fmt: skip
    print("selected:", chosen)


if __name__ == "__main__":
    main()
