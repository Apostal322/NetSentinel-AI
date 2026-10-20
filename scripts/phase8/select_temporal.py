"""Apply the 8B selection rule (fixed in docs/phase8/DEVELOPMENT_LOG.md before the comparison)
to reports/phase8/temporal_{iot23,unsw}.json; writes reports/phase8/temporal_selection.json.

Usage: uv run python scripts/phase8/select_temporal.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

R = Path("reports/phase8")
TARGET = 0.01


def units(level: str = "device", variant: str = "clean"):
    for f in ("temporal_iot23.json", "temporal_unsw.json"):
        p = R / f
        if not p.exists():
            continue
        for scen, r in json.loads(p.read_text("utf-8"))["results"].items():
            lv = r.get(variant, {}).get(level, {}) if isinstance(r.get(variant), dict) else {}
            cfg = {k: v for k, v in lv.items() if isinstance(v, dict) and "pr_auc" in v}
            if not cfg:
                continue
            any_m = next(iter(cfg.values()))
            att = any_m["attack_windows"]
            if att >= 5 and any_m["windows"] - att >= 30:
                yield scen, cfg


def summarise(level: str, variant: str) -> dict:
    table: dict[str, dict] = {}
    names = []
    for scen, cfg in units(level, variant):
        names.append(scen)
        for k, m in cfg.items():
            t = table.setdefault(k, {"pr_auc": [], "fpr": [], "us": [], "fa_h": [],
                                     "recall": [], "recall_at_fpr1": []})  # fmt: skip
            t["pr_auc"].append(m["pr_auc"])
            t["fpr"].append(m["fpr"])
            t["us"].append(m["score_us_per_window"])
            t["fa_h"].append(m["fa_per_h"])
            t["recall"].append(m["recall"])
            t["recall_at_fpr1"].append(m.get("recall_at_fpr1_oracle"))
    out = {}
    for k, t in table.items():
        out[k] = {"mean_pr_auc": float(np.mean(t["pr_auc"])),
                  "pr_auc": dict(zip(names, t["pr_auc"], strict=True)),
                  "median_fpr": float(np.median(t["fpr"])),
                  "median_fa_per_h": float(np.median(t["fa_h"])),
                  "mean_recall": float(np.mean(t["recall"])),
                  "mean_recall_at_fpr1_oracle": float(np.mean([x for x in t["recall_at_fpr1"]
                                                               if x is not None])),
                  "median_score_us": float(np.median(t["us"]))}  # fmt: skip
        out[k]["eligible"] = (out[k]["median_fpr"] <= 3 * TARGET
                              and out[k]["median_score_us"] <= 1000)  # fmt: skip
    return {"units": names, "configs": out}


def main() -> None:
    primary = summarise("device", "clean")
    cands = {k: v for k, v in primary["configs"].items()
             if v["eligible"] and not k.startswith("robust_z/")}  # fmt: skip
    best = max(cands, key=lambda k: cands[k]["mean_pr_auc"]) if cands else None
    base = primary["configs"].get("robust_z/base", {})
    sel = {"rule": "docs/phase8/DEVELOPMENT_LOG.md 8B", "primary": primary,
           "secondary_service_clean": summarise("service", "clean"),
           "secondary_device_unlabelled": summarise("device", "unlabelled"),
           "selected_candidate": best,
           "baseline": "robust_z/base",
           "dev_delta_pr_auc": (cands[best]["mean_pr_auc"] - base.get("mean_pr_auc", np.nan))
           if best else None}  # fmt: skip
    (R / "temporal_selection.json").write_text(json.dumps(sel, indent=1), "utf-8")
    print("units:", primary["units"])
    for k, v in sorted(primary["configs"].items(), key=lambda kv: -kv[1]["mean_pr_auc"]):
        print(f"{k:22s} prauc={v['mean_pr_auc']:.3f} fpr={v['median_fpr']:.4f} "
              f"fa/h={v['median_fa_per_h']:.1f} r@1%={v['mean_recall_at_fpr1_oracle']:.3f} "
              f"us={v['median_score_us']:.1f} eligible={v['eligible']}")  # fmt: skip
    print("selected:", best, "delta vs robust_z/base:", sel["dev_delta_pr_auc"])


if __name__ == "__main__":
    main()
