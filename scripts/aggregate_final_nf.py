"""Aggregate the one-shot NF final evaluation (reports/final/*.json) and apply the hypothesis
predicates exactly as pre-registered in docs/experiments/final_preregistration_nf.md (mean over
the 3 seeds). Writes reports/experiments/results_final_nf.{md,json}.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

FINAL = Path("reports/final")
OUT = Path("reports/experiments")
SETTINGS = {
    "final_unsw2unsw_nf_flow_ctx": "NF-UNSW in-domain",
    "final_ids2ids_nf_flow_ctx": "NF-IDS2018 in-domain",
    "final_ids2unsw_nf_flow_ctx": "NF-IDS2018 -> NF-UNSW, nf_flow_ctx",
    "final_ids2unsw_nf_portable_ctx": "NF-IDS2018 -> NF-UNSW, nf_portable_ctx",
    "final_unsw2ids_nf_flow_ctx": "NF-UNSW -> NF-IDS2018, nf_flow_ctx",
}
TRANSFER = ("final_ids2unsw_nf_flow_ctx", "final_ids2unsw_nf_portable_ctx",
            "final_unsw2ids_nf_flow_ctx")  # fmt: skip
SHOW = ("source_model_target_threshold", "normalized_target_threshold",
        "robust_subset_target_threshold", "target_robust_z_flow", "target_iforest_flow",
        "target_iforest_ctx", "target_autoencoder_flow", "target_autoencoder_flow_noshortcut",
        "target_autoencoder_all")  # fmt: skip


def load() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for pre in SETTINGS:
        runs = [json.loads(p.read_text("utf-8")) for p in sorted(FINAL.glob(f"{pre}_s*.json"))]
        if runs:
            out[pre] = runs
    return out


def mean(runs: list[dict], path: tuple[str, ...], key: str) -> float | None:
    vals = []
    for r in runs:
        node = r
        for p in path:
            node = node.get(p, {}) if isinstance(node, dict) else {}
        if isinstance(node, dict) and node.get(key) is not None:
            vals.append(float(node[key]))
    return float(np.mean(vals)) if vals else None


def cell(runs, path) -> str:
    rec, fpr = mean(runs, path, "recall"), mean(runs, path, "fpr")
    fah, roc = mean(runs, path, "false_alert_flows_per_hour"), mean(runs, path, "roc_auc")
    if rec is None:
        return "| - | - | - | - | - |"
    lo = [r for r in runs if _get(r, path)]
    ci = _get(lo[0], path).get("recall_ci95") if lo else None
    seeds = ", ".join(f"{_get(r, path)['recall']:.3f}" for r in lo)
    ci_s = f"[{ci[0]:.3f}, {ci[1]:.3f}]" if ci else "-"
    return f"| {rec:.3f} ({seeds}) | {ci_s} | {fpr:.4f} | {fah:.0f} | {roc:.3f} |"


def _get(r, path):
    node = r
    for p in path:
        node = node.get(p) if isinstance(node, dict) else None
        if node is None:
            return None
    return node


def main() -> None:
    R = load()  # noqa: N806
    md = ["# Final NF-v3 evaluation (pre-registered, one-shot)\n\n",
          "Pre-registration: `docs/experiments/final_preregistration_nf.md` (commit 47d0817). "
          "Test rows = test under both the episode and chronological protocols. Recall: mean "
          "over seeds (per-seed values); CI = 95% block bootstrap of seed 42; FA/h = "
          "false-alert flows per hour.\n\n"]  # fmt: skip
    for pre, title in SETTINGS.items():
        runs = R.get(pre)
        if not runs:
            md.append(f"## {title}\n\nNOT RUN / missing.\n\n")
            continue
        r0 = runs[0]
        md.append(f"## {title} ({len(runs)} seeds)\n\nTest rows {r0['eval_rows']}, attack rows "
                  f"{r0['eval_attack_rows']}, {r0['eval_hours']:.2f} h; labels "
                  f"{r0.get('eval_label_counts')}\n\n"
                  "| calibration | method | recall (seeds) | recall CI95 (s42) | FPR | FA/h | ROC |\n"
                  "|---|---|---|---|---|---|---|\n")  # fmt: skip
        md.append(f"| none | source model, source threshold {cell(runs, ('source_only',))}\n")
        for cal in ("clean_1000", "clean_10000", "clean_50000", "unlabelled_50000"):
            for m in SHOW:
                if any(_get(r, ("calibration", cal, m)) for r in runs):
                    md.append(f"| {cal} | {m} {cell(runs, ('calibration', cal, m))}\n")
        md.append("\n")

    def m(pre, path, key):
        return mean(R.get(pre, []), path, key)

    hyp = {}
    c50 = ("calibration", "clean_50000")
    u50 = ("calibration", "unlabelled_50000")
    ind = ("final_unsw2unsw_nf_flow_ctx", "final_ids2ids_nf_flow_ctx")
    vals = [(m(p, ("source_only",), "recall"), m(p, ("source_only",), "fpr")) for p in ind]
    hyp["H1"] = all(r is not None and r >= 0.95 and f <= 0.002 for r, f in vals), vals
    vals = [(m(p, ("source_only",), "roc_auc"), m(p, ("source_only",), "fpr")) for p in TRANSFER]
    hyp["H2"] = all(a is not None and (a < 0.6 or f > 0.1) for a, f in vals), vals
    vals = [(m(p, (*c50, "source_model_target_threshold"), "fpr"),
             m(p, (*c50, "source_model_target_threshold"), "recall")) for p in TRANSFER]  # fmt: skip
    hyp["H3"] = all(f is not None and f <= 0.003 and r < 0.05 for f, r in vals), vals
    ids_t = ("final_ids2ids_nf_flow_ctx", "final_unsw2ids_nf_flow_ctx")
    vals = {}
    for p in ids_t:
        for r in R.get(p, [])[:1]:
            for k in r["calibration"].get("clean_50000", {}):
                if k.startswith("target_"):
                    vals[f"{p}:{k}"] = m(p, (*c50, k), "recall")
    hyp["H4"] = bool(vals) and all(v is not None and v < 0.05 for v in vals.values()), vals
    unsw_t = ("final_unsw2unsw_nf_flow_ctx", "final_ids2unsw_nf_flow_ctx")
    vals = [(m(p, (*c50, "target_autoencoder_flow"), "recall"),
             m(p, (*c50, "target_autoencoder_flow_noshortcut"), "recall")) for p in unsw_t]  # fmt: skip
    hyp["H5"] = all(a is not None and b is not None and a >= 0.9 and b >= 0.8 for a, b in vals), vals
    vals = {}
    for p in SETTINGS:
        for k in ("target_autoencoder_flow", "source_model_target_threshold"):
            u, c = m(p, (*u50, k), "recall"), m(p, (*c50, k), "recall")
            vals[f"{p}:{k}"] = (u, c)
    hyp["H6"] = all(u is not None and c is not None and u <= c for u, c in vals.values()), vals
    md.append("## Pre-registered hypotheses\n\n| ID | supported | values (mean over seeds) |\n"
              "|---|---|---|\n")  # fmt: skip
    for k, (ok, v) in hyp.items():
        txt = json.dumps(v, default=lambda x: round(x, 4) if isinstance(x, float) else x)
        txt = txt.replace("|", "/")
        md.append(f"| {k} | {'**yes**' if ok else '**no**'} | {txt[:900]} |\n")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results_final_nf.md").write_text("".join(md), encoding="utf-8")
    (OUT / "results_final_nf.json").write_text(json.dumps(
        {"hypotheses": {k: {"supported": ok, "values": v} for k, (ok, v) in hyp.items()},
         "runs_found": {k: len(v) for k, v in R.items()}}, indent=1, default=str), "utf-8")  # fmt: skip
    print("".join(md[-8:]))


if __name__ == "__main__":
    main()
