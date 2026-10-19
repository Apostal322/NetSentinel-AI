"""Aggregate batch v5 (Missions 2-3) into reports/experiments/results_v5.md (+ JSON + figure).
Mean +- sample std over seeds. Target evaluation = chronological target VALIDATION partition;
thresholds come from target calibration data (benign-only 'clean' or unlabelled pool) or the
source validation set; no target attack label is used to set anything. Test splits untouched.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib
import numpy as np
import yaml

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RUNS = Path("runs")
OUT = Path("reports/experiments")
FIG = Path("reports/figures")
SETTINGS = {  # experiment prefix -> description
    "v5_ids2unsw_nf_flow_ctx": "NF-IDS2018 -> NF-UNSW, nf_flow_ctx",
    "v5_ids2unsw_nf_portable_ctx": "NF-IDS2018 -> NF-UNSW, nf_portable_ctx",
    "v5_unsw2ids_nf_flow_ctx": "NF-UNSW -> NF-IDS2018, nf_flow_ctx",
    "v5_unsw2unsw_nf_flow_ctx": "NF-UNSW in-network, nf_flow_ctx",
    "v5_ids2ids_nf_flow_ctx": "NF-IDS2018 in-network, nf_flow_ctx",
    "v5_cic2cic_flow_ctx": "CIC-IDS2018 in-network, flow_ctx",
}
SUPERVISED = ("source_model_target_threshold", "normalized_source_threshold",
              "normalized_target_threshold", "robust_subset_target_threshold")  # fmt: skip
KEYS = ("recall", "fpr", "false_alert_flows_per_hour", "roc_auc", "pr_auc", "recall_at_fpr_0.001")


def load() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for d in sorted(RUNS.iterdir()):
        f = d / "adapt_results.json"
        if not f.exists():
            continue
        exp = yaml.safe_load((d / "config.yaml").read_text("utf-8")).get("experiment", "")
        for pre in SETTINGS:
            if exp.startswith(pre + "_s"):
                out[pre].append(json.loads(f.read_text("utf-8")))
    return out


def agg(vals) -> tuple[float, float, int] | None:
    a = np.array([v for v in vals if v is not None and np.isfinite(v)], dtype=float)
    if not len(a):
        return None
    return float(a.mean()), float(a.std(ddof=1)) if len(a) > 1 else 0.0, len(a)


def fmt(t, p=3) -> str:
    if t is None:
        return "-"
    m, s, n = t
    return f"{m:.{p}f} +- {s:.{p}f}" if n > 1 else f"{m:.{p}f}"


def methods_of(res: list[dict]) -> list[str]:
    ms = []
    for r in res:
        for cal in r["calibration"].values():
            ms += [k for k, v in cal.items() if isinstance(v, dict) and k not in ms]
    return ms


def main() -> None:
    R = load()  # noqa: N806
    md = ["# Results v5: label-free adaptation and normal modelling (validation)\n\n",
          "Mean +- sample std over seeds (n per cell in JSON). `recall`/`fpr` are at the threshold "
          "set WITHOUT target attack labels (target calibration quantile at FPR 1e-3, or the "
          "source threshold); `FA/h` = false-alert flows per hour of evaluation traffic "
          "(prevalence-weighted). `R@1e-3` uses a threshold read off the evaluation data and is "
          "an oracle diagnostic of ranking quality, not an operating point.\n\n"]  # fmt: skip
    data: dict = {}
    for pre, title in SETTINGS.items():
        res = R.get(pre, [])
        if not res:
            md.append(f"## {title}\n\nNo completed runs.\n\n")
            continue
        md.append(f"## {title} (seeds: {len(res)})\n\n")
        md.append(f"Evaluation: {fmt(agg([r['eval_rows'] for r in res]), 0)} rows, "
                  f"{fmt(agg([r['eval_attack_rows'] for r in res]), 0)} attack rows, "
                  f"{fmt(agg([r['eval_hours'] for r in res]), 1)} h.\n\n")  # fmt: skip
        so = {k: agg([r["source_only"][k] for r in res]) for k in KEYS}
        data.setdefault(pre, {})["source_only"] = so
        md.append("| calibration | method | recall | FPR | FA/h | ROC-AUC | R@1e-3 (oracle) |\n"
                  "|---|---|---|---|---|---|---|\n"
                  f"| none | source model, source threshold | {fmt(so['recall'])} | "
                  f"{fmt(so['fpr'], 4)} | {fmt(so['false_alert_flows_per_hour'], 0)} | "
                  f"{fmt(so['roc_auc'])} | {fmt(so['recall_at_fpr_0.001'])} |\n")  # fmt: skip
        cals = sorted({c for r in res for c in r["calibration"]},
                      key=lambda c: (c.split("_")[0], int(c.split("_")[1])))  # fmt: skip
        for cal in cals:
            rows = [r["calibration"][cal] for r in res if cal in r["calibration"]]
            cont = agg([c.get("contamination") for c in rows])
            for m in methods_of(res):
                vals = [c[m] for c in rows if m in c]
                if not vals:
                    continue
                t = {k: agg([v.get(k) for v in vals]) for k in KEYS}
                data[pre].setdefault(cal, {})[m] = t
                data[pre][cal]["contamination"] = cont
                md.append(f"| {cal} (contam. {fmt(cont)}) | {m} | {fmt(t['recall'])} | "
                          f"{fmt(t['fpr'], 4)} | {fmt(t['false_alert_flows_per_hour'], 0)} | "
                          f"{fmt(t['roc_auc'])} | {fmt(t['recall_at_fpr_0.001'])} |\n")  # fmt: skip
        md.append("\n")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results_v5.md").write_text("".join(md), encoding="utf-8")
    (OUT / "results_v5.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    # figure: recall and FPR vs clean calibration size, adaptation settings
    FIG.mkdir(parents=True, exist_ok=True)
    adapt = [p for p in ("v5_ids2unsw_nf_flow_ctx", "v5_ids2unsw_nf_portable_ctx",
                         "v5_unsw2ids_nf_flow_ctx") if p in data]  # fmt: skip
    if adapt:
        fig, axes = plt.subplots(2, len(adapt), figsize=(5 * len(adapt), 7), squeeze=False)
        for j, pre in enumerate(adapt):
            sizes = sorted(int(c.split("_")[1]) for c in data[pre] if c.startswith("clean_"))
            for m in ("source_model_target_threshold", "normalized_target_threshold",
                      "target_robust_z_flow", "target_iforest_flow", "target_autoencoder_flow",
                      "target_iforest_all", "target_autoencoder_all"):  # fmt: skip
                rec = [data[pre][f"clean_{n}"].get(m, {}).get("recall") for n in sizes]
                fpr = [data[pre][f"clean_{n}"].get(m, {}).get("fpr") for n in sizes]
                xs = [n for n, r in zip(sizes, rec, strict=True) if r]
                if xs:
                    axes[0, j].plot(xs, [r[0] for r in rec if r], marker="o", label=m)
                    axes[1, j].plot(xs, [f[0] for f in fpr if f], marker="o", label=m)
            axes[0, j].set_title(SETTINGS[pre], fontsize=9)
            for i, lab in enumerate(("recall at calibrated threshold", "FPR on target benign")):
                axes[i, j].set_xscale("log")
                axes[i, j].set_ylabel(lab)
                axes[i, j].set_xlabel("clean target calibration flows")
            axes[1, j].axhline(1e-3, color="grey", ls="--", lw=0.8)
            axes[1, j].set_yscale("log")
        axes[0, -1].legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(FIG / "adaptation_calibration.png", dpi=120)
    print(f"wrote {OUT / 'results_v5.md'}")


if __name__ == "__main__":
    main()
