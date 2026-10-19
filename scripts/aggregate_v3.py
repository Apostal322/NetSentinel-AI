"""Aggregate correction batch v3 into reports/experiments/results_v3.md (+ JSON).

Open-set with behaviour-defined hold-out groups and label cleaning v2; context scale ablation.
Mean +- sample std over seeds {42, 1, 2, 3, 4}. VALIDATION only (test untouched).
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import yaml

RUNS = Path("runs")
OUT = Path("reports/experiments")
GROUPS = ("port21_failed_conn", "ssh_bruteforce", "dos_http", "ddos", "web_attack", "botnet")
SEEDS = (42, 1, 2, 3, 4)


def runs() -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for d in sorted(p for p in RUNS.iterdir() if (p / "metrics.json").exists()):
        exp = yaml.safe_load((d / "config.yaml").read_text("utf-8")).get("experiment", "")
        if exp.startswith("v3_"):
            out.setdefault(exp, []).append(d)
    return out


def ms(v: list[float | None]) -> str:
    a = np.array([x for x in v if x is not None], dtype=float)
    if not len(a):
        return "-"
    return (
        f"{a.mean():.3f} +- {a.std(ddof=1):.3f} (n={len(a)})" if len(a) > 1 else f"{a[0]:.3f} (n=1)"
    )


def main() -> None:
    R = runs()  # noqa: N806
    data: dict = {"openset": {}, "binary": {}}
    md = ["# Results v3: corrected open-set protocol and context ablation (validation)\n\n",
          "Hold-out groups are defined by behaviour so that twin classes (identical traffic under "
          "different family labels) are held out together; label cleaning v2. Seeds "
          "{42,1,2,3,4} (model + split). Thresholds at benign-validation FPR <= 1e-3.\n\n"]  # fmt: skip
    for fs in ("flow", "flow_ctx", "flow_ctx_inv"):
        md.append(f"## Unseen-group recall, features `{fs}`\n\n| held-out group | rows | supervised "
                  "| anomaly | fused | supervised benign FPR |\n|---|---|---|---|---|---|\n")  # fmt: skip
        for g in GROUPS:
            ms_ = []
            for s in SEEDS:
                hits = [
                    d
                    for d in R.get(f"v3_openset_{fs}_s{s}", [])
                    if d.name.endswith(f"_without_{g}")
                ]
                if hits:
                    ms_.append(json.loads((hits[-1] / "metrics.json").read_text("utf-8")))
            data["openset"].setdefault(fs, {})[g] = ms_
            if not ms_:
                continue
            md.append(f"| {g} | {int(ms_[0]['unseen_rows'])} | "
                      f"{ms([m['supervised_recall'] for m in ms_])} | "
                      f"{ms([m['anomaly_recall'] for m in ms_])} | "
                      f"{ms([m['fused_recall'] for m in ms_])} | "
                      f"{ms([m['supervised_benign_val_fpr'] for m in ms_])} |\n")  # fmt: skip
        md.append("\n")
    # Per-label supervised recall (flow_ctx), averaged over seeds.
    md.append(
        "## Per-label unseen recall (supervised, `flow_ctx`)\n\n| group | label | recall |\n|---|---|---|\n"
    )
    for g in GROUPS:
        per: dict[str, list[float]] = {}
        for s in SEEDS:
            for d in R.get(f"v3_openset_flow_ctx_s{s}", []):
                if d.name.endswith(f"_without_{g}") and (d / "per_label_unseen.json").exists():
                    for r in json.loads((d / "per_label_unseen.json").read_text("utf-8")):
                        per.setdefault(r["label"], []).append(r["sup"])
        for lab, v in sorted(per.items()):
            md.append(f"| {g} | {lab} | {ms(v)} |\n")
    # C1: in-distribution binary ablation.
    md.append(
        "\n## Context scale ablation, seen attacks (LightGBM binary, episode split)\n\n"
        "| features | PR-AUC | recall @ FPR 1e-3 | recall @ FPR 1e-2 |\n|---|---|---|---|\n"
    )
    for fs in ("flow_ctx_inv", "flow_ctx_abs"):
        mets = []
        for s in SEEDS:
            for d in R.get(f"v3_binary_{fs}_s{s}", []):
                mets.append(json.loads((d / "metrics.json").read_text("utf-8")))
        data["binary"][fs] = mets
        if mets:
            md.append(f"| {fs} | {ms([m.get('val/pr_auc') for m in mets])} | "
                      f"{ms([m.get('val/recall_at_fpr_0.001') for m in mets])} | "
                      f"{ms([m.get('val/recall_at_fpr_0.01') for m in mets])} |\n")  # fmt: skip
    ledger = Path("runs/batch_v3.jsonl")
    if ledger.exists():
        rows = [json.loads(x) for x in ledger.read_text("utf-8").splitlines() if x.strip()]
        md.append(f"\nBatch v3 cost (measured): {len(rows)} processes, "
                  f"{sum(r['seconds'] for r in rows) / 60:.1f} min, max peak working set "
                  f"{max((r['peak_rss_mb'] or 0) for r in rows):.0f} MB.\n")  # fmt: skip
    (OUT / "results_v3.md").write_text("".join(md), "utf-8")
    (OUT / "results_v3.json").write_text(json.dumps(data, indent=2, default=str), "utf-8")
    print("".join(md))


if __name__ == "__main__":
    main()
