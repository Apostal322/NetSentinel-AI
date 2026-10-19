"""Aggregate batch v4 (NetFlow v3) into reports/experiments/results_v4.md (+ JSON).
Mean +- sample std over seeds; VALIDATION only (source val for thresholds, target val for
transfer). Test splits untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import yaml

RUNS = Path("runs")
OUT = Path("reports/experiments")
SETS = ("nf_flow", "nf_flow_noshortcut", "nf_flow_ctx", "nf_portable", "nf_portable_ctx")
GROUPS = ("port21_failed_conn", "ssh_bruteforce", "dos_http", "ddos", "web_attack", "botnet")


def by_experiment() -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for d in sorted(p for p in RUNS.iterdir() if (p / "metrics.json").exists()):
        exp = yaml.safe_load((d / "config.yaml").read_text("utf-8")).get("experiment", "")
        if exp.startswith(("nf_", "app_")):
            out.setdefault(exp, []).append(d)
    return out


def metrics(d: Path) -> dict:
    return json.loads((d / "metrics.json").read_text("utf-8"))


def ms(v) -> str:
    a = np.array([x for x in v if x is not None], dtype=float)
    if not len(a):
        return "-"
    return (
        f"{a.mean():.3f} +- {a.std(ddof=1):.3f} (n={len(a)})" if len(a) > 1 else f"{a[0]:.3f} (n=1)"
    )


def main() -> None:
    E = by_experiment()  # noqa: N806
    md = ["# Results v4: NetFlow v3 in-domain, transfer, open-set (validation)\n\n"]
    data: dict = {}
    for ds, name in (("unsw", "NF-UNSW-NB15-v3"), ("ids", "NF-CSE-CIC-IDS2018-v3")):
        md.append(f"## In-domain retraining: {name}\n\n| features | PR-AUC | recall @ FPR 1e-3 | "
                  "recall @ FPR 1e-2 | ECE |\n|---|---|---|---|---|\n")  # fmt: skip
        base = E.get(f"nf_{ds}_baselines", [])
        for d in base:
            m = metrics(d)
            model = d.name.split("_")[-1]
            md.append(f"| nf_flow ({model}) | {ms([m.get('val/pr_auc')])} | "
                      f"{ms([m.get('val/recall_at_fpr_0.001')])} | "
                      f"{ms([m.get('val/recall_at_fpr_0.01')])} | {ms([m.get('val/ece')])} |\n")  # fmt: skip
        for fs in SETS:
            ms_ = [metrics(d) for s in (42, 1, 2, 3, 4) for d in E.get(f"nf_{ds}_{fs}_s{s}", [])]
            data.setdefault(ds, {})[fs] = ms_
            if ms_:
                md.append(f"| {fs} (lightgbm) | {ms([m.get('val/pr_auc') for m in ms_])} | "
                          f"{ms([m.get('val/recall_at_fpr_0.001') for m in ms_])} | "
                          f"{ms([m.get('val/recall_at_fpr_0.01') for m in ms_])} | "
                          f"{ms([m.get('val/ece') for m in ms_])} |\n")  # fmt: skip
        md.append("\n")
    md.append("## Transfer (fit on source train, threshold on source val, evaluate target val)\n\n"
              "| direction | features | source PR-AUC | target PR-AUC | target ROC-AUC | target "
              "recall @ source thr | target FPR @ source thr | target recall @ oracle thr |\n"
              "|---|---|---|---|---|---|---|---|\n")  # fmt: skip
    for a, b in (("ids", "unsw"), ("unsw", "ids")):
        for fs in SETS:
            ms_ = [metrics(d) for s in (42, 1, 2) for d in
                   E.get(f"nf_transfer_{a}2{b}_{fs}_s{s}", [])]  # fmt: skip
            data.setdefault("transfer", {})[f"{a}2{b}_{fs}"] = ms_
            if ms_:
                md.append(f"| {a} -> {b} | {fs} | {ms([m.get('source_val/pr_auc') for m in ms_])} | "
                          f"{ms([m.get('target_val/pr_auc') for m in ms_])} | "
                          f"{ms([m.get('target_val/roc_auc') for m in ms_])} | "
                          f"{ms([m.get('target_val/recall') for m in ms_])} | "
                          f"{ms([m.get('target_val/fpr') for m in ms_])} | "
                          f"{ms([m.get('target_val_oracle/recall') for m in ms_])} |\n")  # fmt: skip
    md.append(
        "\n## Open-set on NF-IDS2018 (behaviour-defined groups, seeds 42,1,2)\n\n"
        "| held-out group | nf_flow | nf_flow_ctx | nf_portable_ctx |\n|---|---|---|---|\n"
    )
    for g in GROUPS:
        cells = []
        for fs in ("nf_flow", "nf_flow_ctx", "nf_portable_ctx"):
            vals = [metrics(d).get("supervised_recall") for s in (42, 1, 2)
                    for d in E.get(f"nf_ids_openset_{fs}_s{s}", []) if d.name.endswith(f"_without_{g}")]  # fmt: skip
            cells.append(ms(vals))
        md.append(f"| {g} | " + " | ".join(cells) + " |\n")
    ledger = Path("runs/batch_v4.jsonl")
    if ledger.exists():
        rows = [json.loads(x) for x in ledger.read_text("utf-8").splitlines() if x.strip()]
        md.append(f"\nBatch v4 cost (measured): {len(rows)} processes, "
                  f"{sum(r['seconds'] for r in rows) / 60:.1f} min, max peak working set "
                  f"{max((r['peak_rss_mb'] or 0) for r in rows):.0f} MB.\n")  # fmt: skip
    (OUT / "results_v4.md").write_text("".join(md), "utf-8")
    (OUT / "results_v4.json").write_text(json.dumps(data, indent=2, default=str), "utf-8")
    print("".join(md))


if __name__ == "__main__":
    main()
