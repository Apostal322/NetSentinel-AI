"""Aggregate batch v2 (+ the seed-42 runs of batch v1) into reports/experiments/results_v2.md.

Seed variance: mean +- sample std over seeds {42, 1, 2, 3, 4}; each seed changes the model seed
and the split seed. All VALIDATION metrics; test split untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import yaml

RUNS = Path("runs")
OUT = Path("reports/experiments")


def runs_by_experiment() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for d in sorted(p for p in RUNS.iterdir() if (p / "metrics.json").exists()):
        cfg = yaml.safe_load((d / "config.yaml").read_text("utf-8"))
        rec = {"run_id": d.name, "dir": d, "cfg": cfg,
               "metrics": json.loads((d / "metrics.json").read_text("utf-8"))}  # fmt: skip
        out.setdefault(cfg.get("experiment", ""), []).append(rec)
    return out


def latest(recs: list[dict], suffix: str) -> dict | None:
    hits = [r for r in recs if r["run_id"].endswith(suffix)]
    return hits[-1] if hits else None


def ms(values: list[float]) -> str:
    v = np.array([x for x in values if x is not None], dtype=float)
    if len(v) == 0:
        return "-"
    if len(v) == 1:
        return f"{v[0]:.4f} (n=1)"
    return f"{v.mean():.4f} +- {v.std(ddof=1):.4f} (n={len(v)})"


def per_label_recall(run: dict, label: str) -> float | None:
    p = run["dir"] / "error_analysis_val.json"
    if not p.exists():
        return None
    for r in json.loads(p.read_text("utf-8")).get("recall_by_label", []):
        if r["label"] == label:
            return r["recall"]
    return None


def main() -> None:
    E = runs_by_experiment()  # noqa: N806
    md = ["# Results v2: seed variance and temporal open-set (validation, measured)\n",
          "Seeds {42, 1, 2, 3, 4}; each changes model and split seed. Seed 42 = batch v1 runs. "
          "Mean +- sample std. Test split untouched.\n"]  # fmt: skip

    # A: temporal open-set vs LightGBM open-set (seed 42).
    md.append("## A - unseen family: GRU / MLP (flow + per-port sequence) vs LightGBM\n")
    md.append(
        "| held-out family | MLP recall | GRU recall | GRU unseen PR-AUC | GRU benign FPR | "
        "LightGBM flow | LightGBM flow+ctx |\n|---|---|---|---|---|---|---|\n"
    )
    for fam in ("bruteforce", "dos", "ddos", "web_attack", "botnet"):
        t = E.get("temporal_openset", [])
        mlp = latest(t, f"_mlp_without_{fam}")
        gru = latest(t, f"_gru_without_{fam}")
        lf = latest(E.get("openset_flow", []), f"_without_{fam}")
        lc = latest(E.get("openset_flow_ctx", []), f"_without_{fam}")

        def g(r, k):
            return r["metrics"].get(k) if r else None

        md.append(f"| {fam} | {ms([g(mlp, 'supervised_recall')])} | "
                  f"{ms([g(gru, 'supervised_recall')])} | {ms([g(gru, 'unseen_pr_auc')])} | "
                  f"{ms([g(gru, 'supervised_benign_val_fpr')])} | "
                  f"{ms([g(lf, 'supervised_recall')])} | {ms([g(lc, 'supervised_recall')])} |\n")  # fmt: skip

    # B1: binary LightGBM across seeds.
    md.append("\n## B1 - binary LightGBM across seeds (episode split)\n")
    md.append("| features | PR-AUC | recall @ FPR 1e-3 | recall @ FPR 1e-2 | ECE |\n"
              "|---|---|---|---|---|\n")  # fmt: skip
    v1_name = {"flow": "baseline_binary", "flow_noshortcut": "baseline_binary_flow_noshortcut",
               "flow_ctx": "baseline_binary_flow_ctx"}  # fmt: skip
    for fs, base in v1_name.items():
        recs = [latest(E.get(base, []), "_lightgbm")]
        recs += [latest(E.get(f"seeds_binary_{fs}_s{s}", []), "_lightgbm") for s in (1, 2, 3, 4)]
        recs = [r for r in recs if r]
        cols = [ms([r["metrics"].get(f"val/{k}") for r in recs])
                for k in ("pr_auc", "recall_at_fpr_0.001", "recall_at_fpr_0.01", "ece")]  # fmt: skip
        md.append(f"| {fs} | " + " | ".join(cols) + " |\n")

    # B2: open-set LightGBM across seeds.
    md.append("\n## B2 - unseen-family recall (LightGBM) across seeds\n")
    md.append("| held-out family | flow | flow + ctx | anomaly (flow) | fused (flow+ctx) |\n"
              "|---|---|---|---|---|\n")  # fmt: skip
    for fam in ("bruteforce", "dos", "ddos", "web_attack", "botnet"):
        cells = []
        for fs, key in (("flow", "supervised_recall"), ("flow_ctx", "supervised_recall"),
                        ("flow", "anomaly_recall"), ("flow_ctx", "fused_recall")):  # fmt: skip
            exps = [f"openset_{fs}"] + [f"seeds_openset_{fs}_s{s}" for s in (1, 2, 3, 4)]
            vals = [latest(E.get(e, []), f"_without_{fam}") for e in exps]
            cells.append(ms([r["metrics"].get(key) for r in vals if r]))
        md.append(f"| {fam} | " + " | ".join(cells) + " |\n")

    # B3: GRU vs MLP across seeds.
    md.append("\n## B3 - GRU vs MLP on seen attacks across seeds\n")
    md.append("| model | PR-AUC | recall @ FPR 1e-3 | web_xss recall | epochs |\n"
              "|---|---|---|---|---|\n")  # fmt: skip
    for arch in ("mlp", "gru"):
        exps = ["temporal"] + [f"seeds_temporal_s{s}" for s in (1, 2, 3, 4)]
        recs = [latest(E.get(e, []), f"_{arch}") for e in exps]
        recs = [r for r in recs if r]
        md.append(f"| {arch} | {ms([r['metrics'].get('val/pr_auc') for r in recs])} | "
                  f"{ms([r['metrics'].get('val/recall_at_fpr_0.001') for r in recs])} | "
                  f"{ms([per_label_recall(r, 'web_xss') for r in recs])} | "
                  f"{ms([r['metrics'].get('cost/epochs') for r in recs])} |\n")  # fmt: skip

    ledger = Path("runs/batch_v2.jsonl")
    if ledger.exists():
        rows = [json.loads(x) for x in ledger.read_text("utf-8").splitlines() if x.strip()]
        total = sum(r["seconds"] for r in rows) / 60
        peak = max((r["peak_rss_mb"] or 0) for r in rows)
        md.append(f"\nBatch v2 cost (measured): {len(rows)} processes, {total:.1f} min total, "
                  f"max peak working set {peak:.0f} MB.\n")  # fmt: skip
    (OUT / "results_v2.md").write_text("".join(md), "utf-8")
    print(f"wrote {OUT / 'results_v2.md'}")


if __name__ == "__main__":
    main()
