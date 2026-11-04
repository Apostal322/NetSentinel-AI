"""Phase 8q figures, drawn only from saved results (reports/phase8q/*.json). Each answers one
question; no aggregate hides a failed network.

1. label_categories.png       What the historical attack windows are, by evidence category per domain
2. view_recall.png            Frozen M2 recall per network under the historical vs audited views
3. decomposition.png          Where the label dependency comes from: threshold vs memory, per network
4. labelfree_pareto.png       Label-free thresholds vs references: recall vs FPR per network
5. contamination_dose.png     Threshold estimators under controlled contamination (NF-ToN, NF-UNSW)
6. sparsity.png               Threshold variability when only 25 % / 10 % of hosts calibrate
7. memory_guard.png           Attack vs benign novelty under the oracle, unlabelled and guard memories

Usage: python scripts/phase8q/figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports" / "phase8q"
FIG = ROOT / "docs" / "phase8q" / "figures"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
NAMES = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN-IoT", "nfbot": "NF-BoT-IoT"}
COL = {
    "U": "#d62728",
    "T": "#ff9896",
    "P": "#444444",
    "L1": "#1f77b4",
    "L2": "#2ca02c",
    "L4": "#9467bd",
    "L5": "#8c564b",
}
CATS = {"documented_attack": "#2ca02c", "documented_family_mismatch": "#98df8a", "documented_outside_interval": "#bcbd22",
        "attacked_host_traffic": "#ff7f0e", "undocumented_source": "#d62728"}  # fmt: skip


def save(fig, name: str) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=130)
    plt.close(fig)


def label_categories(audit: dict) -> None:
    doms = list(audit["domains"])
    fig, ax = plt.subplots(figsize=(9, 4))
    y = np.arange(len(doms))
    left = np.zeros(len(doms))
    for c, col in CATS.items():
        v = np.array([audit["domains"][d]["categories"][c] for d in doms], float)
        tot = np.array(
            [sum(audit["domains"][d]["categories"][k] for k in CATS) for d in doms], float
        )
        share = np.divide(v, tot, out=np.zeros_like(v), where=tot > 0)
        ax.barh(y, share, left=left, color=col, label=c.replace("_", " "))
        left += share
    ax.set_yticks(y, [d.replace("nfcic/2018-", "CIC ") for d in doms], fontsize=8)
    ax.set_xlabel("share of the domain's historical attack windows")
    ax.legend(fontsize=7, frameon=False, loc="lower left", bbox_to_anchor=(0, 1.0), ncol=3)
    save(fig, "label_categories.png")


def view_recall(bm: dict) -> None:
    s = bm["score_sets"]["frozen_M2_r0"]
    views = (
        "V0_historical|historical_benign",
        "V2_documented_attackers|historical_benign",
        "V1_strict|historical_benign",
    )
    fig, ax = plt.subplots(figsize=(8, 3.4))
    x = np.arange(len(NETWORKS))
    for i, v in enumerate(views):
        ax.bar(
            x + (i - 1) * 0.27,
            [s[v]["networks"][n]["recall"] or 0 for n in NETWORKS],
            0.27,
            label=v.split("|")[0],
        )
    ax.set_xticks(x, [NAMES[n] for n in NETWORKS])
    ax.set_ylabel("window recall at T0 (frozen M2, reference replicate)")
    ax.legend(fontsize=7, frameon=False)
    ax.set_title("Same detector, different evaluation populations", fontsize=9)
    save(fig, "view_recall.png")


def decomposition(cd: dict) -> None:
    pn = cd["per_network"]
    nets = [n for n in NETWORKS if n in pn]
    fig, ax = plt.subplots(figsize=(8, 3.4))
    x = np.arange(len(nets))
    comps = (("threshold", "#d62728", "threshold contamination"), ("eval_memory", "#1f77b4", "evaluation-memory contamination"),
             ("hold_memory", "#2ca02c", "hold-out memory"))  # fmt: skip
    for path, off in (("path1", -0.2), ("path2", 0.2)):
        bottom = np.zeros(len(nets))
        for k, c, lab in comps:
            v = np.array([pn[n][path][k] for n in nets])
            ax.bar(x + off, v, 0.38, bottom=bottom, color=c, alpha=1.0 if path == "path1" else 0.55,
                   label=f"{lab} ({path})")  # fmt: skip
            bottom += v
    ax.set_xticks(x, [NAMES[n] for n in nets])
    ax.set_ylabel("recall_doc recovered (U → P)")
    ax.set_ylim(0, 1.25)
    ax.legend(fontsize=6, frameon=False, ncol=2, loc="upper left")
    save(fig, "decomposition.png")


def labelfree_pareto(f: dict) -> None:
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.3), sharey=True)
    for ax, n in zip(axes, NETWORKS, strict=True):
        for m, v in f["methods"].items():
            x = v["networks"][n]
            ax.scatter(max(x["fpr"] or 0, 1e-4), x["recall"] or 0, color=COL.get(m, "#999"), label=m, s=40,
                       marker="s" if m in ("T", "P") else "o")  # fmt: skip
        ax.axvline(0.01, color="#999", lw=0.6, ls="--")
        ax.set_xscale("log")
        ax.set_xlim(1e-4 / 1.5, 1)
        ax.set_title(NAMES[n], fontsize=9)
        ax.set_xlabel("FPR (log; points at 1e-4 = 0)")
    axes[0].set_ylabel("documented-attacker recall")
    axes[0].legend(fontsize=6, frameon=False)
    fig.suptitle(
        "Label-free thresholds (circles) vs oracle references (squares: T threshold-only, P full)",
        fontsize=9,
    )
    save(fig, "labelfree_pareto.png")


def contamination_dose(g: dict) -> None:
    fracs = (0.0, 0.005, 0.01, 0.02, 0.05, 0.1)
    fig, axes = plt.subplots(2, 4, figsize=(12, 5.5), sharex=True)
    for col, (n, mode) in enumerate((("nfton/all", "persistent"), ("nfton/all", "spread"),
                                     ("nfunsw/all", "persistent"), ("nfunsw/all", "spread"))):  # fmt: skip
        v = g["injection"][n]
        for m in ("U", "L1", "L2", "L4"):
            r = [v[f"{mode}|{f}|{m}"]["recall_mean"] for f in fracs]
            p = [v[f"{mode}|{f}|{m}"]["fpr_mean"] for f in fracs]
            axes[0, col].plot([100 * f for f in fracs], r, marker="o", color=COL[m], label=m)
            axes[1, col].plot([100 * f for f in fracs], p, marker="o", color=COL[m], label=m)
        axes[0, col].set_title(f"{NAMES[n.split('/')[0]]}, {mode}", fontsize=9)
        axes[1, col].set_xlabel("injected attacker windows (% of hold-out)")
    axes[0, 0].set_ylabel("documented recall")
    axes[1, 0].set_ylabel("FPR")
    axes[0, 0].legend(fontsize=7, frameon=False)
    save(fig, "contamination_dose.png")


def sparsity(g: dict) -> None:
    doms = list(g["sparse"])
    fig, ax = plt.subplots(figsize=(9, 3.4))
    x = np.arange(len(doms))
    for i, m in enumerate(("U", "L1", "L4")):
        sd = [g["sparse"][d].get("0.1", {}).get(m, {}).get("sd", np.nan) for d in doms]
        ax.bar(x + (i - 1) * 0.27, sd, 0.27, color=COL[m], label=m)
    ax.set_xticks(x, [d.replace("nfcic/2018-", "CIC ") for d in doms], rotation=30, fontsize=7)
    ax.set_ylabel("SD of the threshold over 20 draws\n(10 % of hold-out hosts)")
    ax.legend(fontsize=7, frameon=False)
    save(fig, "sparsity.png")


def memory_guard(mg: dict) -> None:
    doms = [d for d, v in mg["domains"].items() if v["P1x"]["doc_attack_novel_share"] is not None]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 3.6))
    x = np.arange(len(doms))
    for i, (m, c) in enumerate((("P1x", "#444444"), ("U", "#d62728"), ("F", "#1f77b4"))):
        a1.bar(
            x + (i - 1) * 0.27,
            [mg["domains"][d][m]["doc_attack_novel_share"] for d in doms],
            0.27,
            color=c,
            label=m,
        )
        a2.bar(
            x + (i - 1) * 0.27,
            [mg["domains"][d][m]["benign_novel_share"] for d in doms],
            0.27,
            color=c,
            label=m,
        )
    for ax, lab in (
        (a1, "documented attack windows with novelty > 0"),
        (a2, "benign windows with novelty > 0"),
    ):
        ax.set_xticks(x, [d.replace("nfcic/2018-", "CIC ") for d in doms], rotation=30, fontsize=7)
        ax.set_ylabel(lab, fontsize=8)
    a1.legend(fontsize=7, frameon=False, title="memory", title_fontsize=7)
    save(fig, "memory_guard.png")


def main() -> None:
    label_categories(json.loads((REP / "label_audit.json").read_text("utf-8")))
    view_recall(json.loads((REP / "benchmark_metrics.json").read_text("utf-8")))
    decomposition(json.loads((REP / "calibration_decomposition.json").read_text("utf-8")))
    labelfree_pareto(json.loads((REP / "experiment_f.json").read_text("utf-8")))
    g = json.loads((REP / "experiment_g.json").read_text("utf-8"))
    contamination_dose(g)
    sparsity(g)
    memory_guard(json.loads((REP / "memory_guard_diag.json").read_text("utf-8")))


if __name__ == "__main__":
    main()
