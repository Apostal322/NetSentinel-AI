"""Phase 8n figures, drawn only from saved results (reports/phase8n/*.json).

1. fragility_arms.png      Experiment A: catastrophic cases per perturbation arm (all domains)
2. recall_range.png        Experiment C: window recall per domain, min-max over the 6 fits
3. entity_stability.png    Experiment C: entities detected in all / some / none of the 6 fits
4. recall_vs_alerts.png    Experiment C: per network, mean recall against false alerts

Usage: python scripts/phase8n/figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports" / "phase8n"
FIG = ROOT / "docs" / "phase8n" / "figures"
MODELS = ("M0", "M1", "M2", "M3")
COLOUR = {"M0": "#444444", "M1": "#ff7f0e", "M2": "#d62728", "M3": "#1f77b4"}
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
NAMES = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN-IoT", "nfbot": "NF-BoT-IoT"}


def fragility_arms() -> None:
    s = json.loads((REP / "fragility_analysis.json").read_text("utf-8"))["summary"]
    arms = sorted((a for a in s if a != "P_ref"), key=lambda a: s[a]["catastrophic_cases"])
    fig, ax = plt.subplots(figsize=(7, 6))
    total = [s[a]["catastrophic_cases"] for a in arms]
    focus = [s[a]["catastrophic_focus_cases"] for a in arms]
    ax.barh(arms, total, color="#bbbbbb", label="all domains (27 domain-replicates)")
    ax.barh(arms, focus, color="#d62728", label="NF-CIC 02-14/16/21 (9 cases)")
    ax.set_xlabel("catastrophic cases (recall drop ≥ 0.5 or a detected entity lost)")
    ax.tick_params(axis="y", labelsize=7)
    ax.legend(fontsize=8, frameon=False, loc="lower right")
    ax.set_title("Experiment A: which perturbations break B0", fontsize=10)
    fig.tight_layout()
    fig.savefig(FIG / "fragility_arms.png", dpi=150)
    plt.close(fig)


def candidates() -> dict:
    return json.loads((REP / "candidate_comparison.json").read_text("utf-8"))["models"]


def recall_range(c: dict) -> None:
    doms = list(c["M0"]["per_domain"])
    fig, ax = plt.subplots(figsize=(9, 3.8))
    for j, m in enumerate(MODELS):
        for i, d in enumerate(doms):
            v = c[m]["per_domain"][d]
            x = i + (j - 1.5) * 0.18
            ax.plot([x, x], [v["recall_min"], v["recall_max"]], color=COLOUR[m], lw=2)
            ax.scatter([x], [v["recall_mean"]], color=COLOUR[m], s=14, label=m if i == 0 else None)
    ax.set_xticks(range(len(doms)), [d.replace("nfcic/2018-", "CIC ").replace("/all", "") for d in doms],
                  fontsize=8)  # fmt: skip
    ax.set_ylabel("attack-window recall")
    ax.set_title("Experiment C: recall per domain, mean and min–max over 6 fits (3 base + 3 stress)",
                 fontsize=10)  # fmt: skip
    ax.legend(fontsize=8, frameon=False, ncol=4, loc="lower left")
    fig.tight_layout()
    fig.savefig(FIG / "recall_range.png", dpi=150)
    plt.close(fig)


def entity_stability(c: dict) -> None:
    fig, ax = plt.subplots(figsize=(5, 3.2))
    for i, m in enumerate(MODELS):
        r, u, n = c[m]["R"], c[m]["U"], c[m]["N"]
        ax.bar(i, r, color="#2ca02c", label="all 6 fits" if i == 0 else None)
        ax.bar(i, u, bottom=r, color="#ff7f0e", label="some fits" if i == 0 else None)
        ax.bar(i, n, bottom=r + u, color="#bbbbbb", label="no fit" if i == 0 else None)
    ax.set_xticks(range(len(MODELS)), MODELS)
    ax.set_ylabel("attack entities (75)")
    ax.set_title("Entities detected in ...", fontsize=10)
    ax.legend(fontsize=8, frameon=False, loc="upper right")
    fig.tight_layout()
    fig.savefig(FIG / "entity_stability.png", dpi=150)
    plt.close(fig)


def recall_vs_alerts(c: dict) -> None:
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.2))
    for ax, net in zip(axes, NETWORKS, strict=True):
        for m in MODELS:
            v = c[m]["network_means"][net]
            ax.scatter(v["false_alerts"], v["window_recall"], color=COLOUR[m], s=40, label=m)
        ax.set_title(NAMES[net], fontsize=10)
        ax.set_xlabel("false alerts (verified benign)")
        ax.set_ylim(0, 1.02)
    axes[0].set_ylabel("attack-window recall (mean of 6 fits)")
    axes[-1].legend(fontsize=8, frameon=False, loc="lower right")
    fig.suptitle(
        "Experiment C (registered development): recall vs false alerts at each model's T0",
        fontsize=10,
    )
    fig.tight_layout()
    fig.savefig(FIG / "recall_vs_alerts.png", dpi=150)
    plt.close(fig)


def main() -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    fragility_arms()
    c = candidates()
    recall_range(c)
    entity_stability(c)
    recall_vs_alerts(c)


if __name__ == "__main__":
    main()
