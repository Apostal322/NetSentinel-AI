"""Phase 8m figures, drawn only from saved results (reports/phase8m/*.json).

1. novelty_by_day.png      DEDALE (POST-HOC): share of novel windows per day, calibration
                           (expanding memory) vs evaluation (frozen memory)
2. recall_vs_alerts.png    development: per network, attack-window recall against verified-benign
                           false alerts (mean over domains and seeds) for each variant
3. contamination.png       synthetic beacons: share of beacon windows still novel, A3 vs A1

Usage: python scripts/phase8m/figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports" / "phase8m"
FIG = ROOT / "docs" / "phase8m" / "figures"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
NAMES = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN-IoT", "nfbot": "NF-BoT-IoT"}
STYLE = {"B0": ("#444444", "o"), "B1": ("#1f77b4", "s"), "B2": ("#d62728", "D"),
         "B3": ("#9467bd", "v"), "B1u": ("#ff7f0e", "^"), "A_none": ("#8c8c8c", "x"),
         "A_novol": ("#2ca02c", "P")}  # fmt: skip


def novelty_by_day() -> None:
    d = json.loads((REP / "novelty_audit.json").read_text("utf-8"))["dedale"]["novelty_by_day"]
    fig, ax = plt.subplots(figsize=(7, 3.2))
    for part, colour, label in (("calibration_expanding_memory", "#1f77b4", "calibration (memory expands)"),
                                ("evaluation_frozen_memory", "#d62728", "evaluation (memory frozen)")):  # fmt: skip
        rows = [r for r in d if r["part"] == part]
        ax.bar([r["utc_day"][5:] for r in rows], [100 * r["novel_share"] for r in rows],
               color=colour, label=label)  # fmt: skip
    ax.set_ylabel("windows with a new destination (%)")
    ax.set_title("DEDALE (post-hoc diagnostic): destination novelty by day", fontsize=10)
    ax.tick_params(axis="x", rotation=60, labelsize=7)
    ax.legend(fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "novelty_by_day.png", dpi=150)
    plt.close(fig)


def recall_vs_alerts() -> None:
    p = REP / "model_comparison.json"
    if not p.exists():
        return
    nm = json.loads(p.read_text("utf-8"))["network_means"]
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.2))
    for ax, net in zip(axes, NETWORKS, strict=True):
        for v, (c, m) in STYLE.items():
            if v in nm and net in nm[v]:
                r = nm[v][net]
                ax.scatter(r["false_alerts"], r["window_recall"], color=c, marker=m, label=v, s=40)
        ax.set_title(NAMES[net], fontsize=10)
        ax.set_xlabel("false alerts (verified benign)")
        ax.set_ylim(-0.02, 1.02)
    axes[0].set_ylabel("attack-window recall")
    axes[-1].legend(fontsize=7, frameon=False, loc="lower right")
    fig.suptitle(
        "Development (registered): recall vs false alerts at each model's own T0", fontsize=10
    )
    fig.tight_layout()
    fig.savefig(FIG / "recall_vs_alerts.png", dpi=150)
    plt.close(fig)


def contamination() -> None:
    p = REP / "contamination.json"
    if not p.exists():
        return
    per = json.loads(p.read_text("utf-8"))["per_domain"]
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2), sharey=True)
    for ax, variant in zip(axes, ("single_host", "two_hosts"), strict=True):
        for net, off in zip(NETWORKS, (-0.3, -0.1, 0.1, 0.3), strict=True):
            for policy, mk in (("a3_novel_share", "o"), ("a1_novel_share", "x")):
                for i, period in enumerate((1, 10, 60)):
                    v = [s[policy] for k, r in per.items() if k.startswith(net + "/")
                         for s in r["synthetic"] if s["variant"] == variant and s["period_min"] == period]  # fmt: skip
                    if v:
                        ax.scatter(i + off, 100 * sum(v) / len(v), marker=mk,
                                   color=("#d62728" if policy.startswith("a3") else "#ff7f0e"))  # fmt: skip
        ax.set_xticks([0, 1, 2], ["1 min", "10 min", "1 h"])
        ax.set_xlabel(
            "beacon period (per period, left to right: NF-CIC, NF-UNSW, NF-ToN, NF-BoT)", fontsize=7
        )
        ax.set_title(variant.replace("_", " ") + " (synthetic)", fontsize=10)
    axes[0].set_ylabel("beacon windows still novel (%)")
    axes[0].scatter([], [], marker="o", color="#d62728", label="A3 guarded")
    axes[0].scatter([], [], marker="x", color="#ff7f0e", label="A1 unconditional")
    axes[0].legend(fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "contamination.png", dpi=150)
    plt.close(fig)


def main() -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    novelty_by_day()
    recall_vs_alerts()
    contamination()


if __name__ == "__main__":
    main()
