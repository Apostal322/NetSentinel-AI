"""Phase 8w figures, drawn from saved results only (reports/phase8w/*.json).

1. `fig1_direction.png`: univariate AUC per network, raw value vs unsigned deviation (exploratory).
2. `fig2_partial_auc.png`: exact partial AUC at FPR <= 1 % per network, arm and seed (Z1).
3. `fig3_scenarios.png`: the unsigned arm under each reference scenario against the null control.
4. `fig4_contamination.png`: partial AUC against the injected attack share of the reference.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports" / "phase8w"
OUT = ROOT / "docs" / "phase8w" / "figures"
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
LABEL = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN", "nfbot": "NF-BoT"}
ARM = {
    "R0": ("raw (null control)", "#4d4d4d"),
    "S": ("signed z", "#1f77b4"),
    "A": ("unsigned |z|", "#d95f02"),
}
SEEDS = ("1060", "1061")


def load(name: str) -> dict:
    return json.loads((REP / name).read_text("utf-8"))


def fig1() -> None:
    r = load("references.json")
    feats = r["features"]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), sharey=True)
    for ax, kind, title in zip(axes, ("raw", "abs_Z1"), ("raw value (= signed z within a network)",
                                                         "unsigned deviation |z|, unlabelled reference (Z1)"), strict=True):  # fmt: skip
        t = r["univariate"][kind]["per_network_auc"]
        m = np.array([[t[n][f] for n in NETS] for f in feats])
        im = ax.imshow(m, cmap="RdBu_r", vmin=0, vmax=1, aspect="auto")
        for i in range(m.shape[0]):
            for j in range(m.shape[1]):
                ax.text(j, i, f"{m[i, j]:.2f}", ha="center", va="center", fontsize=8,
                        color="white" if abs(m[i, j] - 0.5) > 0.3 else "black")  # fmt: skip
        ax.set_xticks(range(4), [LABEL[n] for n in NETS])
        ax.set_yticks(range(len(feats)), feats)
        ax.set_title(
            f"{title}\n{r['univariate'][kind]['n_conflicts']} of 12 features conflict", fontsize=10
        )
    fig.colorbar(
        im, ax=axes, label="univariate AUC (attack vs benign evaluation windows)", shrink=0.8
    )
    fig.suptitle(
        "Exploratory, no model: feature direction per network (evaluation labels of consumed networks)",
        fontsize=10,
    )
    fig.savefig(OUT / "fig1_direction.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig2() -> None:
    e = load("evaluation_screening.json")["summary"]["Z1"]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4), sharey=True)
    for ax, key, title in zip(axes, ("pauc_1pct", "recall_1pct"),
                              ("exact partial AUC, FPR <= 1 %", "recall at the retrospective 1 % FPR"), strict=True):  # fmt: skip
        for k, arm in enumerate(ARM):
            for j, n in enumerate(NETS):
                v = [e[arm][s]["networks"][n][key] for s in SEEDS]
                ax.bar(
                    j + (k - 1) * 0.26,
                    np.mean(v),
                    0.24,
                    color=ARM[arm][1],
                    alpha=0.55,
                    label=ARM[arm][0] if j == 0 else None,
                )
                ax.scatter(
                    [j + (k - 1) * 0.26] * 2,
                    v,
                    color=ARM[arm][1],
                    s=18,
                    zorder=3,
                    edgecolor="black",
                    linewidth=0.4,
                )
        ax.set_xticks(range(4), [LABEL[n] for n in NETS])
        ax.set_title(title, fontsize=10)
        ax.set_ylim(0, 1)
        ax.grid(axis="y", alpha=0.3)
    axes[0].legend(
        fontsize=8, title="bars: mean of two seeds; dots: seeds 1060, 1061", title_fontsize=7
    )
    fig.suptitle(
        "Screening, unlabelled target reference (Z1): no arm passed; the unsigned arm gains NF-UNSW and loses NF-BoT, NF-CIC and NF-ToN",
        fontsize=10,
    )
    fig.savefig(OUT / "fig2_partial_auc.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig3() -> None:
    e = load("evaluation_screening.json")
    kinds = {
        "Z0": "Z0 zero-shot",
        "Z1": "Z1 unlabelled",
        "Z2": "Z2 simulated review",
        "Z3": "Z3 oracle",
        "T": "T label-benign",
    }
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.6), sharey=True)
    for ax, n in zip(axes, NETS, strict=True):
        base = [e["summary"]["Z1"]["R0"][s]["networks"][n]["pauc_1pct"] for s in SEEDS]
        ax.axhline(
            np.mean(base), color=ARM["R0"][1], linestyle="--", label="raw (null control), mean"
        )
        for k, arm in enumerate(("S", "A")):
            for j, sc in enumerate(kinds):
                v = [e["summary"][sc][arm][s]["networks"][n]["pauc_1pct"] for s in SEEDS]
                ax.scatter([j + (k - 0.5) * 0.3] * 2, v, color=ARM[arm][1], s=22, edgecolor="black", linewidth=0.4,
                           label=ARM[arm][0] if j == 0 else None)  # fmt: skip
        ax.set_xticks(range(len(kinds)), list(kinds.values()), rotation=40, ha="right", fontsize=7)
        ax.set_title(LABEL[n], fontsize=10)
        ax.set_ylim(-0.02, 1)
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("exact partial AUC, FPR <= 1 %")
    axes[0].legend(fontsize=7)
    fig.suptitle(
        "Same boosters, different target reference (one block per scenario; Z2, Z3 and T are not deployable)",
        fontsize=10,
    )
    fig.savefig(OUT / "fig3_scenarios.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig4() -> None:
    st = load("posthoc_stress.json")
    shares = [str(s) for s in st["shares"]]
    x = [100 * float(s) for s in shares]
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.4), sharey=True)
    for ax, n in zip(axes, NETS, strict=True):
        ax.axhline(np.mean([st["null"][s]["pauc"][n] for s in st["null"]]), color=ARM["R0"][1], linestyle="--",
                   label="raw (null control)")  # fmt: skip
        for arm in ("S", "A"):
            runs = st["runs"][arm]
            for s in runs:
                ax.plot(
                    x,
                    [runs[s][sh]["pauc"][n] for sh in shares],
                    color=ARM[arm][1],
                    alpha=0.35,
                    linewidth=1,
                )
            ax.plot(x, [np.mean([runs[s][sh]["pauc"][n] for s in runs]) for sh in shares], color=ARM[arm][1], marker="o",
                    markersize=3, label=ARM[arm][0])  # fmt: skip
        ax.set_title(LABEL[n], fontsize=10)
        ax.set_xlabel("attack share injected (%)")
        ax.set_ylim(-0.02, 1)
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("exact partial AUC, FPR <= 1 %")
    axes[0].legend(fontsize=7)
    fig.suptitle(
        "Contamination stress (diagnostic): oracle-benign reference plus the evaluated attack; thin lines are seeds",
        fontsize=10,
    )
    fig.savefig(OUT / "fig4_contamination.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    fig1()
    fig2()
    fig3()
    fig4()
