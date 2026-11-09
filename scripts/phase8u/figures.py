"""Phase 8u figures from saved outputs.

Inputs: reports/phase8u/evaluation_final.json, mining.json, posthoc.json.
Output: docs/phase8u/figures/*.png
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
R = json.loads((ROOT / "reports/phase8u/evaluation_final.json").read_text("utf-8"))
M = json.loads((ROOT / "reports/phase8u/mining.json").read_text("utf-8"))
OUT = ROOT / "docs/phase8u/figures"
NETS = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN", "nfbot": "NF-BoT"}
SEEDS = (1060, 1061, 1062)
S = R["summary"]


def screening() -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 3.4))
    for ax, f, lab in (
        (axes[0], "pauc_1pct", "normalised pAUC (FPR ≤ 1 %)"),
        (axes[1], "recall_1pct", "recall at retrospective 1 % FPR"),
    ):
        vs = ("M2member", "A1", "A2", "B", "C1")
        for j, v in enumerate(vs):
            ax.bar(
                np.arange(4) + (j - 2) * 0.16,
                [S[f"{v}|1060"]["networks"][n][f] for n in NETS],
                0.16,
                label=v,
            )
        ax.set_xticks(range(4), list(NETS.values()))
        ax.set_yscale("symlog", linthresh=0.01)
        ax.set_ylabel(lab)
    axes[0].legend(fontsize=7)
    fig.suptitle(
        "2/5. Screening, seed 1060 (single member; M2member = frozen baseline)", fontsize=9
    )
    fig.tight_layout()
    fig.savefig(OUT / "02_screening.png", dpi=140)
    plt.close(fig)


def seeds() -> None:
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.2), sharey=False)
    for ax, (n, lab) in zip(axes, NETS.items(), strict=True):
        for v, mk in (("M2member", "o"), ("B", "s")):
            ax.plot(
                SEEDS,
                [S[f"{v}|{s}"]["networks"][n]["pauc_1pct"] for s in SEEDS],
                marker=mk,
                label=v,
            )
        ax.set_title(lab, fontsize=9)
        ax.set_xticks(SEEDS)
    axes[0].set_ylabel("normalised pAUC (FPR ≤ 1 %)")
    axes[0].legend(fontsize=7)
    fig.suptitle(
        "7/12. Paired seeds: B vs frozen baseline member (same seed, same sources)", fontsize=9
    )
    fig.tight_layout()
    fig.savefig(OUT / "07_seed_pairs.png", dpi=140)
    plt.close(fig)


def operational() -> None:
    fig, axes = plt.subplots(1, 3, figsize=(13, 3.2))
    for ax, f, lab, sc in ((axes[0], "calT_recall", "recall (as calibrated, CAL_T)", 1), (axes[1], "calT_fpr", "FPR % (as calibrated)", 100),
                           (axes[2], "calT_fa_per_h", "false alerts per hour", 1)):  # fmt: skip
        for j, v in enumerate(("M2member", "B")):
            vals = np.array([[S[f"{v}|{s}"]["networks"][n][f] * sc for n in NETS] for s in SEEDS])
            ax.bar(np.arange(4) + (j - 0.5) * 0.35, vals.mean(0), 0.35, yerr=[vals.mean(0) - vals.min(0), vals.max(0) - vals.mean(0)],
                   capsize=3, label=v)  # fmt: skip
        ax.set_xticks(range(4), list(NETS.values()))
        ax.set_title(lab, fontsize=9)
        if f != "calT_recall":
            ax.set_yscale("symlog", linthresh=1)
    axes[0].legend(fontsize=7)
    fig.suptitle("10. Operational behaviour (mean over 3 seeds; bars = seed range)", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "10_operational.png", dpi=140)
    plt.close(fig)


def mining() -> None:
    comp = M["composition"]
    fig, ax = plt.subplots(figsize=(9, 3.4))
    rows = sorted(comp.items())
    labs = [k.replace("nfcic/2018-", "CIC ").replace("/all", "") for k, _ in rows]
    prof_names = ["TCP 1", "TCP 2-5", "TCP >5", "UDP 1", "UDP 2-5", "UDP >5"]
    bottom = np.zeros(len(rows))
    for p in range(6):
        v = np.array([r["profile_mined"][str(p)] / max(r["mined"], 1) for _, r in rows])
        ax.bar(range(len(rows)), v, bottom=bottom, label=prof_names[p])
        bottom += v
    ax.set_xticks(range(len(rows)), labs, rotation=90, fontsize=5)
    ax.set_ylabel("share of mined hard negatives")
    ax.legend(fontsize=6, ncol=6)
    ax.set_title(
        "4. Hard-negative composition by service profile (target | source domain)", fontsize=9
    )
    fig.tight_layout()
    fig.savefig(OUT / "04_hard_negative_composition.png", dpi=140)
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    screening()
    seeds()
    operational()
    mining()
