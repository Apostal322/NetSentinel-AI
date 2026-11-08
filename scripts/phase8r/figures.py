"""Phase 8r figures from the saved reports (no computation beyond lookup).

Output: docs/phase8r/figures/{identified_sets,trusted_tradeoff,contamination}.png
Usage: python scripts/phase8r/figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
R = ROOT / "reports" / "phase8r"
OUT = ROOT / "docs" / "phase8r" / "figures"
NETS = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN", "nfbot": "NF-BoT"}


def identified_sets() -> None:
    d = json.loads((R / "identifiability.json").read_text("utf-8"))["domains"]
    doms = ["nfcic/2018-02-22", "nfcic/2018-03-02", "nfunsw/all", "nfton/all", "nfbot/all"]
    bars = ["0.01", "0.05", "0.10", "0.30", "true"]
    fig, ax = plt.subplots(figsize=(8, 3.6))
    for i, name in enumerate(doms):
        for j, b in enumerate(bars):
            lo, hi = d[name]["identified_sets"][b]["fpr_range"]
            x = i + (j - 2) * 0.14
            ax.plot([x, x], [100 * lo, 100 * hi], lw=5, color=f"C{j}", solid_capstyle="butt",
                    label=(f"ε̄ = {b}" if b != "true" else "ε̄ = true ε") if i == 0 else None)  # fmt: skip
    ax.set_xticks(
        range(len(doms)), [n.replace("nfcic/2018-", "NF-CIC ").replace("/all", "") for n in doms]
    )
    ax.set_ylabel("evaluation FPR over the identified set (%)")
    ax.set_yscale("log")
    ax.axhline(1, color="k", lw=0.6, ls=":")
    ax.legend(fontsize=7, ncol=5, loc="upper left")
    ax.set_title("Benign-threshold identified sets (Horowitz–Manski), mean of 6 fits", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "identified_sets.png", dpi=150)


def trusted_tradeoff() -> None:
    a = json.loads((R / "experiment_a.json").read_text("utf-8"))
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.3))
    for ax, (n, lab) in zip(axes, NETS.items(), strict=True):
        for ref, mk in (("A0", "s"), ("A1", "*"), ("A1T", "D")):
            v = a["references"][ref]["networks"][n]
            ax.scatter(100 * v["fpr"], v["recall"], marker=mk, s=60, color="k", zorder=3)
            ax.annotate(
                ref,
                (100 * v["fpr"], v["recall"]),
                fontsize=7,
                xytext=(3, 3),
                textcoords="offset points",
            )
        for j, pol in enumerate(
            ("random", "diversity", "temporal_block", "service_diverse", "admin_persistent")
        ):
            xs, ys = [], []
            for b in ("small", "modest", "larger"):
                c = a["cells"][f"{b}|{pol}|e0"]["A3"]["networks"][n]
                xs.append(100 * c["fpr"])
                ys.append(c["recall"])
            ax.plot(xs, ys, "-o", ms=3, color=f"C{j}", label=pol if n == "nfcic" else None)
        ax.set_xscale("symlog", linthresh=1)
        ax.set_title(lab, fontsize=9)
        ax.set_xlabel("FPR (%)")
        ax.set_ylim(-0.02, 1.02)
    axes[0].set_ylabel("documented-attacker recall")
    fig.legend(fontsize=7, loc="lower center", ncol=5)
    fig.suptitle(
        "Experiment A: A3 by policy, budgets small → modest → larger (ORACLE-SIMULATED vetting)",
        fontsize=9,
    )
    fig.tight_layout(rect=(0, 0.08, 1, 0.95))
    fig.savefig(OUT / "trusted_tradeoff.png", dpi=150)


def contamination() -> None:
    b = json.loads((R / "experiment_b.json").read_text("utf-8"))
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.2), sharey=True)
    for ax, m in zip(axes, ("A2", "A3", "A4"), strict=True):
        for j, (mech, cells) in enumerate(b["cells"][m].items()):
            fr = sorted(cells, key=float)
            ax.plot([100 * float(f) for f in fr], [cells[f]["delta_macro_recall"] for f in fr], "-o", ms=3,
                    color=f"C{j}", label=mech if m == "A2" else None)  # fmt: skip
        ax.axhline(-0.10, color="k", lw=0.6, ls=":")
        ax.set_title(m, fontsize=9)
        ax.set_xlabel("contamination of the trusted set (%)")
    axes[0].set_ylabel("paired Δ macro recall")
    fig.legend(fontsize=7, loc="lower center", ncol=6)
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    fig.savefig(OUT / "contamination.png", dpi=150)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    identified_sets()
    trusted_tradeoff()
    contamination()
