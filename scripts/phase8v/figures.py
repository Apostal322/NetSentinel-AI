"""Phase 8v figures, generated only from saved reports.

Inputs: reports/phase8v/{telemetry_audit, learnability, evaluation_<tag>}.json
Output: docs/phase8v/figures/*.png
Usage: python scripts/phase8v/figures.py [evaluation tag, default _screening]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports/phase8v"
OUT = ROOT / "docs/phase8v/figures"
NETS = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN", "nfbot": "NF-BoT"}
SEEDS = (1060, 1061, 1062)


def telemetry() -> None:
    t = json.loads((REP / "telemetry_audit.json").read_text("utf-8"))["networks"]
    keys = ["any_retransmission", "fwd_iat_positive_when_2plus_pkts", "fwd_iat_positive_when_1_pkt",
            "size_bins_equal_total_pkts", "tcp_client_syn", "tcp_src_port_gt_dst_port", "no_reverse_packets",
            "duration_over_30s"]  # fmt: skip
    fig, ax = plt.subplots(figsize=(10, 3.6))
    for j, (n, lab) in enumerate(NETS.items()):
        ax.bar(
            np.arange(len(keys)) + (j - 1.5) * 0.2,
            [t[n]["checks"][k] for k in keys],
            0.2,
            label=lab,
        )
    ax.set_xticks(range(len(keys)), [k.replace("_", "\n") for k in keys], fontsize=6)
    ax.set_ylabel("share of sampled flows")
    ax.legend(fontsize=7)
    ax.set_title(
        "2/14. The same field does not mean the same thing in every network (development samples)",
        fontsize=9,
    )
    fig.tight_layout()
    fig.savefig(OUT / "02_telemetry_semantics.png", dpi=140)
    plt.close(fig)


def directions() -> None:
    lr = json.loads((REP / "learnability.json").read_text("utf-8"))
    feats = list(lr["direction"])
    m = np.array([[lr["direction"][f]["network_auc"][n] or np.nan for n in NETS] for f in feats])
    fig, ax = plt.subplots(figsize=(5.2, 8))
    im = ax.imshow(m, cmap="RdBu_r", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(4), list(NETS.values()), fontsize=7)
    ax.set_yticks(range(len(feats)), feats, fontsize=6)
    ax.axhline(11.5, color="k", lw=1)
    for i in range(m.shape[0]):
        for j in range(4):
            ax.text(j, i, f"{m[i, j]:.2f}", ha="center", va="center", fontsize=5)
    fig.colorbar(im, ax=ax, fraction=0.04, label="univariate ROC-AUC, attack vs benign")
    ax.set_title(
        "1. Feature directions by network\n(above the line: the 12 original features; EXPLORATORY)",
        fontsize=8,
    )
    fig.tight_layout()
    fig.savefig(OUT / "01_feature_directions.png", dpi=140)
    plt.close(fig)


def within_and_origin() -> None:
    lr = json.loads((REP / "learnability.json").read_text("utf-8"))
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.4))
    doms = [n for n, w in lr["within_network"].items() if w["chronological"]]
    sets = ["F0", "F0+FLOW", "F0+TIME", "F0+BIDIR", "F0+ALL"]
    for j, s in enumerate(sets):
        axes[0].bar(np.arange(len(doms)) + (j - 2) * 0.16,
                    [lr["within_network"][d]["chronological"][s]["pauc"] for d in doms], 0.16, label=s)  # fmt: skip
    axes[0].set_xticks(
        range(len(doms)),
        [d.replace("/all", "").replace("nfcic/2018-", "CIC ") for d in doms],
        fontsize=7,
    )
    axes[0].set_ylabel("exact partial AUC (FPR ≤ 1 %), second half")
    axes[0].set_title("10. In-network learnability, chronological split (EXPLORATORY)", fontsize=8)
    axes[0].legend(fontsize=6)
    o = lr["domain_origin_accuracy"]
    axes[1].bar(range(len(o)), list(o.values()))
    axes[1].axhline(0.25, color="k", ls=":", lw=0.8)
    axes[1].set_xticks(range(len(o)), [k.replace(" ", "\n") for k in o], fontsize=6)
    axes[1].set_ylabel("accuracy (chance 0.25)")
    axes[1].set_title("15. Network identified from benign windows", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "10_within_network_and_origin.png", dpi=140)
    plt.close(fig)


def comparison(tag: str) -> None:
    ev = json.loads((REP / f"evaluation{tag}.json").read_text("utf-8"))
    s = ev["summary"]
    variants = ["M2member"] + [v for v in ("FLOW", "TIME", "BIDIR", "INV") if f"{v}|1060" in s]
    fig, axes = plt.subplots(1, 3, figsize=(14, 3.4))
    for ax, f, lab, sc in ((axes[0], "pauc_1pct", "exact partial AUC (FPR ≤ 1 %)", 1), (axes[1], "recall_1pct", "recall at retrospective 1 % FPR", 1),
                           (axes[2], "calT_fpr", "as-calibrated FPR (%)", 100)):  # fmt: skip
        for j, v in enumerate(variants):
            ax.bar(np.arange(4) + (j - (len(variants) - 1) / 2) * 0.8 / len(variants),
                   [s[f"{v}|1060"]["networks"][n][f] * sc for n in NETS], 0.8 / len(variants),
                   label="frozen member" if v == "M2member" else v)  # fmt: skip
        ax.set_xticks(range(4), list(NETS.values()))
        ax.set_yscale("symlog", linthresh=0.01 if sc == 1 else 1)
        ax.set_title(lab, fontsize=9)
    axes[0].legend(fontsize=7)
    fig.suptitle(
        "7/8/9. Registered screening, seed 1060 (single member; development networks)", fontsize=9
    )
    fig.tight_layout()
    fig.savefig(OUT / "07_screening.png", dpi=140)
    plt.close(fig)
    rep = [v for v in variants[1:] if all(f"{v}|{sd}" in s for sd in SEEDS)]
    if rep:
        fig, axes = plt.subplots(1, 4, figsize=(13, 3.2))
        for ax, (n, lab) in zip(axes, NETS.items(), strict=True):
            for v in ["M2member", *rep]:
                ax.plot(SEEDS, [s[f"{v}|{sd}"]["networks"][n]["pauc_1pct"] for sd in SEEDS], marker="o",
                        label="frozen member" if v == "M2member" else v)  # fmt: skip
            ax.set_title(lab, fontsize=9)
            ax.set_xticks(SEEDS)
        axes[0].set_ylabel("exact partial AUC (FPR ≤ 1 %)")
        axes[0].legend(fontsize=7)
        fig.suptitle("Paired seeds: replicated candidate vs frozen member", fontsize=9)
        fig.tight_layout()
        fig.savefig(OUT / "09_seed_pairs.png", dpi=140)
        plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    telemetry()
    directions()
    within_and_origin()
    tag = sys.argv[1] if len(sys.argv) > 1 else "_screening"
    if (REP / f"evaluation{tag}.json").exists():
        comparison(tag)
