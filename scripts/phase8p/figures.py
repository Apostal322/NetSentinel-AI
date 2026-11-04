"""Phase 8p figures, drawn only from saved results (reports/phase8p/*.json). Each answers one
question.

1. missed_by_role.png       Which evaluation entities are missed, by role (label audit)?
2. observability.png        Is there in-domain evidence on the source / victim side per group?
3. arm_tradeoff.png         Per network: documented recall change vs false-alert ratio, arms vs S0
4. ranking_vs_operational.png  Do ranking gains (oracle) survive the calibrated threshold?
5. victim_transfer.png      Victim-only model (D1): cross-network AUC per target domain
6. calibration_scenarios.png  H4: recall and FPR per network under C0-C3

Usage: python scripts/phase8p/figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports" / "phase8p"
FIG = ROOT / "docs" / "phase8p" / "figures"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
NAMES = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN-IoT", "nfbot": "NF-BoT-IoT"}
ARMS = ("D2", "S1", "D2S", "D3", "Sonly")
COL = {"S0": "#444444", "D2": "#d62728", "S1": "#1f77b4", "D2S": "#9467bd", "D3": "#ff7f0e", "Sonly": "#8c8c8c",
       "C0": "#444444", "C1": "#d62728", "C2": "#ff7f0e", "C3": "#1f77b4"}  # fmt: skip


def save(fig, name: str) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=130)
    plt.close(fig)


def missed_by_role(obs: dict) -> None:
    ro = obs["role_outcomes"]
    roles = list(ro)
    fig, ax = plt.subplots(figsize=(7, 3.2))
    det = [ro[r]["detected_ge20_in_all_fits"] for r in roles]
    never = [ro[r]["never_ge20"] for r in roles]
    other = [ro[r]["entities"] - a - b for r, a, b in zip(roles, det, never, strict=True)]
    y = np.arange(len(roles))
    ax.barh(y, det, color="#2ca02c", label="detected ≥ 20 % in all 6 fits")
    ax.barh(y, other, left=det, color="#bbbbbb", label="in some fits")
    ax.barh(y, never, left=np.add(det, other), color="#d62728", label="never ≥ 20 %")
    ax.set_yticks(y, [r.replace("_", " ") for r in roles])
    ax.set_xlabel("evaluation entities (M2 = Phase 8o F0, K = 5)")
    ax.legend(fontsize=7, frameon=False, loc="lower right")
    save(fig, "missed_by_role.png")


def observability(obs: dict) -> None:
    g = obs["groups"]
    names = list(g)
    best = {s: [max(max(v["auc"], 1 - v["auc"]) for v in g[n][s]["univariate"].values()) for n in names]
            for s in ("source", "victim")}  # fmt: skip
    fig, ax = plt.subplots(figsize=(8, 4))
    y = np.arange(len(names))
    ax.barh(y - 0.2, best["source"], 0.4, label="source windows", color="#444444")
    ax.barh(y + 0.2, best["victim"], 0.4, label="victim windows", color="#d62728")
    ax.set_yticks(y, [n.replace("nfcic/", "CIC ") for n in names], fontsize=7)
    ax.set_xlim(0.5, 1.0)
    ax.set_xlabel("best single-feature AUC, in-domain (attack windows vs verified benign)")
    ax.legend(fontsize=7, frameon=False)
    save(fig, "observability.png")


def arm_tradeoff(e: dict) -> None:
    s0 = e["arms"]["S0"]["networks"]
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.2), sharey=True)
    for ax, n in zip(axes, NETWORKS, strict=True):
        for a in ARMS:
            if a not in e["arms"]:
                continue
            v = e["arms"][a]["networks"][n]
            ratio = v["fa"] / s0[n]["fa"] if s0[n]["fa"] else np.nan
            ax.scatter(
                np.log2(max(ratio, 1 / 64)),
                (v["recall_doc"] or 0) - (s0[n]["recall_doc"] or 0),
                color=COL[a],
                label=a,
                s=36,
            )
        ax.axhline(0, color="#999999", lw=0.6)
        ax.axvline(np.log2(1.10), color="#999999", lw=0.6, ls="--")
        ax.set_title(NAMES[n], fontsize=9)
        ax.set_xlabel("log2 (false alerts / S0)", fontsize=8)
    axes[0].set_ylabel("documented-attacker recall − S0")
    axes[0].legend(fontsize=6, frameon=False)
    fig.suptitle(
        "Arms vs S0 per network; dashed line = false-alert guardrail 1.10 × S0", fontsize=9
    )
    save(fig, "arm_tradeoff.png")


def ranking_vs_operational(e: dict) -> None:
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.2), sharey=True)
    for ax, n in zip(axes, NETWORKS, strict=True):
        for a in ("S0",) + ARMS:
            if a not in e["arms"] or a == "D3":  # fused CDF score: tie-heavy, diagnostic undefined
                continue
            v = e["arms"][a]["networks"][n]
            ax.scatter(v["ranking_recall"] or 0, v["recall"] or 0, color=COL[a], label=a, s=36)
        ax.plot([0, 1], [0, 1], color="#cccccc", lw=0.6)
        ax.set_title(NAMES[n], fontsize=9)
        ax.set_xlabel("ranking recall at benign q99 (oracle)")
    axes[0].set_ylabel("operational recall at T0")
    axes[0].legend(fontsize=6, frameon=False)
    save(fig, "ranking_vs_operational.png")


def victim_transfer(e: dict) -> None:
    vu = e["victim_units"]
    doms = sorted(next(iter(vu["D1"].values())))
    fig, ax = plt.subplots(figsize=(8, 3.5))
    x = np.arange(len(doms))
    for i, arm in enumerate(("D1", "D1h")):
        aucs = [
            np.mean([f[d]["auc"] for f in vu[arm].values() if f[d]["auc"] is not None])
            for d in doms
        ]
        ax.bar(
            x + (i - 0.5) * 0.4,
            aucs,
            0.4,
            label=f"{arm} (cross-network)",
            color=["#d62728", "#ff9896"][i],
        )
    ax.axhline(0.5, color="#444444", lw=0.6)
    ax.set_xticks(x, [d.replace("nfcic/2018-", "CIC ") for d in doms], rotation=30, fontsize=7)
    ax.set_ylabel("victim-window AUC (attack vs attack-free)")
    ax.legend(fontsize=7, frameon=False)
    save(fig, "victim_transfer.png")


def calibration_scenarios(e: dict) -> None:
    sc = e["H4"]["scenarios"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 3.4))
    x = np.arange(len(NETWORKS))
    for i, c in enumerate(sc):
        a1.bar(
            x + (i - 1.5) * 0.2,
            [sc[c]["networks"][n]["recall_doc"] or 0 for n in NETWORKS],
            0.2,
            color=COL[c],
            label=c,
        )
        a2.bar(
            x + (i - 1.5) * 0.2,
            [sc[c]["networks"][n]["fpr"] for n in NETWORKS],
            0.2,
            color=COL[c],
            label=c,
        )
    for ax, lab in ((a1, "documented-attacker recall"), (a2, "verified-benign FPR")):
        ax.set_xticks(x, [NAMES[n] for n in NETWORKS], fontsize=8)
        ax.set_ylabel(lab)
    a2.axhline(0.01, color="#999999", lw=0.6, ls="--")
    a1.legend(fontsize=7, frameon=False)
    save(fig, "calibration_scenarios.png")


def main() -> None:
    obs = json.loads((REP / "observability.json").read_text("utf-8"))
    missed_by_role(obs)
    observability(obs)
    e = json.loads((REP / "experiment_e.json").read_text("utf-8"))
    arm_tradeoff(e)
    ranking_vs_operational(e)
    victim_transfer(e)
    calibration_scenarios(e)


if __name__ == "__main__":
    main()
