"""Phase 8h figures from reports/phase8h/analysis.json and the per-domain outputs (no compute).

fig1_oracle_recall.png   per-domain recall at FPR 1% (oracle threshold), models x domains
fig2_h1_deltas.png       paired H1a / H1b / H3 differences per held-out domain
fig3_threshold_fpr.png   realised label-benign FPR per unit under T0 / T1 / T2 / T3 / deployed
Usage: uv run python scripts/phase8h/figures.py -> docs/phase8h/figures/
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

A = json.loads(Path("reports/phase8h/analysis.json").read_text("utf-8"))
OUT = Path("docs/phase8h/figures")
MODELS = ["B-rz", "B-lr", "B-raw", "B-loc", "N-dis", "F-or"]


def short(k: str) -> str:
    n = k.split("__")[1]
    return {"NF-UNSW-NB15-v3-dev": "NF-UNSW", "CTU-IoT-Malware-Capture-3-1": "IoT-23 3-1",
            "CTU-IoT-Malware-Capture-34-1": "IoT-23 34-1",
            "CTU-IoT-Malware-Capture-8-1": "IoT-23 8-1"}.get(
        n, n.replace("nfcic_2018-", "CIC "))  # fmt: skip


FAMILY = {"CIC 02-14": "SSH-BF", "CIC 02-16": "DoS-Hulk", "CIC 02-20": "DDoS-LOIC",
          "CIC 02-21": "DDoS-HOIC", "CIC 03-02": "Bot"}  # fmt: skip


def fig1() -> None:
    t = A["macro_table_primary"]
    doms = [k for k in t["B-raw"]["per_domain"] if t["B-raw"]["per_domain"][k][
        "oracle_recall_at_fpr1"] is not None]  # fmt: skip
    M = np.array([[t[m]["per_domain"][d]["oracle_recall_at_fpr1"] for d in doms] for m in MODELS])  # noqa: N806
    fig, ax = plt.subplots(figsize=(8.5, 3.8))
    im = ax.imshow(M, vmin=0, vmax=1, cmap="viridis", aspect="auto")
    labels = [f"{short(d)}\n{FAMILY.get(short(d), '')}" for d in doms]
    ax.set_xticks(range(len(doms)), labels, fontsize=8)
    ax.set_yticks(range(len(MODELS)), MODELS)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            ax.text(j, i, f"{M[i, j]:.2f}", ha="center", va="center", fontsize=7,
                    color="white" if M[i, j] < 0.6 else "black")  # fmt: skip
    ax.set_title("Recall at 1% FPR on the held-out domain's label-benign windows (oracle)")
    fig.colorbar(im, ax=ax, fraction=0.03)
    fig.tight_layout()
    fig.savefig(OUT / "fig1_oracle_recall.png", dpi=150)


def fig2() -> None:
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.6))
    for ax, (h, title) in zip(axes, (("H1a", "H1a: B-loc − B-raw"), ("H1b", "H1b: N-dis − B-loc"),
                                     ("H3", "H3: F-or − best single")), strict=True):  # fmt: skip
        r = A[h]
        names = [short(n) for n in r["domains"]]
        d = np.array(r["deltas"])
        ax.barh(range(len(d)), d, color=["#2a9d8f" if v >= 0 else "#e76f51" for v in d])
        ax.axvline(0, color="k", lw=0.8)
        ax.axvline(0.05, color="grey", ls="--", lw=0.8)
        ax.set_yticks(range(len(d)), names, fontsize=8)
        ax.set_xlim(-1.05, 1.05)
        ax.set_title(f"{title}\nmean {r['mean']:+.3f} [{r['ci95'][0]:+.2f}, {r['ci95'][1]:+.2f}]",
                     fontsize=9)  # fmt: skip
        ax.invert_yaxis()
    fig.suptitle("Paired differences per held-out domain (dashed: registered minimum effect)",
                 fontsize=10)  # fmt: skip
    fig.tight_layout()
    fig.savefig(OUT / "fig2_paired_deltas.png", dpi=150)


def fig3() -> None:
    src = Path("reports/phase8h/lodo_h2")
    rows = []
    for p in sorted(src.glob("*.json")):
        r = json.loads(p.read_text("utf-8"))
        if r["benign_windows"] < 60 or r["role"] == "secondary":
            continue
        b = r["B-rz"]
        rows.append([b[t].get("fpr") if t != "T3" else (None if b["T3"]["abstain"] else
                     b["T3"].get("fpr")) for t in ("T0", "T1", "T2", "T3")]
                    + [b["deployed_crossfit"].get("fpr")])  # fmt: skip
    cols = ["T0 split-\nconformal", "T1 block-\nbootstrap", "T2 popu-\nlation", "T3 selective",
            "deployed\ncross-fit"]  # fmt: skip
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    ticks = []
    for j in range(len(cols)):
        v = np.array([r[j] for r in rows if r[j] is not None]) * 100
        ax.scatter(np.full(len(v), j) + np.random.default_rng(j).uniform(-0.15, 0.15, len(v)),
                   v, s=14, alpha=0.7)  # fmt: skip
        ticks.append(f"{cols[j]}" + chr(10) + f"> 2%: {np.mean(v > 2):.0%} (n={len(v)})")
    ax.axhline(1, color="k", lw=0.8, label="target 1%")
    ax.axhline(2, color="grey", ls="--", lw=0.8, label="exceedance 2%")
    ax.set_yscale("symlog", linthresh=1)
    ax.set_ylim(0, 40)
    ax.set_xticks(range(len(cols)), ticks, fontsize=8)
    ax.set_ylabel("realised FPR, label-benign windows (%)")
    ax.set_title(
        "Robust baseline: threshold reliability on 27 benign evaluation units", fontsize=10
    )
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    fig.savefig(OUT / "fig3_threshold_fpr.png", dpi=150)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    fig1()
    fig2()
    fig3()
    print(sorted(p.name for p in OUT.glob("*.png")))
