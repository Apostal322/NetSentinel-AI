"""Phase 8h figures from reports/phase8h/analysis.json and the per-domain outputs (no compute).

fig1_oracle_recall.png        per-domain recall at FPR 1% (oracle threshold), models x domains
fig2_paired_deltas.png        paired H1a / H1b / H3 differences per held-out domain
fig3_threshold_fpr.png        realised label-benign FPR per unit under T0 / T1 / T2 / T3 / deployed
fig4_ablations.png            B-raw feature ablations, recall at FPR 1% per domain
fig5_calibration_length.png   calibration length vs units over twice the target (paired units)
fig6_benign_shift.png         benign KS within NF-CIC vs between NF-CIC and NF-UNSW
Usage: uv run python scripts/phase8h/figures.py -> docs/phase8h/figures/
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
import matplotlib.ticker

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


def fig4() -> None:
    """Ablations of B-raw: recall at FPR 1% (oracle), full vs ablated, per H1 domain."""
    ex = json.loads(Path("reports/phase8h/exploratory_summary.json").read_text("utf-8"))
    abl = ex["ablations"]
    names = ["no_volume", "no_new_dst_frac", "no_udp_share"]
    doms = [k for k, v in abl[names[0]]["per_domain"].items()
            if v["oracle_recall_at_fpr1"]["full"] is not None]  # fmt: skip
    fig, ax = plt.subplots(figsize=(8.5, 3.6))
    w = 0.2
    full = [abl[names[0]]["per_domain"][d]["oracle_recall_at_fpr1"]["full"] for d in doms]
    ax.bar(np.arange(len(doms)) - 1.5 * w, full, w, label="all 12 features", color="#264653")
    for i, (n, c) in enumerate(zip(names, ("#e76f51", "#f4a261", "#e9c46a"), strict=True)):
        v = [abl[n]["per_domain"][d]["oracle_recall_at_fpr1"]["ablated"] for d in doms]
        ax.bar(np.arange(len(doms)) + (i - 0.5) * w, v, w, label=n.replace("_", " "), color=c)
    ax.set_xticks(range(len(doms)), [short(d) + chr(10) + FAMILY.get(short(d), "") for d in doms],
                  fontsize=8)  # fmt: skip
    ax.set_ylabel("recall at FPR 1% (oracle)")
    ax.set_ylim(0, 1.05)
    ax.set_title("B-raw feature ablations (exploratory, 3 seeds, leave-one-domain-out)",
                 fontsize=10)  # fmt: skip
    ax.legend(fontsize=7, ncol=4, loc="lower left")
    fig.tight_layout()
    fig.savefig(OUT / "fig4_ablations.png", dpi=150)


def fig5() -> None:
    """Calibration length vs threshold exceedance, on the 11 units present at every length."""
    import glob

    res = {Path(p).stem: json.loads(Path(p).read_text("utf-8"))
           for p in glob.glob("reports/phase8h/calsize/*.json")}  # fmt: skip
    mins = ("15", "30", "60", "120")
    units = [k for k, r in res.items() if r["benign_windows"] >= 60 and r["role"] != "secondary"
             and all("T0" in r["calsize"].get(m, {}) for m in mins)]  # fmt: skip
    fig, ax = plt.subplots(figsize=(6, 3.4))
    for t, lab, c in (("T0", "split-conformal (T0)", "#e76f51"),
                      ("deployed_crossfit", "deployed cross-fit", "#2a9d8f")):  # fmt: skip
        e = [np.mean([res[k]["calsize"][m][t]["fpr"] > 2 * 0.01 for k in units]) for m in mins]
        ax.plot([int(m) for m in mins], e, "o-", label=lab, color=c)
    ax.set_xscale("log")
    ax.set_xticks([15, 30, 60, 120], ["15", "30", "60", "120"])
    ax.xaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
    ax.set_xlabel("calibration length (minutes before evaluation)")
    ax.set_ylabel("share of units with FPR > 2%")
    ax.set_ylim(0, 0.6)
    ax.set_title(f"Robust baseline: calibration length vs exceedance (n = {len(units)} units)",
                 fontsize=9)  # fmt: skip
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig5_calibration_length.png", dpi=150)


def fig6() -> None:
    """Benign feature shift: within NF-CIC (median KS across days) vs NF-CIC vs NF-UNSW."""
    d = json.loads(Path("reports/phase8h/shift_diagnostics.json").read_text("utf-8"))
    feats = list(d["benign_shift_cic_vs_unsw"])
    a = [d["benign_shift_within_cic_median_ks"][f] for f in feats]
    b = [d["benign_shift_cic_vs_unsw"][f]["ks"] for f in feats]
    fig, ax = plt.subplots(figsize=(8, 3.4))
    x = np.arange(len(feats))
    ax.bar(x - 0.2, a, 0.4, label="within NF-CIC (one day vs other days, median)", color="#2a9d8f")
    ax.bar(x + 0.2, b, 0.4, label="NF-CIC vs NF-UNSW", color="#e76f51")
    ax.set_xticks(x, feats, rotation=40, ha="right", fontsize=8)
    ax.set_ylabel("KS statistic, label-benign windows")
    auc = d["domain_identity_control"]["test_roc_auc"]
    ax.set_title(f"Benign covariate shift; network identity from benign windows: ROC-AUC {auc:.4f}",
                 fontsize=9)  # fmt: skip
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig6_benign_shift.png", dpi=150)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    fig1()
    fig2()
    fig3()
    fig4()
    fig5()
    fig6()
    print(sorted(p.name for p in OUT.glob("*.png")))
