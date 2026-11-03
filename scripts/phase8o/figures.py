"""Phase 8o figures, drawn only from saved results (reports/phase8o/*.json). Each answers one
question of docs/phase8o/PREREGISTRATION.md.

1. novelty_by_row_type.png   Do training, hold-out and evaluation rows share novelty semantics?
2. novelty_by_age.png        Does benign novelty rise as the frozen memory ages (by quarter)?
3. recall_by_domain.png      Arms F0-F5 (K = 5): window recall per domain, min-max over fits
4. entity_recall.png         H3: per entity, worst-fit recall of single members vs K = 5
5. fpr_vs_recall.png         H4: per network, FPR against recall for T0, C1, C2, C3, C4
6. ensemble_size.png         H2: unstable entities and macro recall against K
7. ensemble_cost.png         H2: measured throughput, latency and artifact size against K
8. margin_sensitivity.png    H3: per entity, median score margin to T0 (single members, K = 5)
9. failure_frequency.png     How often each arm's fits collapse or lose entities

Usage: python scripts/phase8o/figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "reports" / "phase8o"
FIG = ROOT / "docs" / "phase8o" / "figures"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
NAMES = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN-IoT", "nfbot": "NF-BoT-IoT"}
ARMS = ("F0", "F1", "F4", "F2", "F5")
COLOUR = {"F0": "#444444", "F1": "#d62728", "F4": "#7f7f7f", "F2": "#1f77b4", "F5": "#2ca02c",
          "T0": "#444444", "C1": "#d62728", "C2": "#ff7f0e", "C3": "#1f77b4", "C4_exploratory": "#9467bd"}  # fmt: skip


def save(fig, name: str) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=130)
    plt.close(fig)


def novelty_by_row_type(audit: dict) -> None:
    rows = []
    for name, v in audit["sources"].items():
        rows.append((name, v["cal_expanding_benign"].get("share_pos"),
                     v["eval_frozen_benign"].get("share_pos"), v["eval_frozen_attack"].get("share_pos")))  # fmt: skip
    fig, ax = plt.subplots(figsize=(8, 5))
    y = np.arange(len(rows))
    for i, (lab, c) in enumerate((("calibration rows, expanding (benign)", "#1f77b4"),
                                  ("evaluation rows, frozen (benign)", "#ff7f0e"),
                                  ("evaluation rows, frozen (attack)", "#d62728"))):  # fmt: skip
        ax.barh(y + (i - 1) * 0.27, [r[i + 1] or 0 for r in rows], 0.27, color=c, label=lab)
    ax.set_yticks(y, [r[0] for r in rows], fontsize=7)
    ax.set_xlabel("share of source training rows with new_dst_frac > 0")
    ax.set_title("Training rows: memory semantics and label are confounded", fontsize=10)
    ax.legend(fontsize=7, frameon=False, loc="lower right")
    save(fig, "novelty_by_row_type.png")


def novelty_by_age(audit: dict) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    for name, v in audit["targets"].items():
        q = [v["eval_benign_by_quarter"][str(i)].get("share_pos") for i in range(4)]
        xs = [i for i in range(4) if q[i] is not None]
        line = ax.plot([-1] + [x for x in xs], [v["holdout_benign_expanding"]["share_pos"]] + [q[i] for i in xs],
                       marker="o", lw=1, label=name)  # fmt: skip
        line[0].set_alpha(0.8)
    ax.set_xticks([-1, 0, 1, 2, 3], ["T0 hold-out", "eval Q1", "Q2", "Q3", "Q4"])
    ax.set_yscale("log")
    ax.set_ylabel("benign windows with new_dst_frac > 0")
    ax.set_title("Benign novelty: calibration hold-out vs evaluation quarters", fontsize=10)
    ax.legend(fontsize=6, frameon=False, ncol=2)
    save(fig, "novelty_by_age.png")


def recall_by_domain(d: dict) -> None:
    arms = [a for a in ARMS if a in d["arms"]]
    doms = sorted(d["arms"]["F0"]["per_domain"])
    fig, ax = plt.subplots(figsize=(9, 4.5))
    x = np.arange(len(doms))
    w = 0.8 / len(arms)
    for i, a in enumerate(arms):
        pd = d["arms"][a]["per_domain"]
        mean = [pd[n]["mean"] for n in doms]
        lo = [pd[n]["mean"] - pd[n]["min"] for n in doms]
        hi = [pd[n]["max"] - pd[n]["mean"] for n in doms]
        ax.bar(x + (i - len(arms) / 2 + 0.5) * w, mean, w, yerr=[lo, hi], capsize=1.5,
               color=COLOUR[a], label=a, error_kw={"lw": 0.6})  # fmt: skip
    ax.set_xticks(x, [n.replace("nfcic/2018-", "CIC ") for n in doms], rotation=30, fontsize=7)
    ax.set_ylabel("window recall at T0 (K = 5; bars min-max over fits)")
    ax.legend(fontsize=7, frameon=False, ncol=5)
    save(fig, "recall_by_domain.png")


def entity_recall(d: dict) -> None:
    s, k5 = d["H3"]["entities_single"], d["H3"]["entities_K5"]
    keys = sorted(s, key=lambda e: k5[e]["recall_median"])
    fig, ax = plt.subplots(figsize=(9, 4))
    x = np.arange(len(keys))
    ax.scatter(
        x,
        [s[e]["recall_min"] for e in keys],
        s=8,
        color="#ff7f0e",
        label="single member: worst of 30 fits",
    )
    ax.scatter(
        x, [k5[e]["recall_min"] for e in keys], s=8, color="#d62728", label="K = 5: worst of 6 fits"
    )
    ax.plot(
        x, [k5[e]["recall_median"] for e in keys], color="#444444", lw=0.8, label="K = 5: median"
    )
    ax.axhline(0.2, color="#999999", lw=0.6, ls="--")
    ax.set_xlabel("attacker entity (sorted by K = 5 median recall)")
    ax.set_ylabel("entity window recall at T0")
    ax.legend(fontsize=7, frameon=False)
    save(fig, "entity_recall.png")


def fpr_vs_recall(d: dict) -> None:
    cal = d["H4"]["K5"]
    marker = {"T0": "o", "C1": "s", "C2": "D", "C3": "^", "C4_exploratory": "v"}
    floor = 1e-4  # FPR 0 (nothing assessed or no alert) is drawn on the axis floor
    fig, axes = plt.subplots(1, 4, figsize=(12, 3.4), sharey=True)
    for ax, n in zip(axes, NETWORKS, strict=True):
        for m, s in cal.items():
            v = s["networks"][n]
            if v["fpr"] is not None and v["recall"] is not None:
                ax.scatter(max(v["fpr"], floor), v["recall"], color=COLOUR[m], marker=marker[m],
                           label=m, s=36, alpha=0.75, edgecolors="none")  # fmt: skip
        ax.axvline(0.01, color="#999999", lw=0.6, ls="--")
        ax.set_xscale("log")
        ax.set_xlim(floor / 1.5, 0.5)
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(NAMES[n], fontsize=9)
        ax.set_xlabel("FPR (log; α = 1 % dashed)")
    axes[0].set_ylabel("window recall (K = 5, 6 fits)")
    axes[0].legend(fontsize=6, frameon=False, loc="lower left")
    fig.suptitle("Calibration methods: points at the left edge have FPR 0 (unassessed or no alerts)",
                 fontsize=9)  # fmt: skip
    save(fig, "fpr_vs_recall.png")


def ensemble_size(d: dict) -> None:
    by = d["H2"]["by_K"]
    ks = sorted(int(k) for k in by)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.5))
    for lv, c in (("1", "#d62728"), ("20", "#1f77b4"), ("50", "#2ca02c")):
        a1.plot(
            ks,
            [by[str(k)]["U"][lv] for k in ks],
            marker="o",
            color=c,
            label=f"U (≥ {lv}{'' if lv == '1' else ' %'} {'window' if lv == '1' else 'of windows'})",
        )
    sp = d["H2"].get("subset_spread_exploratory", {})
    for k, v in sp.items():
        a1.scatter([int(k)] * len(v["U1"]), v["U1"], s=6, color="#d62728", alpha=0.3)
    a1.set_xlabel("K (members)")
    a1.set_ylabel("unstable entities over 6 fits")
    a1.legend(fontsize=7, frameon=False)
    for n in NETWORKS:
        a2.plot(ks, [by[str(k)]["networks"][n]["recall"] for k in ks], marker="o", label=NAMES[n])
    a2.set_xlabel("K (members)")
    a2.set_ylabel("window recall (mean of 6 fits)")
    a2.legend(fontsize=7, frameon=False)
    save(fig, "ensemble_size.png")


def ensemble_cost(p: dict) -> None:
    ks = sorted(int(k) for k in p["K"])
    v = [p["K"][str(k)] for k in ks]
    fig, axes = plt.subplots(1, 3, figsize=(10, 3))
    axes[0].plot(ks, [x["windows_per_s_2t"] for x in v], marker="o", label="2 threads")
    axes[0].plot(ks, [x["windows_per_s_1t"] for x in v], marker="o", label="1 thread")
    axes[0].set_ylabel("windows scored per second")
    axes[0].legend(fontsize=7, frameon=False)
    axes[1].plot(ks, [x["single_window_ms_median"] for x in v], marker="o", label="median")
    axes[1].plot(ks, [x["single_window_ms_p95"] for x in v], marker="o", label="p95")
    axes[1].set_ylabel("single-window latency (ms)")
    axes[1].legend(fontsize=7, frameon=False)
    axes[2].plot(ks, [x["artifact_bytes"] / 1e6 for x in v], marker="o")
    axes[2].set_ylabel("artifact size (MB)")
    for ax in axes:
        ax.set_xlabel("K")
    save(fig, "ensemble_cost.png")


def margin_sensitivity(d: dict) -> None:
    s, k5 = d["H3"]["entities_single"], d["H3"]["entities_K5"]
    keys = sorted(s, key=lambda e: k5[e]["margin_median"])
    fig, ax = plt.subplots(figsize=(9, 3.8))
    x = np.arange(len(keys))
    ax.vlines(x, [s[e]["margin_min"] for e in keys], [s[e]["margin_median"] for e in keys], color="#ff7f0e", lw=1,
              label="single member: worst to median margin")  # fmt: skip
    ax.scatter(
        x,
        [k5[e]["margin_median"] for e in keys],
        s=8,
        color="#d62728",
        label="K = 5: median margin",
    )
    ax.axhline(0, color="#444444", lw=0.6)
    ax.set_xlabel("attacker entity (sorted by K = 5 median margin)")
    ax.set_ylabel("median attack score − T0")
    ax.legend(fontsize=7, frameon=False)
    save(fig, "margin_sensitivity.png")


def failure_frequency(d: dict) -> None:
    arms = [a for a in ARMS if a in d["arms"]]
    fig, ax = plt.subplots(figsize=(7, 3.2))
    x = np.arange(len(arms))
    fits = [d["arms"][a]["fits"] for a in arms]
    ax.bar(x - 0.2, [d["arms"][a]["collapses"] / f for a, f in zip(arms, fits, strict=True)], 0.4,
           label="collapses per fit (strong domains)", color="#d62728")  # fmt: skip
    ax.bar(
        x + 0.2,
        [d["arms"][a]["U"]["20"] for a in arms],
        0.4,
        label="unstable entities (≥ 20 %)",
        color="#1f77b4",
    )
    ax.set_xticks(x, [f"{a}\n({f} fits)" for a, f in zip(arms, fits, strict=True)])
    ax.legend(fontsize=7, frameon=False)
    save(fig, "failure_frequency.png")


def main() -> None:
    audit = json.loads((REP / "semantics_audit.json").read_text("utf-8"))
    novelty_by_row_type(audit)
    novelty_by_age(audit)
    prof = REP / "inference_profile.json"
    if prof.exists():
        ensemble_cost(json.loads(prof.read_text("utf-8")))
    res = REP / "experiment_d.json"
    if res.exists():
        d = json.loads(res.read_text("utf-8"))
        recall_by_domain(d)
        entity_recall(d)
        fpr_vs_recall(d)
        ensemble_size(d)
        margin_sensitivity(d)
        failure_frequency(d)


if __name__ == "__main__":
    main()
