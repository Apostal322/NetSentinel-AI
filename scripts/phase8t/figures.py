"""Phase 8t figures from saved outputs.

Inputs:
- reports/phase8t/oracle_feasibility.json and deployable_r2.json;
- the saved Phase 8o F0 scores (fit base_r6) for the score-distribution and shrinkage panels.

Output: docs/phase8t/figures/*.png
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OR = json.loads((ROOT / "reports/phase8t/oracle_feasibility.json").read_text("utf-8"))
DP = json.loads((ROOT / "reports/phase8t/deployable_r2.json").read_text("utf-8"))
OUT = ROOT / "docs/phase8t/figures"
NETS = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN", "nfbot": "NF-BoT"}
SVC = ["TCP 1 port", "TCP 2-5", "TCP >5", "UDP 1 port", "UDP 2-5", "UDP >5"]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def bars(ax, series: dict, field: str, scale: float = 1.0) -> None:
    for j, (lab, nets) in enumerate(series.items()):
        ax.bar(np.arange(4) + (j - (len(series) - 1) / 2) * 0.8 / len(series),
               [nets[n][field] * scale for n in NETS], width=0.8 / len(series), label=lab)  # fmt: skip
    ax.set_xticks(range(4), list(NETS.values()))


def oracle_tradeoff() -> None:
    s = OR["summary"]
    series = {
        f"{k} (S_U)": {n: v for n, v in s["S_U"][k]["networks"].items()}
        for k in ("O0", "O2g", "O3g", "O3", "O4")
    }
    series["O0 (S_P, clean memory)"] = s["S_P"]["O0"]["networks"]
    fig, ax = plt.subplots(figsize=(9, 3.6))
    bars(ax, series, "recall")
    ax.set_ylabel("documented-attack recall at 1 % FPR")
    ax.legend(fontsize=7, ncol=3)
    ax.set_title(
        "1. Retrospective oracles at the same 1 % false-alert budget (O4 = host-identity memorisation)",
        fontsize=9,
    )
    fig.tight_layout()
    fig.savefig(OUT / "01_oracle_tradeoff.png", dpi=140)
    plt.close(fig)


def score_by_service() -> None:
    of = _load("of", "scripts/phase8t/oracle_feasibility.py")
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.4), sharey=True)
    for ax, (name, lab) in zip(axes, (("nfcic/2018-02-21", "NF-CIC 02-21"), ("nfunsw/all", "NF-UNSW"),
                                      ("nfton/all", "NF-ToN"), ("nfbot/all", "NF-BoT")), strict=True):  # fmt: skip
        d = of.load(name)
        s = of.FG.scores(name, "base", 6)["s_ev_u"]
        for g in range(6):
            b, p = s[d["neg"] & (d["svc"] == g)], s[d["pos"] & (d["svc"] == g)]
            if b.size >= 20:
                q = np.quantile(b, [0.5, 0.9, 0.99])
                ax.plot([g, g], [q[0], q[2]], color="C0", lw=4, alpha=0.5)
                ax.scatter(
                    g,
                    q[2],
                    color="C0",
                    marker="_",
                    s=200,
                    label="benign q50–q99" if g == 0 and ax is axes[0] else None,
                )
            if p.size:
                ax.scatter(g + 0.15, np.median(p), color="C3", marker="o", s=12 + 3 * np.log1p(p.size),
                           label="attack median (size ∝ log count)" if ax is axes[0] and g == 0 else None)  # fmt: skip
        ax.set_xticks(range(6), SVC, rotation=60, fontsize=6)
        ax.set_title(lab, fontsize=9)
    axes[0].set_ylabel("score (S_U, fit base r6)")
    axes[0].legend(fontsize=6)
    fig.suptitle(
        "2. Benign score tails and attack scores by window service profile (evaluation period)",
        fontsize=9,
    )
    fig.tight_layout()
    fig.savefig(OUT / "02_score_by_service.png", dpi=140)
    plt.close(fig)


def matched_and_calibrated() -> None:
    S = DP["summary"]
    meths = ("D0", "D1", "D2", "D3", "D_host")
    fig, axes = plt.subplots(1, 3, figsize=(14, 3.4))
    bars(axes[0], {m: S[f"CAL_T|{m}"]["matched_budget"]["networks"] for m in meths}, "recall")
    axes[0].set_title("5a. Recall at the matched 1 % budget (CAL_T)", fontsize=9)
    bars(axes[1], {m: S[f"CAL_T|{m}"]["as_calibrated"]["networks"] for m in meths}, "recall")
    axes[1].set_title("5b. Recall as calibrated (CAL_T)", fontsize=9)
    bars(axes[2], {m: S[f"CAL_T|{m}"]["as_calibrated"]["networks"] for m in meths}, "fpr", 100)
    axes[2].axhline(1, color="k", ls=":", lw=0.8)
    axes[2].set_yscale("symlog", linthresh=1)
    axes[2].set_title("5c. FPR as calibrated (%; dotted = 1 % target)", fontsize=9)
    axes[0].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "05_matched_and_calibrated.png", dpi=140)
    plt.close(fig)


def entities_and_concentration() -> None:
    S, Ou = DP["summary"], OR["summary"]["S_U"]
    labs = ["O0", "O2g", "O3g", "O4", "D0 MB", "D2 MB", "D0 cal", "D2 cal"]
    r20 = [Ou["O0"]["R20"], Ou["O2g"]["R20"], Ou["O3g"]["R20"], Ou["O4"]["R20"], S["CAL_T|D0"]["matched_budget"]["R20"],
           S["CAL_T|D2"]["matched_budget"]["R20"], S["CAL_T|D0"]["as_calibrated"]["R20"], S["CAL_T|D2"]["as_calibrated"]["R20"]]  # fmt: skip
    missed = [Ou["O0"]["missed_entities"], Ou["O2g"]["missed_entities"], Ou["O3g"]["missed_entities"], Ou["O4"]["missed_entities"],
              S["CAL_T|D0"]["matched_budget"]["missed"], S["CAL_T|D2"]["matched_budget"]["missed"],
              S["CAL_T|D0"]["as_calibrated"]["missed"], S["CAL_T|D2"]["as_calibrated"]["missed"]]  # fmt: skip
    fig, axes = plt.subplots(1, 2, figsize=(12, 3.4))
    x = np.arange(len(labs))
    axes[0].bar(x - 0.2, r20, 0.4, label="R₂₀ (of 48)")
    axes[0].bar(x + 0.2, missed, 0.4, label="missed entirely")
    axes[0].set_xticks(x, labs, fontsize=7)
    axes[0].legend(fontsize=7)
    axes[0].set_title(
        "6. Documented attacker entities (MB = matched budget; cal = as calibrated)", fontsize=9
    )
    bars(
        axes[1],
        {m: S[f"CAL_T|{m}"]["as_calibrated"]["networks"] for m in ("D0", "D1", "D2", "D_host")},
        "top_host_fa_share",
    )
    axes[1].set_title("8. Top host's share of false alerts (as calibrated)", fontsize=9)
    axes[1].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "06_entities_and_concentration.png", dpi=140)
    plt.close(fig)


def shrinkage() -> None:
    dv = _load("dv", "scripts/phase8t/deployable_eval.py")
    cc = dv.CC
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.2))
    for ax, (name, lab) in zip(axes, (("nfcic/2018-02-21", "NF-CIC 02-21"), ("nfunsw/all", "NF-UNSW"),
                                      ("nfton/all", "NF-ToN"), ("nfbot/all", "NF-BoT")), strict=True):  # fmt: skip
        d = dv.load(name)
        s = dv.FG.scores(name, "base", 6)["s_hold_u"]
        m = ~d["cal_att"]
        args = (s[m], d["cal_grp"][m], d["cal_key"][m])
        d0 = cc.Calibrator("D0", *args).t_glob
        d1 = cc.Calibrator("D1", *args, min_group=1).group_thresholds()
        d2 = cc.Calibrator("D2", *args).group_thresholds()
        n = {g: int((d["cal_grp"][m] == g).sum()) for g in d2}
        for g in d2:
            ax.plot([n[g], n[g]], [d1.get(g, d0), d2[g]], color="C1", lw=1)
            ax.scatter(
                n[g],
                d1.get(g, d0),
                color="C0",
                s=15,
                label="group's own (D1)" if g == min(d2) else None,
            )
            ax.scatter(
                n[g],
                d2[g],
                color="C1",
                s=15,
                label="pooled (D2, κ = 500)" if g == min(d2) else None,
            )
        ax.axhline(d0, color="k", ls=":", lw=0.8, label="global (D0)")
        ax.set_xscale("log")
        ax.set_xlabel("calibration benign windows in group")
        ax.set_title(lab, fontsize=9)
    axes[0].set_ylabel("threshold (CAL_T, fit base r6)")
    axes[0].legend(fontsize=6)
    fig.suptitle("9. Hierarchical shrinkage of service-group thresholds", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "09_shrinkage.png", dpi=140)
    plt.close(fig)


def temporal() -> None:
    S = DP["summary"]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.2))
    ser = {
        m: S[f"CAL_T|{m}|second_half"]["as_calibrated"]["networks"]
        for m in ("D0", "D1", "D2", "D_host")
    }
    bars(axes[0], ser, "recall")
    axes[0].set_title("10a. Recall, evaluation second half (as calibrated)", fontsize=9)
    bars(axes[1], ser, "fpr", 100)
    axes[1].set_yscale("symlog", linthresh=1)
    axes[1].set_title("10b. FPR %, evaluation second half", fontsize=9)
    axes[0].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "10_temporal.png", dpi=140)
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    oracle_tradeoff()
    score_by_service()
    matched_and_calibrated()
    entities_and_concentration()
    shrinkage()
    temporal()
