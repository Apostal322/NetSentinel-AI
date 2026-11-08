"""Phase 8s figures, generated only from saved results.

Inputs:
- reports/phase8s/experiments.json and estimand.json;
- data/derived/phase8s/rows.parquet and temporal_rows.parquet;
- the hold-out host keys (for the activity distribution).

Output: docs/phase8s/figures/*.png
Usage: python scripts/phase8s/figures.py
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
import polars as pl  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
R = json.loads((ROOT / "reports/phase8s/experiments.json").read_text("utf-8"))
ROWS = pl.read_parquet(ROOT / "data/derived/phase8s/rows.parquet").with_columns(
    pl.col("domain").str.split("/").list.first().alias("net"))  # fmt: skip
TROWS = pl.read_parquet(ROOT / "data/derived/phase8s/temporal_rows.parquet").with_columns(
    pl.col("domain").str.split("/").list.first().alias("net"))  # fmt: skip
OUT = ROOT / "docs/phase8s/figures"
NETS = {"nfcic": "NF-CIC", "nfunsw": "NF-UNSW", "nfton": "NF-ToN", "nfbot": "NF-BoT"}
DESIGNS = ("random_host", "random_window", "pps", "stratified", "diversity", "tail")


def save(fig, name: str) -> None:
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=140)
    plt.close(fig)


def host_activity() -> None:
    spec = importlib.util.spec_from_file_location("fg", ROOT / "scripts/phase8q/experiment_fg.py")
    fg = importlib.util.module_from_spec(spec)
    sys.modules["fg"] = fg
    spec.loader.exec_module(fg)
    fig, ax = plt.subplots(figsize=(6, 3.6))
    for name, lab in (("nfcic/2018-02-21", "NF-CIC 02-21"), ("nfunsw/all", "NF-UNSW"), ("nfton/all", "NF-ToN"),
                      ("nfbot/all", "NF-BoT")):  # fmt: skip
        d = fg.domain_data(name)
        _, n = np.unique(d["hu_key"][~d["is_att"]], return_counts=True)
        o = np.sort(n)[::-1]
        ax.plot(np.arange(1, o.size + 1) / o.size, np.cumsum(o) / o.sum(), label=lab)
    ax.set_xscale("log")
    ax.set_xlabel("share of benign hold-out hosts (most active first)")
    ax.set_ylabel("share of benign windows")
    ax.legend(fontsize=8)
    ax.set_title("1. Benign window mass is concentrated in few hosts", fontsize=9)
    save(fig, "01_host_activity.png")


def per_design(
    metric: str, ylabel: str, fname: str, title: str, log: bool = False, est: str = "C1"
) -> None:
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.2))
    g = ROWS.filter(
        (pl.col("reviewer") == "R0")
        & ((pl.col("estimator") == est) | (pl.col("design") == "diversity"))
    )
    for ax, (n, lab) in zip(axes, NETS.items(), strict=True):
        for j, dsg in enumerate(DESIGNS):
            x = g.filter((pl.col("net") == n) & (pl.col("design") == dsg)).group_by("k").agg(
                pl.col(metric).cast(pl.Float64).median()).sort("k")  # fmt: skip
            ax.plot(
                x["k"], x[metric], "-o", ms=3, color=f"C{j}", label=dsg if n == "nfcic" else None
            )
        ax.set_xscale("log")
        if log:
            ax.set_yscale("symlog", linthresh=1)
        ax.set_title(lab, fontsize=9)
        ax.set_xlabel("expected host reviews k")
    axes[0].set_ylabel(ylabel)
    fig.legend(fontsize=7, loc="lower center", ncol=6)
    fig.suptitle(title, fontsize=9)
    fig.tight_layout(rect=(0, 0.1, 1, 0.95))
    fig.savefig(OUT / fname, dpi=140)
    plt.close(fig)


def hosts_vs_windows() -> None:
    g = ROWS.filter(
        (pl.col("reviewer") == "R0") & (pl.col("k") == 30) & (pl.col("estimator") == "C1")
    )
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.2))
    for ax, (n, lab) in zip(axes, NETS.items(), strict=True):
        for j, dsg in enumerate(DESIGNS):
            x = g.filter((pl.col("net") == n) & (pl.col("design") == dsg))
            ax.scatter(x["benign_verified"], x["trusted_windows"], s=5, alpha=0.4, color=f"C{j}",
                       label=dsg if n == "nfcic" else None)  # fmt: skip
        ax.set_yscale("symlog", linthresh=10)
        ax.set_title(lab, fontsize=9)
        ax.set_xlabel("verified-benign hosts")
    axes[0].set_ylabel("trusted windows represented")
    fig.legend(fontsize=7, loc="lower center", ncol=6, markerscale=3)
    fig.suptitle("2. Host count vs represented benign windows (k = 30, R0)", fontsize=9)
    fig.tight_layout(rect=(0, 0.1, 1, 0.95))
    fig.savefig(OUT / "02_hosts_vs_windows.png", dpi=140)
    plt.close(fig)


def contamination() -> None:
    g = ROWS.filter(
        (pl.col("k") == 30) & (pl.col("estimator") == "C1")
        | (pl.col("design") == "diversity") & (pl.col("k") == 30)
    )
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.2), sharey=True)
    for ax, (n, lab) in zip(axes, NETS.items(), strict=True):
        for j, rv in enumerate(("R0", "R1", "R2")):
            x = g.filter((pl.col("net") == n) & (pl.col("reviewer") == rv)).group_by("design").agg(
                pl.col("trusted_contamination").fill_null(0).mean())  # fmt: skip
            xs = [DESIGNS.index(d) + (j - 1) * 0.25 for d in x["design"]]
            ax.bar(
                xs,
                100 * x["trusted_contamination"],
                width=0.25,
                color=f"C{j}",
                label=rv if n == "nfcic" else None,
            )
        ax.set_xticks(range(len(DESIGNS)), [d.replace("_", "\n") for d in DESIGNS], fontsize=6)
        ax.set_title(lab, fontsize=9)
    axes[0].set_ylabel("mean HT-weighted trusted contamination (%)")
    fig.legend(fontsize=7, loc="lower center", ncol=3)
    fig.suptitle("6. Trusted-set contamination by design and reviewer (k = 30)", fontsize=9)
    fig.tight_layout(rect=(0, 0.08, 1, 0.95))
    fig.savefig(OUT / "06_trusted_contamination.png", dpi=140)
    plt.close(fig)


def weights_bias() -> None:
    g = ROWS.filter(
        (pl.col("reviewer") == "R0")
        & (pl.col("k") == 30)
        & (pl.col("estimator").is_in(["C0", "C1"]))
    )
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.4))
    for j, est in enumerate(("C0", "C1")):
        x = (
            g.filter(pl.col("estimator") == est)
            .group_by("design", "net")
            .agg(pl.col("cal_error").abs().median())
        )
        for i, (n, lab) in enumerate(NETS.items()):
            xn = x.filter(pl.col("net") == n)
            axes[0].scatter([DESIGNS.index(d) + (j - 0.5) * 0.3 for d in xn["design"]], 100 * xn["cal_error"],
                            marker="os^D"[i], color=f"C{j}", label=f"{est} {lab}" if True else None, s=18)  # fmt: skip
    axes[0].set_xticks(range(len(DESIGNS)), [d.replace("_", "\n") for d in DESIGNS], fontsize=7)
    axes[0].set_yscale("symlog", linthresh=1)
    axes[0].set_ylabel("median |calibration error| (pp)")
    axes[0].legend(fontsize=6, ncol=2)
    w = g.filter((pl.col("estimator") == "C1") & pl.col("weight_cv").is_not_null()).group_by("design", "net").agg(
        pl.col("weight_cv").median(), pl.col("kish_neff").median())  # fmt: skip
    for i, (n, lab) in enumerate(NETS.items()):
        wn = w.filter(pl.col("net") == n)
        axes[1].scatter(wn["weight_cv"], wn["kish_neff"], marker="os^D"[i], label=lab)
        for d, a, b in zip(wn["design"], wn["weight_cv"], wn["kish_neff"], strict=True):
            axes[1].annotate(d[:6], (a, b), fontsize=6)
    axes[1].set_yscale("log")
    axes[1].set_xlabel("weight coefficient of variation")
    axes[1].set_ylabel("Kish window n_eff")
    axes[1].legend(fontsize=7)
    fig.suptitle("7. Selection bias (C0 vs C1) and weight variability (k = 30, R0)", fontsize=9)
    save(fig, "07_bias_and_weights.png")


def fa_per_entity() -> None:
    g = ROWS.filter(
        (pl.col("reviewer") == "R0")
        & (pl.col("k") == 30)
        & ((pl.col("estimator") == "C1") | (pl.col("design") == "diversity"))
    )
    x = g.group_by("design", "net").agg(pl.col("fa_per_detected_entity").cast(pl.Float64).median())
    fig, ax = plt.subplots(figsize=(8, 3.4))
    for i, (n, lab) in enumerate(NETS.items()):
        xn = x.filter(pl.col("net") == n)
        ax.bar([DESIGNS.index(d) + (i - 1.5) * 0.2 for d in xn["design"]], xn["fa_per_detected_entity"].fill_null(0),
               width=0.2, label=lab)  # fmt: skip
    ax.set_xticks(range(len(DESIGNS)), DESIGNS, fontsize=7)
    ax.set_yscale("symlog", linthresh=10)
    ax.set_ylabel("median false alerts per entity detected at 20 %")
    ax.legend(fontsize=7)
    ax.set_title("8. False alerts per detected entity (k = 30, R0; C1, diversity C0)", fontsize=9)
    save(fig, "08_fa_per_entity.png")


def temporal() -> None:
    cells = ("T_reference", "E0_historical", "E1_recent_half", "E2_refresh", "E3_abstain_if_stale")
    x = TROWS.with_columns(pl.col("fpr").fill_null(0)).group_by("cell", "net").agg(
        pl.col("fpr").mean(), pl.col("recall").fill_null(0).mean())  # fmt: skip
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.4))
    for i, (n, lab) in enumerate(NETS.items()):
        xn = x.filter(pl.col("net") == n)
        for ax, m in zip(axes, ("fpr", "recall"), strict=True):
            vals = [
                float(xn.filter(pl.col("cell") == c)[m].item())
                if xn.filter(pl.col("cell") == c).height
                else np.nan
                for c in cells
            ]
            ax.bar(np.arange(len(cells)) + (i - 1.5) * 0.2, [100 * v if m == "fpr" else v for v in vals], width=0.2,
                   label=lab)  # fmt: skip
    for ax, m in zip(axes, ("FPR (%)", "documented recall"), strict=True):
        ax.set_xticks(range(len(cells)), [c.replace("_", "\n") for c in cells], fontsize=6)
        ax.set_ylabel(m)
    axes[0].set_yscale("symlog", linthresh=1)
    axes[0].legend(fontsize=7)
    fig.suptitle(
        "9. Calibration age and refresh (evaluation second half; A2 + C1, k = 30)", fontsize=9
    )
    save(fig, "09_temporal.png")


def networks() -> None:
    pr = R["cells"]["pps|30|R0|C1"]["networks"]
    refs = {k: R["references"][k]["networks"] for k in ("U", "T", "P")}
    base = R["cells"]["random_host|30|R0|C0"]["networks"]
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.4))
    series = {
        "U": refs["U"],
        "A0+C0 (8r)": base,
        "A2+C1 (primary)": pr,
        "T oracle thr.": refs["T"],
        "P oracle": refs["P"],
    }
    for j, (lab, s) in enumerate(series.items()):
        for ax, m in zip(axes, ("recall", "fpr"), strict=True):
            ax.bar(
                np.arange(4) + (j - 2) * 0.16,
                [s[n][m] * (100 if m == "fpr" else 1) for n in NETS],
                width=0.16,
                label=lab,
            )
    for ax, m in zip(axes, ("documented recall", "FPR (%)"), strict=True):
        ax.set_xticks(range(4), list(NETS.values()))
        ax.set_ylabel(m)
    axes[1].set_yscale("symlog", linthresh=1)
    axes[0].legend(fontsize=7)
    fig.suptitle("10. Performance across development networks (k = 30, R0)", fontsize=9)
    save(fig, "10_networks.png")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    host_activity()
    hosts_vs_windows()
    per_design(
        "kish_neff",
        "median Kish window n_eff",
        "03_budget_neff.png",
        "3. Review budget vs effective sample size (R0, C1)",
        log=True,
    )
    per_design(
        "fpr", "median FPR", "04_budget_fpr.png", "4. Review budget vs FPR (R0, C1; diversity C0)"
    )
    per_design(
        "recall",
        "median documented recall",
        "05_budget_recall.png",
        "5. Review budget vs recall (R0, C1; diversity C0)",
    )
    contamination()
    weights_bias()
    fa_per_entity()
    temporal()
    networks()
