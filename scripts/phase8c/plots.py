"""Phase 8c score/threshold figures (reports/phase8c/figures/).

Per capture: deployed robust_z_product scores (log scale) of
* cross-fit held-out calibration windows, split by scoring group (own device profile vs pooled
  fallback) - these set the threshold;
* evaluation benign windows; evaluation attack windows;
with the deployed threshold (A), and the Mondrian address-class threshold for private
addresses (C2). Consumed captures are titled RETROSPECTIVE.
Usage: uv run python scripts/phase8c/plots.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace import CAPTURES  # noqa: E402

from harness import load, with_truth  # noqa: E402
from policies import agg, crossfit, private, thr  # noqa: E402

from netsentinel.behavior.profile import _zs  # noqa: E402

OUT = Path("reports/phase8c/figures")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    names = [n for n in CAPTURES if (Path(CAPTURES[n][0]) / n / "meta.json").exists()]
    fig, axes = plt.subplots(len(names), 1, figsize=(9, 2.3 * len(names)), sharex=True)
    for ax, n in zip(np.atleast_1d(axes), names, strict=True):
        d = load(Path(CAPTURES[n][0]) / n)
        cal, ev = d["cal_clean"], d["eval_clean"]
        prof, Zh, kh, oh = crossfit(cal)
        sh = agg(Zh, "top2")
        se = agg(_zs(prof, ev), "top2")
        y = with_truth(ev.select("key", "win"), d["truth"])["y"].to_numpy()
        t_a = thr(sh)
        ph = np.array([private(k) for k in kh])
        t_c2 = thr(sh[ph]) if ph.any() else np.nan
        bins = np.logspace(-2, 2.2, 70)
        series = [(sh[oh], "held-out: own device profile", "#4c78a8"),
                  (sh[~oh], "held-out: pooled fallback (transient sources)", "#f58518"),
                  (se[~y], "evaluation: benign", "#9d9d9d"),
                  (se[y], "evaluation: ATTACK", "#e45756")]  # fmt: skip
        for vals, lab, col in series:
            if len(vals):
                ax.hist(np.clip(vals, 1e-2, None), bins=bins, histtype="step", lw=1.6,
                        color=col, label=f"{lab} (n={len(vals)})", density=True)  # fmt: skip
        ax.axvline(t_a, color="black", lw=1.5, ls="-", label=f"deployed threshold A = {t_a:.1f}")
        if np.isfinite(t_c2):
            ax.axvline(t_c2, color="#54a24b", lw=1.5, ls="--",
                       label=f"C2 threshold, private addresses = {t_c2:.1f}")  # fmt: skip
        ax.set_xscale("log")
        ax.set_yscale("log")
        role = "RETROSPECTIVE (consumed)" if "retro" in CAPTURES[n][1] else "development"
        ax.set_title(f"{n} - {role}", fontsize=9, loc="left")
        ax.legend(fontsize=6, loc="upper right", frameon=False)
        ax.set_ylabel("density", fontsize=8)
    np.atleast_1d(axes)[-1].set_xlabel("window score (mean of top-2 |z|), log scale")
    fig.tight_layout()
    p = OUT / "score_distributions.png"
    fig.savefig(p, dpi=110)
    print(p)


if __name__ == "__main__":
    main()
