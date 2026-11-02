"""Phase 8i [E] error analysis: what drives the cross-network source model (A1 setup) on each
development target. Predictive attribution only, not causal.

For each cross-network fold and seed: the source model's total-gain importance, and on the
target, the mean TreeSHAP contribution (LightGBM `pred_contrib`, exact for trees) of each feature
on (a) attack windows detected at T0, (b) attack windows missed at T0, (c) benign windows that
raised a false alert. Attribution stability is reported as the Spearman correlation of the
gain rankings across seeds.

Output: reports/phase8i/attribution.json
Usage: uv run python scripts/phase8i/attribution.py [--seeds 0,1,2]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812
from exp_a import folds  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

SAMPLE = 5_000  # windows per group for the contribution means


def mean_contrib(model, x: np.ndarray, rng) -> list[float] | None:
    if len(x) == 0:
        return None
    if len(x) > SAMPLE:
        x = x[rng.choice(len(x), SAMPLE, replace=False)]
    c = model.booster_.predict(x, pred_contrib=True)[:, :-1]  # last column = bias
    return [float(v) for v in c.mean(axis=0)]


def main() -> None:
    from scipy.stats import spearmanr

    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="0,1,2")
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(",")]
    t0 = time.perf_counter()
    groups: dict[tuple, list] = {}
    for name, tgt, srcs in folds(False):
        groups.setdefault(tuple(sorted(srcs)), []).append((name, tgt, srcs))
    out = {"features": C.FEATS, "folds": {}}
    for units in groups.values():
        srcs = units[0][2]
        nets = sorted({d["network"] for d in srcs.values()})
        fold = {"sources": nets, "gain": {}, "targets": {}}
        for seed in seeds:
            m, _, _ = C.fit_source(srcs, seed, C.Rep("raw"))
            g = m.booster_.feature_importance("gain")
            fold["gain"][str(seed)] = [float(v) for v in g / g.sum()]
            rng = np.random.default_rng(seed)
            for name, tgt, _ in units:
                C.prepare(tgt)
                xe, xh = C.S._x(tgt["ev"]), C.S._x(tgt["_hold"])
                se, sh = m.predict_proba(xe)[:, 1], m.predict_proba(xh)[:, 1]
                thr, _ = C.t0(sh)
                y, ben = tgt["ev"]["y"].to_numpy(), tgt["ev"]["benign"].to_numpy()
                al = se > thr
                fold["targets"].setdefault(name, {})[str(seed)] = {
                    "detected": mean_contrib(m, xe[y & al], rng),
                    "missed": mean_contrib(m, xe[y & ~al], rng),
                    "false_alerts": mean_contrib(m, xe[ben & al], rng),
                    "benign": mean_contrib(m, xe[ben & ~al], rng),
                    "n": {"detected": int((y & al).sum()), "missed": int((y & ~al).sum()),
                          "false_alerts": int((ben & al).sum())}}  # fmt: skip
        gs = [fold["gain"][str(s)] for s in seeds]
        fold["gain_rank_spearman_min"] = float(min(
            spearmanr(gs[i], gs[j]).statistic for i in range(len(gs)) for j in range(i + 1, len(gs))
        )) if len(gs) > 1 else None  # fmt: skip
        out["folds"]["+".join(nets)] = fold
        print(nets, "top gain:", [C.FEATS[i] for i in np.argsort(-np.array(gs[0]))[:4]],
              flush=True)  # fmt: skip
    out["seconds"] = time.perf_counter() - t0
    out["peak_rss_mb"] = peak_rss_mb()
    C.dump(Path("reports/phase8i/attribution.json"), out)


if __name__ == "__main__":
    main()
