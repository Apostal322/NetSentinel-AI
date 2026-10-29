"""Phase 8g post-hoc [E]: controlled synthetic contamination study of baseline refresh
strategies (docs/phase8g/V4_FAILURE_ANALYSIS.md, section 4). Synthetic data only: no CTU-13 or
development capture is used, so nothing here is evidence about a real network; it tests
whether a mechanism found on CTU-13 scenario 9 is reproduced and whether conservative
alternatives remove it in a setting where the truth is known.

World (device windows, the product's 12 window features, 30 s windows, 1 h = 120 windows):
* 150 known devices: per-device mean ~ N(0, 1) per feature, window noise sd 0.5. From
  evaluation segment 2 on, every known device drifts by +0.75 on two features (a legitimate
  change that makes a refresh useful).
* Transient sources: 300 new sources per hour with 1-5 windows each, means ~ N(0, 2): they are
  scored by the pooled fallback and set the tail (as in CTU-13, tail_fallback_share 0.97).
* 5 attackers, persistent from evaluation segment 0: every window shifted by `delta` on three
  features. "new": absent from calibration (CTU-13: initiators excluded from calibration);
  "known": benign in calibration, compromised at segment 0. "known_ramp": as "known", but the
  shift grows linearly from delta / 6 in segment 0 to delta in segment 5 (gradual contamination).
Calibration = 2 h; evaluation = 6 h; refresh due after segments 1 and 3 (every 2 h).

Strategies (candidate = product fit_level_crossfit on the last 2 h of device windows):
  S1   fixed baseline (the deployed behaviour; refusal to refresh)
  S5   Phase 8f gate on the candidate period (device alert rate, strong outlier) + reliable
       threshold -> activate (the V4 strategy)
  Q    S5 after removing entities whose alert count under the CURRENT baseline is
       significantly above the target rate (one-sided binomial, Holm, alpha 0.01)
  QC   Q, and every removed entity keeps its current statistics (carry-over)
  QKC  QC, and no entity WITHOUT an own profile in the current baseline may obtain one from
       unvetted data (its windows are left out; it stays on the pooled fallback)
  QKCD QKC with delayed activation: the candidate runs in shadow for one segment and is
       activated only if every entity with significant excess alerts under the current
       baseline on that segment also has it under the candidate (no evidence suppressed)
  V    vetted-only: candidate from 30 operator-vetted known devices; every other device keeps
       its current statistics
Metrics: attack windows admitted into an activated fit ("absorbed"), attack-window recall
after the first refresh, attackers detected in the last segment, benign false-alert rate after
the drift, activations.
Usage: uv run python scripts/phase8g_post/v4_synthetic.py [--cells new,known,known_ramp]
       -> reports/phase8g_post/v4_synthetic.json (v4_synthetic_<cells>.json for a subset)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import numpy as np
import polars as pl
from scipy.stats import binom

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8f"))
from recalibration_sim import gate  # noqa: E402

from netsentinel.behavior.profile import _zs, fit_level_crossfit, window_scores  # noqa: E402
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402

OUT = Path("reports/phase8g_post/v4_synthetic.json")
F, SEG, T, MINW = len(WINDOW_FEATURES), 120, 0.01, 30
N_KNOWN, N_ATT, N_VETTED, TRANSIENT_PER_H = 150, 5, 30, 300
CAL_SEGS, EVAL_SEGS, EVERY = 2, 6, 2
STRATEGIES = ("S1", "S5", "Q", "QC", "QKC", "QKCD", "V")


def world(seed: int, delta: float, attackers: str) -> tuple[pl.DataFrame, np.ndarray]:
    rng = np.random.default_rng(seed)
    mu = rng.normal(0, 1, (N_KNOWN, F))
    mu_att = rng.normal(0, 1, (N_ATT, F))
    shift = np.zeros(F)
    shift[[0, 4, 5]] = delta  # connection rate, destination and port diversity
    drift = np.zeros(F)
    drift[[1, 2]] = 0.75
    rows, att = [], []
    for s in range(CAL_SEGS + EVAL_SEGS):
        ev = s - CAL_SEGS  # evaluation segment index (negative = calibration)
        for w in range(s * SEG, (s + 1) * SEG):
            x = mu + rng.normal(0, 0.5, mu.shape) + (drift if ev >= 2 else 0)
            rows += [(f"k{i}", w, x[i]) for i in range(N_KNOWN)]
            att += [False] * N_KNOWN
            if ev >= 0 or attackers != "new":
                ramp = (ev + 1) / EVAL_SEGS if attackers == "known_ramp" else 1.0
                xa = mu_att + rng.normal(0, 0.5, mu_att.shape) + (shift * ramp if ev >= 0 else 0)
                rows += [(f"a{i}", w, xa[i]) for i in range(N_ATT)]
                att += [ev >= 0] * N_ATT
        for t in range(TRANSIENT_PER_H):
            m = rng.normal(0, 2, F)
            for w in rng.choice(np.arange(s * SEG, (s + 1) * SEG), rng.integers(1, 6), False):
                rows.append((f"t{s}_{t}", int(w), m + rng.normal(0, 0.5, F)))
                att.append(False)
    keys, wins, xs = zip(*rows, strict=True)
    df = pl.DataFrame({"key": list(keys), "win": np.array(wins, np.int64)}).with_columns(
        [pl.Series(f, np.array(xs)[:, i]) for i, f in enumerate(WINDOW_FEATURES)]
    ).with_columns(pl.lit("device").alias("level"),
                   ((pl.col("win") + 1) * 30_000).alias("window_end_ms"))  # fmt: skip
    return df, np.array(att)


def fit(df: pl.DataFrame):
    return fit_level_crossfit(df, "device", T, MINW, "vetted_benign")


def holm_flags(p: dict[str, float], alpha: float = 0.01) -> set[str]:
    out, m = set(), len(p)
    for i, (k, v) in enumerate(sorted(p.items(), key=lambda x: x[1])):
        if v > alpha / (m - i):
            break
        out.add(k)
    return out


def excess_entities(prof, df: pl.DataFrame) -> set[str]:
    a = window_scores(_zs(prof, df), 2) > prof.threshold
    per_key = (pl.DataFrame({"key": df["key"], "a": a})
               .group_by("key").agg(pl.len().alias("n"), pl.col("a").sum().alias("x"))
               .filter(pl.col("n") >= MINW))  # fmt: skip
    return holm_flags({k: float(binom.sf(x - 1, n, T)) if x else 1.0
                       for k, n, x in per_key.iter_rows()})  # fmt: skip


def candidate(strategy: str, prof, df: pl.DataFrame):
    """-> (candidate profile or None, admitted-row mask)."""
    keep = np.ones(df.height, bool)
    k = np.array(df["key"].to_list(), dtype=object)
    excluded: set[str] = set()
    if strategy.startswith("Q"):
        excluded |= excess_entities(prof, df)
    if strategy.startswith("QK"):
        counts = df.group_by("key").len()
        persistent = set(counts.filter(pl.col("len") >= MINW)["key"].to_list())
        excluded |= {x for x in persistent if x not in prof.keys}
    if strategy == "V":  # vetted devices refreshed; every other entity keeps its statistics
        keep &= np.isin(k, [f"k{i}" for i in range(N_VETTED)])
        cand = fit(df.filter(pl.Series(keep)))
        if cand.pooled is None:
            return None, keep
        return replace(prof, keys={**prof.keys, **cand.keys}), keep
    keep &= ~np.isin(k, list(excluded))
    cand = fit(df.filter(pl.Series(keep)))
    if strategy in ("QC", "QKC", "QKCD") and cand.pooled is not None:
        # an excluded entity keeps its CURRENT statistics; without this it falls back to the
        # pooled profile, becomes invisible and is admitted at the next refresh (cascade)
        cand = replace(
            cand, keys={**cand.keys, **{x: prof.keys[x] for x in excluded if x in prof.keys}}
        )
    return cand, keep


def run(strategy: str, df: pl.DataFrame, att: np.ndarray) -> dict:
    seg = (df["win"].to_numpy() // SEG) - CAL_SEGS
    prof = fit(df.filter(pl.Series(seg < 0)))
    alert = np.zeros(df.height, bool)
    absorbed = acts = refusals = 0
    first_act = None
    shadow = None  # QKCD: (candidate, admitted attack windows, gate passed)

    def usable(c, ok) -> bool:
        return bool(ok and c is not None and c.pooled is not None
                    and c.threshold_diag.get("reliable"))  # fmt: skip

    for s in range(EVAL_SEGS):
        m = seg == s
        part = df.filter(pl.Series(m))
        alert[m] = window_scores(_zs(prof, part), 2) > prof.threshold
        if shadow is not None:  # delayed activation: the shadow must keep the current evidence
            cand, n_att, ok = shadow
            shadow = None
            if usable(cand, ok) and excess_entities(prof, part) <= excess_entities(cand, part):
                prof, acts, absorbed = cand, acts + 1, absorbed + n_att
                first_act = s if first_act is None else first_act
            else:
                refusals += 1
        if strategy == "S1" or (s + 1) % EVERY:
            continue
        recent = (seg > s - EVERY) & (seg <= s)
        cdf = df.filter(pl.Series(recent))
        cand, keep = candidate(strategy, prof, cdf)
        ok, _ = gate(prof, cdf.filter(pl.Series(keep))) if cand is not None else (False, "")
        if strategy == "QKCD":
            shadow = (cand, int(att[recent][keep].sum()), ok)
            continue
        if usable(cand, ok):
            prof, acts = cand, acts + 1
            absorbed += int(att[recent][keep].sum())
            first_act = s if first_act is None else first_act
        else:
            refusals += 1
    after = seg > (first_act if first_act is not None else 1)
    keys = np.array(df["key"].to_list(), dtype=object)
    last = seg == EVAL_SEGS - 1
    ben_after = (~att) & (seg >= 2) & np.char.startswith(keys.astype(str), "k")
    return {"activations": acts, "refusals": refusals, "absorbed_attack_windows": absorbed,
            "absorbed_share": absorbed / max(1, int(att.sum())),
            "recall_after_first_refresh": float(alert[att & after].mean()),
            "recall_all": float(alert[att].mean()),
            "attackers_detected_last_segment": int(sum(
                bool((alert & att & last & (keys == f"a{i}")).any()) for i in range(N_ATT))),
            "known_device_fpr_after_drift": float(alert[ben_after].mean())}  # fmt: skip


def main(seeds=range(5)) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cells", default="new,known")
    cells = ap.parse_args().cells.split(",")
    t0 = time.perf_counter()
    res = {}
    for attackers in cells:
        for delta in (1.5, 3.0):
            cell = {s: [] for s in STRATEGIES}
            for seed in seeds:
                df, att = world(seed, delta, attackers)
                for s in STRATEGIES:
                    cell[s].append(run(s, df, att))
            res[f"{attackers}_delta{delta}"] = {
                s: {k: float(np.mean([r[k] for r in v])) for k in v[0]} for s, v in cell.items()
            }
    out = {"label": "[E] synthetic design study; not evidence about any real network",
           "seeds": list(seeds), "results": res, "seconds": time.perf_counter() - t0}  # fmt: skip
    path = (
        OUT if cells == ["new", "known"] else OUT.with_name(f"v4_synthetic_{'_'.join(cells)}.json")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1), "utf-8")
    for cell, r in res.items():
        print(cell)
        for s, v in r.items():
            print(
                f"  {s:3s} act={v['activations']:.1f} absorbed={v['absorbed_share']:.2f} "
                f"recall_after={v['recall_after_first_refresh']:.2f} "
                f"det_last={v['attackers_detected_last_segment']:.1f} "
                f"fpr_drift={v['known_device_fpr_after_drift']:.3f}"
            )


if __name__ == "__main__":
    main()
