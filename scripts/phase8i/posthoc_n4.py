"""Phase 8i POST-HOC [E] diagnostic on N4 (NF-BoT-IoT-v3), after the confirmatory verdicts were
fixed (reports/phase8i/confirm/verdicts.json). Changes no verdict. Why did benign-calibrated
thresholds overrun? For the A1 source model (seed 0, saved scores): false alerts by benign
entity and by day; benign calibration composition (entities, days) vs the evaluation period.

Output: reports/phase8i/confirm/posthoc_n4.json
Usage: uv run python scripts/phase8i/posthoc_n4.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812


def main() -> None:
    d = C.prepare(C.load_network("nfbot")["nfbot/all"])
    z = np.load("reports/phase8i/confirm/exp_a/nfbot__all__seed0_A1.npz")
    thr, _ = C.t0(z["s_hold"])
    ev = d["ev"].with_columns(pl.Series("s", z["s_ev"]), pl.Series("alert", z["s_ev"] > thr),
                              (pl.col("window_end_ms") // 86_400_000).alias("day"))  # fmt: skip
    ben = ev.filter(pl.col("benign"))
    by_ent = (ben.group_by("key").agg(pl.len().alias("windows"), pl.col("alert").mean().alias("fpr"))
              .sort("windows", descending=True))  # fmt: skip
    by_day = ben.group_by("day").agg(pl.len().alias("windows"),
                                     pl.col("alert").mean().alias("fpr")).sort("day")  # fmt: skip
    cal = pl.concat([d["_btrain"].with_columns(pl.lit("train").alias("part")),
                     d["_hold"].with_columns(pl.lit("hold").alias("part"))])  # fmt: skip
    cal_ent = cal.group_by("key", "part").len().sort("len", descending=True)
    cal_days = (cal.with_columns((pl.col("window_end_ms") // 86_400_000).alias("day"))
                .group_by("day").len().sort("day"))  # fmt: skip
    out = {"label": "[E post-hoc] N4 diagnostic; verdicts unchanged", "T0": thr,
           "benign_eval_windows": ben.height, "fpr": float(ben["alert"].mean()),
           "fpr_by_entity": by_ent.to_dicts(), "fpr_by_day": by_day.to_dicts(),
           "cal_by_entity": cal_ent.to_dicts(), "cal_days": cal_days.to_dicts(),
           "eval_entities_not_in_cal": sorted(set(ben["key"]) - set(cal["key"]))}  # fmt: skip
    C.dump(Path("reports/phase8i/confirm/posthoc_n4.json"), out)
    print(by_ent, by_day, cal_ent, cal_days, out["eval_entities_not_in_cal"], sep="\n")


if __name__ == "__main__":
    main()
