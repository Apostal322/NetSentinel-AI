"""Phase 8s post-hoc analyses, labelled EXPLORATORY (outcomes were visible). They read the saved
rows only and never replace a registered verdict.

1. Temporal re-summary (amendment S-1, reporting only). The registered `summarise` averaged recall
   with NaN for domains without documented-attack windows in the evaluation second half, so the
   NF-CIC temporal recall printed as NaN. Here those domains are excluded from recall means;
   abstained rows still count as recall 0. FPR, and therefore H5, is unaffected.
2. H1 without the census networks. At k = 30, every design reviews every hold-out host of NF-UNSW
   (21) and NF-BoT (15), so the H1 comparison there differs only in the estimator's quantile
   definition, not in the design.
3. The budget at which each probability design reaches the oracle-threshold reference T.

Output: reports/phase8s/posthoc.json
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
D = ROOT / "data" / "derived" / "phase8s"
R = json.loads((ROOT / "reports/phase8s/experiments.json").read_text("utf-8"))
OUT = ROOT / "reports/phase8s/posthoc.json"
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")


def net_col(df: pl.DataFrame) -> pl.DataFrame:
    return df.with_columns(pl.col("domain").str.split("/").list.first().alias("net"))


def temporal() -> dict:
    t = net_col(pl.read_parquet(D / "temporal_rows.parquet"))
    t = t.with_columns(
        pl.when(pl.col("abstain")).then(0.0).otherwise(pl.col("recall")).fill_nan(None).alias("rec"),
        pl.col("fpr").fill_null(0.0),
        pl.col("r20").fill_null(0),
    )  # fmt: skip
    out: dict = {}
    for (cell,), g in t.group_by("cell", maintain_order=True):
        nets = {}
        for (n,), gn in g.group_by("net", maintain_order=True):
            per = gn.group_by("fit", "draw").agg(
                pl.col("rec").mean(), pl.col("fpr").mean(), pl.col("abstain").mean()
            )
            nets[n] = {"recall": None if per["rec"].null_count() == per.height else float(per["rec"].mean()),
                       "fpr": float(per["fpr"].mean()), "abstention": float(per["abstain"].mean())}  # fmt: skip
        rec = [v["recall"] for v in nets.values() if v["recall"] is not None]
        out[cell] = {"networks": nets, "macro_recall": float(np.mean(rec)),
                     "mean_R20": float(g.group_by("fit", "draw").agg(pl.col("r20").sum())["r20"].mean())}  # fmt: skip
    return out


def h1_without_census() -> dict:
    h = R["decisions"]["H1_representative_sampling"]
    p, b = h["median_abs_cal_error_primary"], h["median_abs_cal_error_baseline"]
    nets = ("nfcic", "nfton")
    return {"networks": {n: {"primary": p[n], "baseline": b[n], "ratio": p[n] / b[n]} for n in nets},
            "note": "NF-UNSW and NF-BoT are census-limited at k = 30: every design reviews all hosts"}  # fmt: skip


def reach_t() -> dict:
    t = R["references"]["T"]["networks"]
    out = {}
    for key, c in R["cells"].items():
        design, k, rv, est = key.split("|")
        if rv != "R0" or est != "C1":
            continue
        ok = {n: c["networks"][n]["fpr"] <= t[n]["fpr"] + 0.02 and c["networks"][n]["fpr_p90"] <= t[n]["fpr"] + 0.05
              for n in NETS}  # fmt: skip
        out[key] = {"macro_recall": c["macro_recall"], "fpr_within_registered_limits": ok, "all_networks": all(ok.values()),
                    "nfton_fpr": c["networks"]["nfton"]["fpr"], "nfton_fpr_p90": c["networks"]["nfton"]["fpr_p90"]}  # fmt: skip
    return out


def main() -> None:
    res = {"status": "EXPLORATORY post-hoc analyses (outcomes visible)", "temporal_resummary": temporal(),
           "h1_without_census_networks": h1_without_census(), "cells_within_fpr_limits": reach_t()}  # fmt: skip
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    for k, v in res["temporal_resummary"].items():
        print(
            k,
            round(v["macro_recall"], 3),
            {
                n: (
                    None if x["recall"] is None else round(x["recall"], 3),
                    round(100 * x["fpr"], 1),
                )
                for n, x in v["networks"].items()
            },
        )
    print(json.dumps(res["h1_without_census_networks"], indent=1))
    for k, v in res["cells_within_fpr_limits"].items():
        print(
            k,
            round(v["macro_recall"], 3),
            v["all_networks"],
            round(100 * v["nfton_fpr"], 1),
            round(100 * v["nfton_fpr_p90"], 1),
        )


if __name__ == "__main__":
    main()
