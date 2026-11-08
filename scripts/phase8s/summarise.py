"""Phase 8s: print the registered tables from the saved report (lookup only).

Usage: python scripts/phase8s/summarise.py [cells|acq|temporal|decisions]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
R = json.loads((ROOT / "reports" / "phase8s" / "experiments.json").read_text("utf-8"))
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")


def fmt(c: dict) -> str:
    parts = []
    for n in NETS:
        v = c["networks"].get(n)
        if v is None:
            parts.append("—")
            continue
        e = v.get("median_abs_cal_error")
        parts.append(f"{v['recall']:.3f}/{100 * v['fpr']:.1f}%(p90 {100 * v['fpr_p90']:.1f})"
                     f" a{100 * v['abstention']:.0f} e{'—' if e is None else f'{100 * e:.2f}'}")  # fmt: skip
    return f"{c['macro_recall']:.3f} | R20 {c['mean_R20']:.1f} | " + " | ".join(parts)


def cells() -> None:
    for k, c in R["references"].items():
        print("REF", k, "|", fmt(c))
    for k, c in R["cells"].items():
        print(k, "|", fmt(c))


def acq() -> None:
    keys = ("reviews", "benign_verified", "malicious_found", "inconclusive", "review_success", "cost",
            "trusted_windows", "kish_neff", "cluster_neff", "weight_cv", "tail_hosts", "trusted_contamination",
            "t_bias", "fa_per_host_hour", "top_host_fa_share", "fa_per_detected_entity")  # fmt: skip
    for row in R["acquisition_medians"]:
        if row["estimator"] != "C1" and row["design"] != "diversity":
            continue
        vals = " ".join(
            f"{k[:6]}={row[k]:.3g}" if isinstance(row[k], float) else f"{k[:6]}={row[k]}"
            for k in keys
        )
        print(row["design"], row["k"], row["reviewer"], row["net"], vals)


def temporal() -> None:
    for k, c in R["temporal"].items():
        print(k, "|", fmt(c))
    print(R["temporal_ks_drift"])


def decisions() -> None:
    print(json.dumps(R["decisions"], indent=1))
    print("runtime", R["runtime_s"], "peak", R["peak_rss_mb"], "sha", R["provenance"]["git_sha"], "dirty",
          R["provenance"]["dirty_tree"])  # fmt: skip


if __name__ == "__main__":
    {"cells": cells, "acq": acq, "temporal": temporal, "decisions": decisions}[
        sys.argv[1] if len(sys.argv) > 1 else "cells"
    ]()
