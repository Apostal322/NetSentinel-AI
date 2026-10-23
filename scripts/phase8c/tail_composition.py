"""Phase 8c: composition of the deployed threshold's tail (top 1% of cross-fit held-out
scores): which share comes from devices scored against the POOLED fallback, and which share
from non-private (external) source addresses. Retrospective rows are labelled.
Usage: uv run python scripts/phase8c/tail_composition.py  -> reports/phase8c/tail_composition.json
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8b"))
from trace import CAPTURES, fit, heldout_by_device  # noqa: E402

from harness import load  # noqa: E402


def private(a: str) -> bool:
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local


def main() -> None:
    res = {}
    for name, (root, role) in CAPTURES.items():
        p = Path(root) / name
        if not (p / "meta.json").exists():
            continue
        d = load(p)
        cal = d["cal_clean"]
        hs = heldout_by_device(cal, fit(cal))
        hs = hs.with_columns(pl.Series("private", [private(k) for k in hs["key"].to_list()]))
        t = hs.filter(pl.col("score") > np.quantile(hs["score"], 0.99))
        res[name] = {"role": role, "heldout": hs.height,
                     "heldout_pooled_share": float((~hs["own_profile"]).mean()),
                     "heldout_external_share": float((~hs["private"]).mean()),
                     "tail": t.height, "tail_pooled_share": float((~t["own_profile"]).mean()),
                     "tail_external_share": float((~t["private"]).mean()),
                     "devices": cal["key"].n_unique(),
                     "external_devices": int(sum(not private(k) for k in cal["key"].unique().to_list()))}  # fmt: skip
        print(
            name,
            role,
            {
                k: (round(v, 3) if isinstance(v, float) else v)
                for k, v in res[name].items()
                if k != "role"
            },
        )
    Path("reports/phase8c").mkdir(parents=True, exist_ok=True)
    Path("reports/phase8c/tail_composition.json").write_text(json.dumps(res, indent=1), "utf-8")


if __name__ == "__main__":
    main()
