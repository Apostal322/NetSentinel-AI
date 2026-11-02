"""Phase 8i: label audit of the development networks (docs/phase8i/PREREGISTRATION.md section 8).

For every domain: attacker entities (evaluation and calibration), their attack-window counts,
the share of each attacker's windows that are attack windows, and the concentration of attack
windows in the top entities. Phase 8c found that the ToN_IoT labels did not identify initiators
in files 1-4 (3 hosts, 192.168.1.30-32, were endpoints of all attack flows); this checks whether
the NetFlow v3 attack windows are attributed to a small set of initiating sources.

Output: reports/phase8i/label_audit.json
Usage: uv run python scripts/phase8i/label_audit.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402, N812


def audit(d: dict) -> dict:
    ev = d["ev"]
    att = ev.filter(pl.col("y")).group_by("key").len().sort("len", descending=True)
    tot = ev.group_by("key").len().rename({"len": "all"})
    att = att.join(tot, on="key").with_columns(
        (pl.col("len") / pl.col("all")).alias("attack_share")
    )
    n = int(att["len"].sum()) if att.height else 0
    top = att.head(10)
    return {"eval_windows": ev.height, "benign_windows": int(ev["benign"].sum()),
            "attack_windows": n, "attack_entities": att.height,
            "top3_share": float(att.head(3)["len"].sum() / n) if n else None,
            "top": [dict(zip(top.columns, r, strict=True)) for r in top.iter_rows()],
            "pool_windows": d["pool"].height,
            "pool_entities": d["pool"]["key"].n_unique() if d["pool"].height else 0,
            "benign_cal_windows": d["cal"].height}  # fmt: skip


def main() -> None:
    out = {}
    for net in C.DEV_NETWORKS:
        for name, d in C.load_network(net).items():
            out[name] = audit(d)
            print(name, {k: out[name][k] for k in ("attack_windows", "attack_entities",
                                                   "top3_share", "pool_windows")}, flush=True)  # fmt: skip
    C.dump(Path("reports/phase8i/label_audit.json"), out)


if __name__ == "__main__":
    main()
