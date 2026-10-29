"""Phase 8h amendment A3, item 4: does N-dis screening keep the same features when the source
calibration windows of ATTACKING entities are removed (strict label-benign)?

For every primary and secondary held-out domain, recompute `lodo.screen` on the other domains
of its family (a) as run: all clean calibration windows, (b) strict: clean calibration windows
of entities that never attack in that domain. Folds whose kept set differs are listed; their
N-dis result must be re-run. No model is trained.
Output: reports/phase8h/screen_check.json.
Usage: uv run python scripts/phase8h/screen_check.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lodo  # noqa: E402

OUT = Path("reports/phase8h/screen_check.json")


def strict(d: dict) -> dict:
    return {**d, "cal": d["cal"].filter(~pl.col("key").is_in(list(d["attackers"])))}


def main() -> None:
    out = {}
    for family in ("netflow", "zeek"):
        doms = lodo.domains(family)
        strict_doms = {k: strict(v) for k, v in doms.items()}
        for name in lodo.PRIMARY[family] + lodo.SECONDARY[family]:
            if name not in doms:
                continue
            src = {k: v for k, v in doms.items() if k != name}
            keep_a, _ = lodo.screen(src)
            keep_b, _ = lodo.screen(
                {k: strict_doms[k] for k in src if strict_doms[k]["cal"].height >= 60}
            )
            out[f"{family}__{name}"] = {
                "as_run": [lodo.FEATS[i] for i in keep_a],
                "strict": [lodo.FEATS[i] for i in keep_b], "same": keep_a == keep_b}  # fmt: skip
            print(family, name, keep_a == keep_b, flush=True)
    res = {"folds": out, "folds_changed": [k for k, v in out.items() if not v["same"]]}
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print(json.dumps({"folds_changed": res["folds_changed"]}))


if __name__ == "__main__":
    main()
