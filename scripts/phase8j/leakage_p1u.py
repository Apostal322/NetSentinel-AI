"""Phase 8j data-integrity audit, protocol P1u [E]: the deployable calibration.

P1u = all-flow (unlabelled) calibration windows minus the hosts known to attack DURING THE
CALIBRATION PERIOD, and all-flow evaluation windows. It uses no evaluation-period label and no
flow-level cleaning, so it removes all three label uses of the Phase 8i calibration (L1-L3 in
leakage_audit.py) except the past-period host exclusion an operator could do.

No model is fitted. P1u's hold-out is the P2_none hold-out without the calibration-period
attackers (checked: removing them does not move the 70% time cut), so its scores are read from
the seed-0 P2_none score files written by leakage_audit.py. Appends "P1u_past_unlabelled" to
every domain in reports/phase8j/leakage_audit.json.

Usage: uv run python scripts/phase8j/leakage_p1u.py   (after leakage_audit.py)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leakage_audit as LA  # noqa: E402, N812

C = LA.C
NAME = "P1u_past_unlabelled"


def main() -> None:
    res = json.loads(LA.OUT.read_text("utf-8"))
    nets = {n: C.load_network(n) for n in LA.NETWORKS}
    for name, r in res["domains"].items():
        net = name.split("/")[0]
        d = nets[net][name]
        base = C.DERIVED / d["network"] / d["name"]
        ct = pl.read_parquet(base / "cal_truth.parquet") if (base / "cal_truth.parquet").exists() \
            else pl.DataFrame(schema={"key": pl.Utf8, "win": pl.Int64, "y": pl.Boolean})  # fmt: skip
        cal_att = set(r["cal_attackers"])
        cal_u, ev_u = LA.unlabelled(d)
        kept = cal_u.filter(~pl.col("key").is_in(list(cal_att)))
        if C.S.split_cut(kept) != C.S.split_cut(cal_u):
            raise SystemExit(f"{name}: the time cut moves; P1u needs its own scoring run")
        z = np.load(LA.SCORES / f"{name.replace('/', '__')}__P2_none.npz")
        keep = ~np.isin(z["hold_key"], list(cal_att))
        hold = pl.DataFrame({"key": z["hold_key"][keep], "win": z["hold_win"][keep]})
        thr, _ = C.t0(z["s_hold"][keep])
        met = C.evaluate({**d, "ev": ev_u}, z["s_ev"], thr)
        r["protocols"][NAME] = {**LA.composition(hold, ct, d["attackers"]),
                                **{k: met.get(k) for k in ("threshold", "fpr", "window_recall",
                                   "false_alerts_per_h", "entity_recall", "roc_auc",
                                   "oracle_recall_at_fpr1")}}  # fmt: skip
        print(name, round(r["protocols"][NAME]["fpr"], 4),
              round(r["protocols"][NAME]["window_recall"], 3), flush=True)  # fmt: skip
    C.dump(LA.OUT, res)


if __name__ == "__main__":
    main()
