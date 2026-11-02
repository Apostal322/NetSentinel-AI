"""Phase 8l [E]: can calibration-period history foreshadow post-calibration failure?

Development data only (the Phase 8j P1x score files, seeds 0-2); fits nothing. For each domain
it compares a HISTORICAL signal, computed inside the calibration period (benign-train = first
70% of calibration slots vs hold-out = last 30%), with the same quantity in the evaluation
period, and with the realised verified-benign FPR at T0:

  turnover      share of hold-out windows from hosts absent from benign-train
                vs share of verified-benign evaluation windows from hosts absent from the
                whole calibration
  seen-host p95 shift   median over hosts present in both parts of (p95 later - p95 earlier)
  host dominance        largest host's share of windows (hold-out vs verified-benign evaluation)

The decomposition of Phase 8k found population turnover (NF-ToN-IoT) and dominant-host change
(N4) to be the post-calibration failure mechanisms. If history foreshadows them, a historical
drift-risk estimator is worth registering; if not, they need online monitoring.

Output: reports/phase8l/drift_history.json
Usage: uv run python scripts/phase8l/drift_history.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

DEV = Path("data/derived/phase8j/dev")
OUT = Path("reports/phase8l/drift_history.json")


def p95_shift(k_a: np.ndarray, s_a: np.ndarray, k_b: np.ndarray, s_b: np.ndarray) -> float | None:
    out = []
    for h in np.intersect1d(np.unique(k_a), np.unique(k_b)):
        a, b = s_a[k_a == h], s_b[k_b == h]
        if len(a) >= 20 and len(b) >= 20:
            out.append(float(np.quantile(b, 0.95) - np.quantile(a, 0.95)))
    return float(np.median(out)) if out else None


def top_share(k: np.ndarray) -> float | None:
    return float(np.unique(k, return_counts=True)[1].max() / len(k)) if len(k) else None


def main() -> None:
    names = sorted({p.name.split("__seed")[0] for p in DEV.glob("*__seed*.npz")})
    res = {}
    for name in names:
        rows = []
        for seed in (0, 1, 2):
            z = np.load(DEV / f"{name}__seed{seed}.npz")
            hold = z["cal_hold"]
            kt, st = z["cal_key"][~hold], z["cal_s"][~hold]
            kh, sh = z["cal_key"][hold], z["cal_s"][hold]
            ben = z["ev_benign"]
            ke, se = z["ev_key"][ben], z["ev_s"][ben]
            t0 = np.sort(sh)[min(int(np.ceil((len(sh) + 1) * 0.99)), len(sh)) - 1]
            rows.append({
                "hist_turnover": float((~np.isin(kh, kt)).mean()),
                "eval_turnover": float((~np.isin(ke, z["cal_key"])).mean()) if len(ke) else None,
                "hist_p95_shift_seen": p95_shift(kt, st, kh, sh),
                "eval_p95_shift_seen": p95_shift(z["cal_key"], z["cal_s"], ke, se),
                "hist_top_share": top_share(kh), "eval_top_share": top_share(ke),
                "fpr_t0": float((se > t0).mean()) if len(se) else None})  # fmt: skip
        res[name] = {k: (None if any(r[k] is None for r in rows) else float(np.mean([r[k] for r in rows])))
                     for k in rows[0]}  # fmt: skip
        print(name, {k: (round(v, 3) if v is not None else None) for k, v in res[name].items()})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")


if __name__ == "__main__":
    main()
