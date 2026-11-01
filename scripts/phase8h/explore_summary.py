"""Phase 8h exploratory summary [E, post-hoc]: B-raw feature ablations and the calibration
sample-size study (pre-registration section 6). Not part of the registered decisions.
Output: reports/phase8h/exploratory_summary.json.
Usage: uv run python scripts/phase8h/explore_summary.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import ALPHA, seed_mean  # noqa: E402

R = Path("reports/phase8h")
METRICS = ("oracle_recall_at_fpr1", "window_recall", "entity_recall", "fpr", "pr_auc")


def load(d: Path) -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text("utf-8")) for p in sorted(d.glob("*.json"))}


def braw(r: dict) -> dict:
    return (seed_mean([s["B-raw"] for s in r["per_seed"]]) or {}).get("T0", {})


def ablations() -> dict:
    base = {k: r for k, r in load(R / "lodo").items() if r["role"] == "primary"}
    out = {}
    for d in sorted(R.glob("ablation_*")):
        ab = load(d)
        rows = {}
        for k, r in base.items():
            if k not in ab or not ab[k].get("per_seed"):
                continue
            b, a = braw(r), braw(ab[k])
            rows[k] = {m: {"full": b.get(m), "ablated": a.get(m),
                           "delta": None if b.get(m) is None or a.get(m) is None
                           else a[m] - b[m]} for m in METRICS}  # fmt: skip
        macro = {m: float(np.mean([v[m]["delta"] for v in rows.values()
                                   if v[m]["delta"] is not None]))
                 for m in METRICS if any(v[m]["delta"] is not None for v in rows.values())}  # fmt: skip
        out[d.name.removeprefix("ablation_")] = {"macro_delta": macro, "per_domain": rows}
    return out


def calsize() -> dict:
    res = load(R / "calsize")
    units = {k: r for k, r in res.items() if r["benign_windows"] >= 60 and r["role"] != "secondary"}
    attack = {k: r for k, r in res.items() if r["role"] == "primary"}
    out = {}
    for m in ("15", "30", "60", "120"):
        row = {}
        for thr in ("T0", "deployed_crossfit"):
            f = [r["calsize"][m][thr]["fpr"] for r in units.values()
                 if thr in r["calsize"].get(m, {}) and r["calsize"][m][thr].get("fpr") is not None]  # fmt: skip
            rec = [r["calsize"][m][thr]["window_recall"] for r in attack.values()
                   if thr in r["calsize"].get(m, {})
                   and r["calsize"][m][thr].get("window_recall") is not None]  # fmt: skip
            row[thr] = {"units": len(f),
                        "exceedance": float(np.mean(np.array(f) > 2 * ALPHA)) if f else None,
                        "median_fpr": float(np.median(f)) if f else None,
                        "p90_fpr": float(np.quantile(f, 0.9)) if f else None,
                        "attack_domains": len(rec),
                        "median_window_recall": float(np.median(rec)) if rec else None}  # fmt: skip
        out[m] = row
    return out


def main() -> None:
    out = {"label": "[E] exploratory, after the registered tests", "ablations": ablations(),
           "calibration_minutes": calsize()}  # fmt: skip
    (R / "exploratory_summary.json").write_text(json.dumps(out, indent=1), "utf-8")
    print(json.dumps({"ablations": {k: v["macro_delta"] for k, v in out["ablations"].items()},
                      "calibration_minutes": out["calibration_minutes"]}, indent=1))  # fmt: skip


if __name__ == "__main__":
    main()
