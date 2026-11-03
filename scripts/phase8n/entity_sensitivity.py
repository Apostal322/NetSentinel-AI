"""Phase 8n EXPLORATORY (post-hoc) sensitivity of the entity stability counts to the definition
of "detected" (docs/phase8n/REVIEW.md, finding A1-A2). Not part of the registered G1-G3 rule.

The registered rule counts an entity as detected when at least one of its attack windows is
alerted. Here the counts R / U / N over the 6 Experiment C fits are recomputed when detection
requires a share of the entity's windows (any window, >= 20 %, >= 50 %), with the fit in which
each instability occurs, and for the base regime alone.

Output: reports/phase8n/entity_sensitivity.json
Usage: python scripts/phase8n/entity_sensitivity.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8n_analyze", ROOT / "scripts/phase8n/analyze_fragility.py"
)
AF = importlib.util.module_from_spec(_spec)
sys.modules["phase8n_analyze"] = AF
_spec.loader.exec_module(AF)

CAND = ROOT / "data" / "derived" / "phase8n" / "candidates"
OUT = ROOT / "reports" / "phase8n" / "entity_sensitivity.json"
MODELS = ("M0", "M1", "M2", "M3")
FITS = [(g, r) for g in ("base", "stress") for r in (0, 1, 2)]
SHARES = {"any_window": 1e-12, "share_20pct": 0.2, "share_50pct": 0.5}


def alerted_share(model: str, labels: dict) -> dict:
    """(domain, entity) -> fit -> share of the entity's attack windows alerted at T0."""
    out: dict = {}
    for name, lab in labels.items():
        for g, r in FITS:
            z = np.load(CAND / model / g / f"{name.replace('/', '__')}__r{r}.npz")
            t0 = np.sort(z["s_hold"])[AF.k_of(z["s_hold"].size) - 1]
            alert = z["s_ev"] > t0
            for e, m in lab.masks.items():
                out.setdefault(f"{name}|{e}", {})[f"{g}_r{r}"] = float(alert[m].mean())
    return out


def counts(share: dict, thr: float, fits: list[str]) -> dict:
    r = u = n = 0
    misses: Counter = Counter()
    for v in share.values():
        d = [v[f] >= thr for f in fits]
        if all(d):
            r += 1
        elif any(d):
            u += 1
            misses.update(f for f, ok in zip(fits, d, strict=True) if not ok)
        else:
            n += 1
    return {"R": r, "U": u, "N": n, "unstable_misses_by_fit": dict(misses)}


def main() -> None:
    names = sorted(
        p.name.split("__seed0")[0].replace("__", "/") for p in AF.B0_DIR.glob("*__seed0.npz")
    )
    labels = {n: AF.Labels(n) for n in names}
    all_fits = [f"{g}_r{r}" for g, r in FITS]
    res = {"status": "EXPLORATORY (post-hoc, after the independent review); not a registered criterion",
           "models": {}}  # fmt: skip
    for model in MODELS:
        share = alerted_share(model, labels)
        res["models"][model] = {k: {"all_6_fits": counts(share, t, all_fits),
                                    "base_only": counts(share, t, all_fits[:3])}
                                for k, t in SHARES.items()}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(res, indent=1).encode())
    tmp.replace(OUT)
    for m, v in res["models"].items():
        print(
            m,
            {
                k: (x["all_6_fits"]["R"], x["all_6_fits"]["U"], x["base_only"]["U"])
                for k, x in v.items()
            },
        )


if __name__ == "__main__":
    main()
