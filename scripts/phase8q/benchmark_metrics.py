"""Phase 8q Stage 3: frozen M2 on the historical and audited benchmark views (saved scores only;
no model fitted).

**Score sets** (each a mean over 5 members; T0 = conformal rank at α = 1 % on the P1x hold-out):
- `frozen_M2_r0`: the frozen candidate's reference replicate (Phase 8n M2 base r0);
- `M2_8n`: Phase 8n M2, base + stress, r0-5 (12 fits);
- `M2_8o`: Phase 8o F0 (= Phase 8p S0), base + stress, r6-8 (6 fits).

**Views** (scripts/phase8q/label_audit.py `VIEWS`): the positives are the windows of the view's
categories.
- Entities of a view are sources with ≥ 5 positive windows in it; they are detected in a fit at
  ≥ 1 window / ≥ 20 % / ≥ 50 % of their windows.
- Negatives, by default, are the historical benign set (`benign_uninvolved` + `benign_involved_host`).
- Sensitivity negatives:
  - `uninvolved`: `benign_uninvolved` only;
  - `undocumented_as_benign`: the historical benign set plus every window of undocumented
    sources.

Output: reports/phase8q/benchmark_metrics.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8q/benchmark_metrics.py
"""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "phase8q_label_audit", ROOT / "scripts/phase8q/label_audit.py"
)
LA = importlib.util.module_from_spec(_spec)
sys.modules["phase8q_label_audit"] = LA
_spec.loader.exec_module(LA)

AUDIT = ROOT / "data" / "derived" / "phase8q" / "label_audit"
N8 = ROOT / "data" / "derived" / "phase8n" / "candidates" / "M2"
O8 = ROOT / "data" / "derived" / "phase8o" / "experiment_d" / "F0"
B0 = ROOT / "data" / "derived" / "phase8j" / "dev"
OUT = ROOT / "reports" / "phase8q" / "benchmark_metrics.json"
ALPHA = 0.01
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
BENIGN = ("benign_uninvolved", "benign_involved_host")
SCORE_SETS = {"frozen_M2_r0": [("base", 0)],
              "M2_8n": [(g, r) for g in ("base", "stress") for r in range(6)],
              "M2_8o": [(g, r) for g in ("base", "stress") for r in (6, 7, 8)]}  # fmt: skip


def t0_of(s_hold: np.ndarray, alpha: float = ALPHA) -> float:
    n = s_hold.size
    return float(np.sort(s_hold)[min(n, math.ceil((n + 1) * (1 - alpha))) - 1])


def load_scores(name: str, set_name: str, regime: str, r: int) -> tuple[np.ndarray, np.ndarray]:
    f = f"{name.replace('/', '__')}__r{r}.npz"
    if set_name == "M2_8o":
        z = np.load(O8 / regime / f)
        return z["s_hold"].mean(0), z["s_ev"].mean(0)
    z = np.load(N8 / regime / f)
    return z["s_hold"], z["s_ev"]


def entities(key: np.ndarray, pos: np.ndarray, min_windows: int = 5) -> list[str]:
    k, c = np.unique(key[pos], return_counts=True)
    return [str(x) for x, n in zip(k, c, strict=True) if n >= min_windows]


def view_metrics(
    alert: np.ndarray, key: np.ndarray, pos: np.ndarray, neg: np.ndarray, hours: float
) -> dict:
    ents = entities(key, pos)
    frac = {e: float(alert[pos & (key == e)].mean()) for e in ents}
    nwin = {e: int((pos & (key == e)).sum()) for e in ents}
    fa = int((alert & neg).sum())
    return {"positives": int(pos.sum()), "negatives": int(neg.sum()),
            "recall": float(alert[pos].mean()) if pos.any() else None,
            "fpr": float(alert[neg].mean()) if neg.any() else None, "false_alerts": fa,
            "false_alerts_per_h": fa / hours if hours else None, "entity_frac": frac, "entity_windows": nwin}  # fmt: skip


def detected(frac: float, n: int, level: int) -> bool:
    return frac * n >= 1 - 1e-9 if level == 1 else frac >= level / 100 - 1e-12


def summarise(per_fit: dict[tuple, dict[str, dict]]) -> dict:
    nets = {}
    for net in NETWORKS:
        rows = [m for per in per_fit.values() for d, m in per.items() if d.startswith(net + "/")]
        rec = [m["recall"] for m in rows if m["recall"] is not None]
        fpr = [m["fpr"] for m in rows if m["fpr"] is not None]
        nets[net] = {
            "recall": float(np.mean(rec)) if rec else None,
            "fpr": float(np.mean(fpr)) if fpr else None,
            "false_alerts": float(np.mean([m["false_alerts"] for m in rows])),
        }
    rec = [v["recall"] for v in nets.values() if v["recall"] is not None]
    out = {
        "networks": nets,
        "macro_recall": float(np.mean(rec)) if rec else None,
        "R": {},
        "U": {},
        "N": {},
    }
    first = next(iter(per_fit.values()))
    for lv in (1, 20, 50):
        r = u = nn = 0
        for name, m in first.items():
            for e in m["entity_frac"]:
                v = [
                    detected(per[name]["entity_frac"][e], per[name]["entity_windows"][e], lv)
                    for per in per_fit.values()
                ]
                r, u, nn = r + all(v), u + (any(v) and not all(v)), nn + (not any(v))
        out["R"][lv], out["U"][lv], out["N"][lv] = r, u, nn
    out["entities"] = sum(len(m["entity_frac"]) for m in first.values())
    out["positives"] = {d: m["positives"] for d, m in first.items()}
    return out


def main() -> None:
    names = sorted(p.stem.replace("__", "/") for p in AUDIT.glob("*.parquet"))
    audit = {n: pl.read_parquet(AUDIT / f"{n.replace('/', '__')}.parquet") for n in names}
    hours = {n: float(np.load(B0 / f"{n.replace('/', '__')}__seed0.npz")["hours"]) for n in names}
    res: dict = {"status": "audit of saved scores (no fit); views from label_audit.py",
                 "audit_version": LA.AUDIT_VERSION, "score_sets": {}}  # fmt: skip
    negs = {"historical_benign": BENIGN, "uninvolved": ("benign_uninvolved",)}
    for set_name, fits in SCORE_SETS.items():
        out = {}
        for view, cats in LA.VIEWS.items():
            for neg_name in ("historical_benign", "uninvolved", "undocumented_as_benign"):
                if neg_name != "historical_benign" and view not in (
                    "V0_historical",
                    "V2_documented_attackers",
                ):
                    continue
                per_fit = {}
                for regime, r in fits:
                    per = {}
                    for name in names:
                        a = audit[name]
                        s_hold, s_ev = load_scores(name, set_name, regime, r)
                        if s_ev.size != a.height:
                            raise RuntimeError(f"{name}: scores and audit rows differ")
                        cat = a["category"].to_numpy().astype(str)
                        key = a["key"].to_numpy().astype(str)
                        pos = np.isin(cat, cats)
                        if neg_name == "undocumented_as_benign":
                            neg = np.isin(cat, BENIGN) | (
                                a["role"].to_numpy().astype(str) == "undocumented"
                            )
                            pos = pos & ~(a["role"].to_numpy().astype(str) == "undocumented")
                        else:
                            neg = np.isin(cat, negs[neg_name])
                        per[name] = view_metrics(s_ev > t0_of(s_hold), key, pos, neg, hours[name])
                    per_fit[(regime, r)] = per
                out[f"{view}|{neg_name}"] = summarise(per_fit)
        res["score_sets"][set_name] = out
        v0, v2 = (
            out["V0_historical|historical_benign"],
            out["V2_documented_attackers|historical_benign"],
        )
        print(set_name, "V0 macro", round(v0["macro_recall"], 3), "R20", v0["R"][20], "/", v0["entities"],
              "| V2 macro", round(v2["macro_recall"], 3), "R20", v2["R"][20], "/", v2["entities"], flush=True)  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    main()
