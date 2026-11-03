"""Phase 8n amendment 2: replicate the registered M2 development GO with fresh randomness
(docs/phase8n/PREREGISTRATION.md, amendment 2). No model is fitted here.

Uses only the fresh replicates r = 3, 4, 5 (base and stress) of M0, M2 and M3 from
scripts/phase8n/candidates.py, none of which had been seen when the criteria were written.

RP1  G1 and G2 of amendment 1 on the fresh fits.
RP2  amendment 1's G3 (entity detected = at least one alerted window): U <= U(M0) - 3, R >= R(M0).
RP3  the same with detection = at least 20 % of the entity's attack windows alerted.
RP4  window collapses: domain-fits with window recall < 0.2 on the domains where the original
     Phase 8j B0 mean recall is >= 0.5; M2 must have fewer than M0.
Replicated development GO for M2 if RP1-RP4 all hold; otherwise "not replicated".

Output: reports/phase8n/replication.json
Usage: python scripts/phase8n/replication_check.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


CC = _load("phase8n_compare", "scripts/phase8n/compare_candidates.py")
ES = _load("phase8n_entity", "scripts/phase8n/entity_sensitivity.py")
AF = CC.AF
FRESH = (3, 4, 5)
OUT = ROOT / "reports" / "phase8n" / "replication.json"
COLLAPSE, STRONG_DOMAIN, SHARE = 0.2, 0.5, 0.2


def strong_domains(labels: dict) -> list[str]:
    """Domains where the Phase 8j B0 (seeds 0-2) mean window recall is >= 0.5."""
    out = []
    for name, lab in labels.items():
        rec = []
        for s in (0, 1, 2):
            z = np.load(AF.B0_DIR / f"{name.replace('/', '__')}__seed{s}.npz")
            hold = z["cal_s"][z["cal_hold"]]
            t0 = np.sort(hold)[AF.k_of(hold.size) - 1]
            rec.append(float((z["ev_s"][lab.y] > t0).mean()))
        if np.mean(rec) >= STRONG_DOMAIN:
            out.append(name)
    return out


def main() -> None:
    CC.REPS = FRESH
    ES.FITS = [(g, r) for g in ("base", "stress") for r in FRESH]
    labels = {n: AF.Labels(n) for n in CC.domains()}
    strong = strong_domains(labels)
    fits = [f"{g}_r{r}" for g, r in ES.FITS]
    res = {"status": "REGISTERED DEVELOPMENT (amendment 2 replication, fresh randomness on consumed "
                     "development networks)", "fresh_reps": FRESH, "strong_domains": strong, "models": {}}  # fmt: skip
    for model in ("M0", "M2", "M3"):
        f = CC.fits(model, labels)
        if f is None:
            sys.exit(f"{model}: fresh fits missing")
        s = CC.summarise(f, labels)
        share = ES.alerted_share(model, labels)
        s["share20"] = ES.counts(share, SHARE, fits)
        s["collapses"] = sum(
            per[n]["window_recall"] < COLLAPSE for per in f.values() for n in strong
        )
        res["models"][model] = s
    m0, m2 = res["models"]["M0"], res["models"]["M2"]
    g = CC.go(m2, m0)
    rp = {"RP1": bool(all(g["G1_recall_by_network"].values()) and g["G1_entity"]
                      and all(g["G2_workload_by_network"].values())),
          "RP2": bool(m2["U"] <= m0["U"] - CC.U_GAIN and m2["R"] >= m0["R"]),
          "RP3": bool(m2["share20"]["U"] <= m0["share20"]["U"] - CC.U_GAIN and m2["share20"]["R"] >= m0["share20"]["R"]),
          "RP4": bool(m2["collapses"] < m0["collapses"])}  # fmt: skip
    res["criteria"], res["go_detail"] = rp, g
    res["verdict"] = (
        "replicated development GO" if all(rp.values()) else "registered GO not replicated"
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(res, indent=1).encode())
    tmp.replace(OUT)
    for m, s in res["models"].items():
        print(m, "R/U/N", s["R"], s["U"], s["N"], "share20", s["share20"]["R"], s["share20"]["U"],
              "collapses", s["collapses"], {n: round(v["window_recall"], 3) for n, v in s["network_means"].items()})  # fmt: skip
    print(rp, res["verdict"])


if __name__ == "__main__":
    main()
