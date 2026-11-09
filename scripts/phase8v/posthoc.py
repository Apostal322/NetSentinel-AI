"""Phase 8v failure analysis (EXPLORATORY; outcomes visible). Saved scores, boosters and the
registered evaluation only; no model is fitted and no registered verdict is changed.

1. Per-domain change in exact partial AUC for every screened candidate.
2. Where each candidate's guardrails failed (as-calibrated FPR, entities missed, recall).
3. NF-ToN and NF-UNSW by attack label: recall at the retrospective 1 % FPR threshold, baseline vs
   each candidate.
4. Entities (documented attackers with ≥ 5 windows): detected at ≥ 20 % and missed entirely at
   the retrospective 1 % threshold, per candidate.
5. Split-gain share of the added columns in each saved booster (descriptive only).

Output: reports/phase8v/posthoc.json
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")
REP = ROOT / "reports/phase8v"
DER = ROOT / "data/derived/phase8v"
F0 = ROOT / "data/derived/phase8o/experiment_d/F0/base"
VARIANTS = ("FLOW", "TIME", "BIDIR", "INV")
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
SEED = 1060


def scores(variant: str, name: str) -> np.ndarray:
    f = name.replace("/", "__")
    if variant == "M2member":
        return np.load(F0 / f"{f}__r6.npz")["s_ev_u"][0]
    return np.load(DER / "scores" / variant / f"{f}__s{SEED}.npz")["s_ev_u"]


def main() -> None:
    ev = json.loads((REP / "evaluation_screening.json").read_text("utf-8"))
    per, summ = ev["per_domain"], ev["summary"]
    names = sorted(per[f"M2member|{SEED}"])
    out: dict = {"status": "EXPLORATORY failure analysis (outcomes visible)", "per_domain_d_pauc": {}, "guardrail_detail": {},
                 "by_attack_label": {}, "entities": {}, "added_column_gain_share": {}}  # fmt: skip
    for v in VARIANTS:
        out["per_domain_d_pauc"][v] = {
            n: per[f"{v}|{SEED}"][n]["pauc_1pct"] - per[f"M2member|{SEED}"][n]["pauc_1pct"]
            for n in names
        }
        c, b = summ[f"{v}|{SEED}"], summ[f"M2member|{SEED}"]
        out["guardrail_detail"][v] = {
            "calT_fpr": {n: [b["networks"][n]["calT_fpr"], c["networks"][n]["calT_fpr"]] for n in NETS},
            "calT_recall": {n: [b["networks"][n]["calT_recall"], c["networks"][n]["calT_recall"]] for n in NETS},
            "missed_calT": [b["missed_calT"], c["missed_calT"]], "missed_oracle": [b["missed_oracle"], c["missed_oracle"]],
            "R20_oracle": [b["R20_oracle"], c["R20_oracle"]], "R20_calT": [b["R20_calT"], c["R20_calT"]]}  # fmt: skip
    for name in names:
        d = OF.load(name)
        a = pl.read_parquet(
            OF.BM.AUDIT / f"{name.replace('/', '__')}.parquet", columns=["attack_labels"]
        )
        lab = a["attack_labels"].fill_null("").to_numpy().astype(str)
        budget = int(math.floor(0.01 * d["neg"].sum()))
        alerts = {}
        for v in ("M2member", *VARIANTS):
            s = scores(v, name)
            alerts[v] = s > OF.TO.global_threshold(s[d["neg"]], budget)
        ents = {}
        for v, al in alerts.items():
            det20 = missed = 0
            for _, idx in d["ents"]:
                f = al[idx].mean()
                det20 += f >= 0.2 - 1e-12
                missed += not al[idx].any()
            ents[v] = {
                "entities": len(d["ents"]),
                "detected_20pct": int(det20),
                "missed": int(missed),
            }
        out["entities"][name] = ents
        if name.startswith(("nfton", "nfunsw")):
            # group labels by their attack families present; report labels with >= 100 windows
            rows = {}
            for label in np.unique(lab[d["pos"]]):
                m = d["pos"] & (lab == label)
                if m.sum() >= 100:
                    rows[label] = {
                        "windows": int(m.sum()),
                        **{v: float(al[m].mean()) for v, al in alerts.items()},
                    }
            out["by_attack_label"][name] = rows
        print(name, flush=True)
    import lightgbm as lgb

    for v in VARIANTS:
        share = {}
        for net in NETS:
            mf = json.loads((DER / "manifests" / f"{v}__{net}__s{SEED}.json").read_text("utf-8"))
            # the driver wrote the model in text mode, so the files have CRLF line endings, which
            # LightGBM cannot parse; normalised, the text matches the recorded SHA-256 (amendment V-1)
            path = DER / "models" / f"{v}__{net}__s{SEED}.txt"
            raw = path.read_bytes().replace(bytes([13, 10]), bytes([10]))  # CRLF -> LF
            if hashlib.sha256(raw).hexdigest() != mf["model_sha256"]:
                raise RuntimeError(f"{v} {net}: saved model does not match its recorded hash")
            bst = lgb.Booster(model_str=raw.decode("utf-8"))
            gain = bst.feature_importance(importance_type="gain")
            cols = mf["train_columns"]
            added = set(mf["added_columns"])
            tot = float(gain.sum())
            top = sorted(zip(cols, gain / tot, strict=True), key=lambda t: -t[1])[:5]
            share[net] = {"added_gain_share": float(sum(g for c, g in zip(cols, gain, strict=True) if c in added) / tot),
                          "top5": [[c, round(float(g), 3)] for c, g in top], "dropped": mf.get("dropped_columns", [])}  # fmt: skip
        out["added_column_gain_share"][v] = share
    (REP / "posthoc.json").write_bytes(json.dumps(out, indent=1, default=float).encode())
    for v in VARIANTS:
        print(v, {n: round(x, 3) for n, x in out["per_domain_d_pauc"][v].items()})
        print(
            "   guard",
            {
                k: (
                    x
                    if not isinstance(x, dict)
                    else {n: [round(a, 3) for a in y] for n, y in x.items()}
                )
                for k, x in out["guardrail_detail"][v].items()
            },
        )
        print(
            "   gain",
            {
                n: (round(x["added_gain_share"], 2), x["top5"])
                for n, x in out["added_column_gain_share"][v].items()
            },
        )
    print(json.dumps(out["by_attack_label"], indent=0)[:3500])
    tot = {
        v: [
            sum(e[v]["detected_20pct"] for e in out["entities"].values()),
            sum(e[v]["missed"] for e in out["entities"].values()),
        ]
        for v in ("M2member", *VARIANTS)
    }
    print(
        "entities det20/missed",
        tot,
        {n: e for n, e in out["entities"].items() if n.startswith(("nfton", "nfunsw", "nfbot"))},
    )


if __name__ == "__main__":
    main()
