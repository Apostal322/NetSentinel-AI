"""Phase 8u post-hoc (EXPLORATORY; outcomes visible): where B's registered gain comes from.
Reads reports/phase8u/evaluation_final.json only. Output: reports/phase8u/posthoc.json"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
R = json.loads((ROOT / "reports/phase8u/evaluation_final.json").read_text("utf-8"))
S = R["summary"]
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
SEEDS = (1060, 1061, 1062)


def main() -> None:
    out: dict = {"status": "EXPLORATORY", "per_seed": {}, "per_domain": {}}
    for s in SEEDS:
        b, m = S[f"B|{s}"], S[f"M2member|{s}"]
        d = {n: {k: b["networks"][n][k] - m["networks"][n][k] for k in ("pauc_1pct", "recall_1pct", "calT_recall", "calT_fpr", "roc_auc")}
             for n in NETS}  # fmt: skip
        out["per_seed"][s] = {"networks": d,
                              "macro_d_pauc_without_nfbot": float(np.mean([d[n]["pauc_1pct"] for n in NETS if n != "nfbot"])),
                              "macro_d_pauc_hard_networks": float(np.mean([d[n]["pauc_1pct"] for n in ("nfunsw", "nfton")])),
                              "d_missed_oracle": b["missed_oracle"] - m["missed_oracle"], "d_missed_calT": b["missed_calT"] - m["missed_calT"],
                              "d_R20_oracle": b["R20_oracle"] - m["R20_oracle"]}  # fmt: skip
    for name in R["per_domain"]["B|1060"]:
        out["per_domain"][name] = [
            R["per_domain"][f"B|{s}"][name]["pauc_1pct"]
            - R["per_domain"][f"M2member|{s}"][name]["pauc_1pct"]
            for s in SEEDS
        ]
    base_sd = {
        n: float(np.std([S[f"M2member|{s}"]["networks"][n]["pauc_1pct"] for s in SEEDS], ddof=1))
        for n in NETS
    }
    out["baseline_seed_sd_pauc"] = base_sd
    out["mean_d_pauc_by_network"] = {
        n: float(np.mean([out["per_seed"][s]["networks"][n]["pauc_1pct"] for s in SEEDS]))
        for n in NETS
    }
    out["mean_macro_d_pauc_without_nfbot"] = float(
        np.mean([out["per_seed"][s]["macro_d_pauc_without_nfbot"] for s in SEEDS])
    )
    out["screening_single_seed"] = {
        v: {n: S[f"{v}|1060"]["networks"][n]["pauc_1pct"] for n in NETS}
        for v in ("A0", "A1", "A2", "B", "C1")
    }
    delays = {}
    for v in ("B", "M2member"):
        for s in SEEDS:
            dl = [
                x["oracle_1pct"]["delay_median_min"]
                for x in R["per_domain"][f"{v}|{s}"].values()
                if x["oracle_1pct"]["delay_median_min"] is not None
            ]
            delays[f"{v}|{s}"] = float(np.median(dl)) if dl else None
    out["median_domain_delay_min_oracle"] = delays
    (ROOT / "reports/phase8u/posthoc.json").write_bytes(json.dumps(out, indent=1).encode())
    print(
        json.dumps(
            {
                k: out[k]
                for k in (
                    "mean_d_pauc_by_network",
                    "mean_macro_d_pauc_without_nfbot",
                    "baseline_seed_sd_pauc",
                    "median_domain_delay_min_oracle",
                )
            },
            indent=1,
        )
    )
    for s in SEEDS:
        print(s, {k: v for k, v in out["per_seed"][s].items() if k != "networks"})


if __name__ == "__main__":
    main()
