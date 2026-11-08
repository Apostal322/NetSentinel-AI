"""Phase 8r: print the registered tables from the saved reports (no computation beyond lookup).

Usage: python scripts/phase8r/summarise.py [A|B|C]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1].parent
R = ROOT / "reports" / "phase8r"
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")


def row(label: str, c: dict) -> str:
    cells = []
    for n in NETS:
        v = c["networks"].get(n)
        cells.append(
            "—"
            if v is None
            else f"{v['recall']:.3f} / {100 * v['fpr']:.1f} % (p90 {100 * v['fpr_p10_p90'][1]:.1f})"
        )
    return (
        f"| {label} | {c['macro_recall']:.3f} [{c['macro_p10_p90'][0]:.3f}, {c['macro_p10_p90'][1]:.3f}] | "
        + " | ".join(cells)
        + f" | {c['mean_R20']:.1f} |"
    )


def show_a() -> None:
    a = json.loads((R / "experiment_a.json").read_text("utf-8"))
    print(
        "| cell | macro recall [p10, p90] | "
        + " | ".join(f"{n} recall / FPR" for n in NETS)
        + " | R20 |"
    )
    print("|---|---|" + "---|" * len(NETS) + "---|")
    for k in ("A0", "A1", "A1T"):
        print(row(k, a["references"][k]))
    for cid, ms in a["cells"].items():
        for m, c in ms.items():
            if "macro_recall" in c:
                print(row(f"{cid} {m}", c))
            else:
                print(f"| {cid} {m} | abstention rate {c['abstention_rate']:.2f} |")
    print(json.dumps(a["decision_H_A1"], indent=1))
    print(json.dumps(a["categories"], indent=1))
    print(
        json.dumps(
            {k: v for k, v in a["effort"].items() if "modest" in k or "interval" in k}, indent=1
        )
    )


def show_b() -> None:
    b = json.loads((R / "experiment_b.json").read_text("utf-8"))
    print("evaluable", b["evaluable_domains"], "skipped", b["skipped_counts"])
    for m, c in b["clean"].items():
        print(
            "clean",
            m,
            round(c["macro_recall"], 3),
            {n: (round(v["recall"], 3), round(v["fpr"], 4)) for n, v in c["networks"].items()},
        )
    for m, mechs in b["cells"].items():
        for mech, fr in mechs.items():
            print(
                m,
                mech,
                {f: round(v["delta_macro_recall"], 3) for f, v in fr.items()},
                "dFPR@5%",
                {n: round(x, 4) for n, x in fr.get("0.05", {}).get("delta_fpr", {}).items()},
            )
    print(json.dumps(b["breakdown_fraction"], indent=1))
    print(json.dumps(b["decision_H_B1"], indent=1))


def show_c() -> None:
    c = json.loads((R / "experiment_c_features.json").read_text("utf-8"))
    for n, d in c["domains"].items():
        print(
            n,
            "legit",
            d["legit_destinations"],
            "attack_only",
            d["attack_only_destinations"],
            d["vetting"],
        )
        for m, r in d["memories"].items():
            print(
                "  ",
                m,
                {
                    k: (round(v, 4) if isinstance(v, float) else v)
                    for k, v in r.items()
                    if k != "growth"
                },
            )
    print(json.dumps(c["scored_part_gate"], indent=1))


if __name__ == "__main__":
    {"A": show_a, "B": show_b, "C": show_c}[sys.argv[1] if len(sys.argv) > 1 else "A"]()
