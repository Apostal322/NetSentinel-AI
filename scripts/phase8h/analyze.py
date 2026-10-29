"""Phase 8h [E]: apply the pre-registered decision rules (docs/phase8h/PREREGISTRATION.md
sections 4-5, amendments A1-A2) to the leave-one-domain-out outputs of lodo.py.

Written before any result of the registered run was inspected.
Output: reports/phase8h/analysis.json.
Usage: uv run python scripts/phase8h/analyze.py
"""

from __future__ import annotations

import json
from itertools import product
from pathlib import Path

import numpy as np

SRC = Path("reports/phase8h/lodo")
OUT = Path("reports/phase8h/analysis.json")
ALPHA = 0.01
FAMILY_ALPHA = 0.05
MODELS = ("B-raw", "B-loc", "N-dis", "B-lr")


SRC_H2 = Path("reports/phase8h/lodo_h2")  # B-rz with the registered T1 (amendment A3)
SRC_NDIS = Path("reports/phase8h/lodo_ndis_strict")


def load() -> dict[str, dict]:
    res = {p.stem: json.loads(p.read_text("utf-8")) for p in sorted(SRC.glob("*.json"))}
    for k, r in res.items():
        h2 = SRC_H2 / f"{k}.json"
        r["B-rz_source"] = "lodo_h2" if h2.exists() else "lodo (T1 floored at T0)"
        if h2.exists():
            r["B-rz"] = json.loads(h2.read_text("utf-8"))["B-rz"]
        nd = SRC_NDIS / f"{k}.json"  # N-dis with the registered strict screening (A3)
        r["N-dis_source"] = "lodo_ndis_strict" if nd.exists() else "lodo (as run)"
        if nd.exists() and r.get("per_seed"):
            strict = json.loads(nd.read_text("utf-8"))
            for mine, st in zip(r["per_seed"], strict["per_seed"], strict=True):
                mine["N-dis"] = st["N-dis"]
            r["screening"] = strict["screening"]
    return res


def sign_flip_p(d: np.ndarray) -> float:
    """Exact one-sided sign-flip permutation p of mean(d) > 0 (paired by domain)."""
    obs = d.mean()
    hits = sum(np.mean(d * np.array(s)) >= obs - 1e-12 for s in product((1, -1), repeat=len(d)))
    return hits / 2 ** len(d)


def boot_ci(d: np.ndarray, n: int = 10_000, seed: int = 0) -> list[float]:
    rng = np.random.default_rng(seed)
    m = d[rng.integers(0, len(d), (n, len(d)))].mean(axis=1)
    return [float(np.quantile(m, 0.025)), float(np.quantile(m, 0.975))]


def mcnemar_p(b: int, c: int) -> float:
    """One-sided exact McNemar: P(X >= b), X ~ Bin(b + c, 0.5); b = only T0 exceeds."""
    from scipy.stats import binom

    n = b + c
    return float(binom.sf(b - 1, n, 0.5)) if n else 1.0


def holm(pvals: dict[str, float]) -> dict[str, bool]:
    out, ok = {}, True
    for i, (k, p) in enumerate(sorted(pvals.items(), key=lambda x: x[1])):
        ok = ok and p <= FAMILY_ALPHA / (len(pvals) - i)
        out[k] = ok
    return out


def seed_mean(vals: list):
    """Mean over seeds of one leaf: numbers -> mean of the non-None values; booleans -> share
    True; anything else -> the common value if all seeds agree, else None (amendment A3)."""
    if all(isinstance(v, dict) for v in vals):
        return {k: seed_mean([v.get(k) for v in vals]) for k in set().union(*vals)}
    nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if nums and all(v is None or v in nums for v in vals):
        return float(np.mean(nums))
    if all(isinstance(v, bool) for v in vals):
        return float(np.mean(vals))
    return vals[0] if all(v == vals[0] for v in vals) else None


def sup(r: dict, model: str, thr: str = "T0") -> dict:
    """Seed-mean metrics of a supervised model (recomputed from per_seed, not lodo's mean)."""
    seeds = r.get("per_seed") or []
    if not seeds:
        return {}
    if "_sup" not in r:
        r["_sup"] = seed_mean([{k: v for k, v in s.items() if isinstance(v, dict)} for s in seeds])
    return (r["_sup"].get(model) or {}).get(thr) or {}


def paired(rows: dict, f) -> tuple[list[str], np.ndarray]:
    names, vals = [], []
    for n, r in rows.items():
        v = f(r)
        if v is not None:
            names.append(n)
            vals.append(v)
    return names, np.array(vals, dtype=float)


def test_mean(names, d, min_effect) -> dict:
    if len(d) == 0:
        return {"domains": [], "status": "no domains"}
    return {"domains": names, "deltas": d.round(4).tolist(), "mean": float(d.mean()),
            "ci95": boot_ci(d), "p_one_sided": sign_flip_p(d), "min_effect": min_effect,
            "effect_ok": bool(d.mean() >= min_effect)}  # fmt: skip


def main() -> None:
    res = load()
    primary = {k: r for k, r in res.items() if r["role"] == "primary"}
    h1_dom = {k: r for k, r in primary.items() if r["benign_windows"] >= 60}

    def oracle(m):
        return lambda r: sup(r, m).get("oracle_recall_at_fpr1")

    # ------------------------------------------------------------------ H1a, H1b
    n1, d1a = paired(h1_dom, lambda r: None if oracle("B-loc")(r) is None or oracle("B-raw")(r)
                     is None else oracle("B-loc")(r) - oracle("B-raw")(r))  # fmt: skip
    n2, d1b = paired(h1_dom, lambda r: None if oracle("N-dis")(r) is None or oracle("B-loc")(r)
                     is None else oracle("N-dis")(r) - oracle("B-loc")(r))  # fmt: skip
    h1a, h1b = test_mean(n1, d1a, 0.05), test_mean(n2, d1b, 0.05)
    h1b["n_dis_sources"] = sorted({h1_dom[k]["N-dis_source"] for k in n2})
    h1b["harmful_domains"] = [n for n, v in zip(n2, d1b, strict=True) if v < -0.20]

    # ------------------------------------------------------------------ H2 (B-rz primary)
    # amendment A1: the secondary (label-noisy) domain 02-22 is excluded from every primary test
    units = {k: r for k, r in res.items() if r["benign_windows"] >= 60 and r["role"] != "secondary"}
    ex = {k: (r["B-rz"]["T0"]["fpr"] > 2 * ALPHA, r["B-rz"]["T1"]["fpr"] > 2 * ALPHA)
          for k, r in units.items() if r["B-rz"]["T0"].get("fpr") is not None}  # fmt: skip
    e0 = np.mean([a for a, _ in ex.values()]) if ex else None
    e1 = np.mean([b for _, b in ex.values()]) if ex else None
    b = sum(a and not c for a, c in ex.values())
    c = sum(c and not a for a, c in ex.values())
    loss = [r["B-rz"]["T0"]["window_recall"] - r["B-rz"]["T1"]["window_recall"]
            for r in primary.values() if r["B-rz"]["T0"].get("window_recall") is not None]  # fmt: skip
    h2 = {"units": len(ex), "b_rz_sources": sorted({units[k]["B-rz_source"] for k in ex}), "exceedance_T0": e0, "exceedance_T1": e1,
          "only_T0_exceeds": b, "only_T1_exceeds": c, "p_one_sided": mcnemar_p(b, c),
          "median_recall_loss": float(np.median(loss)) if loss else None,
          "testable": bool(e0 is not None and e0 > 0.10),
          "effect_ok": bool(e0 is not None and e1 <= 0.5 * e0
                            and (np.median(loss) if loss else 0) <= 0.10)}  # fmt: skip
    sec2 = {}
    for thr in ("T0", "T1", "T2", "T3"):
        f = [r["B-rz"][thr].get("fpr") for r in units.values()]
        f = [x for x in f if x is not None]
        sec2[f"B-rz/{thr}"] = {"units": len(f), "exceedance": float(np.mean(np.array(f) > 2 * ALPHA))
                               if f else None, "median_fpr": float(np.median(f)) if f else None,
                               "p90_fpr": float(np.quantile(f, 0.9)) if f else None}  # fmt: skip
    t3 = [r["B-rz"]["T3"]["abstain"] for r in units.values()]
    sec2["B-rz/T3_coverage"] = 1 - float(np.mean(t3)) if t3 else None
    for thr in ("T0", "T1", "T2"):
        f = [sup(r, "B-loc", thr).get("fpr") for r in h1_dom.values()]
        f = [x for x in f if x is not None]
        sec2[f"B-loc/{thr}"] = {"units": len(f), "exceedance": float(np.mean(np.array(f) > 2 * ALPHA))
                                if f else None, "median_fpr": float(np.median(f)) if f else None}  # fmt: skip
    dep = [r["B-rz"]["deployed_crossfit"].get("fpr") for r in units.values()]
    dep = [x for x in dep if x is not None]
    sec2["B-rz/deployed_crossfit"] = {"units": len(dep),
                                      "exceedance": float(np.mean(np.array(dep) > 2 * ALPHA)),
                                      "median_fpr": float(np.median(dep))}  # fmt: skip

    # ------------------------------------------------------------------ H3
    def better(r):
        a, bb = sup(r, "B-loc"), r["B-rz"]["T0"]
        return (a, "B-loc") if (a.get("window_recall") or 0) >= (bb.get("window_recall") or 0) \
            else (bb, "B-rz")  # fmt: skip

    def fuse(r):
        sup(r, "B-loc")  # fills r["_sup"]
        return ((r.get("_sup") or {}).get("fusion") or {}).get("F-or") or {}

    n3, d3 = paired(primary, lambda r: None if fuse(r).get("window_recall") is None else
                    fuse(r)["window_recall"] - (better(r)[0].get("window_recall") or 0))  # fmt: skip
    h3 = test_mean(n3, d3, 0.05)
    fprs = [fuse(r).get("fpr") for r in primary.values() if r["benign_windows"] >= 60]
    fprs = [x for x in fprs if x is not None]
    ent_ok = [(fuse(r).get("entity_recall") or 0) >= (better(r)[0].get("entity_recall") or 0)
              for r in primary.values()]  # fmt: skip
    h3.update(fusion_median_fpr=float(np.median(fprs)) if fprs else None,
              entity_recall_not_worse_share=float(np.mean(ent_ok)) if ent_ok else None,
              better_component={k: better(r)[1] for k, r in primary.items()})  # fmt: skip
    h3["effect_ok"] = bool(h3.get("effect_ok") and h3["fusion_median_fpr"] is not None
                           and h3["fusion_median_fpr"] <= 1.5 * ALPHA
                           and h3["entity_recall_not_worse_share"] >= 0.75)  # fmt: skip

    # ------------------------------------------------------------------ decisions
    pv = {"H1a": h1a.get("p_one_sided", 1.0), "H1b": h1b.get("p_one_sided", 1.0),
          "H2": h2["p_one_sided"], "H3": h3.get("p_one_sided", 1.0)}  # fmt: skip
    hp = holm(pv)
    dec = {}
    for k, t in (("H1a", h1a), ("H1b", h1b), ("H2", h2), ("H3", h3)):
        if k == "H2" and not h2["testable"]:
            dec[k] = "not testable (T0 exceedance <= 10%)"
        elif t.get("effect_ok") and hp[k]:
            dec[k] = "success"
        elif hp[k] and not t.get("effect_ok"):
            dec[k] = "failure: significant but below the registered effect"
        else:
            dec[k] = "failure"
    if h1b["harmful_domains"]:  # registered: a loss > 0.20 on any domain is a harmful failure
        dec["H1b"] = "failure: harmful on " + ", ".join(h1b["harmful_domains"])

    # ------------------------------------------------------------------ descriptive tables
    table = {}
    for m in (*MODELS, "B-rz", "F-or"):
        rows = []
        for k, r in primary.items():
            t0 = r["B-rz"]["T0"] if m == "B-rz" else fuse(r) if m == "F-or" else sup(r, m)
            rows.append((k, r, t0))

        def mean(key, rows=rows):  # noqa: E306
            v = [t.get(key) for _, _, t in rows if t.get(key) is not None]
            return float(np.mean(v)) if v else None

        att = [(r["attack_windows"], t.get("window_recall")) for _, r, t in rows
               if t.get("window_recall") is not None]  # fmt: skip
        table[m] = {k2: mean(k2) for k2 in ("pr_auc", "roc_auc", "oracle_recall_at_fpr1",
                                             "oracle_entity_macro_recall", "window_recall",
                                             "entity_recall", "fpr", "false_alerts_per_h",
                                             "median_delay_s")}  # fmt: skip
        table[m]["micro_window_recall_T0"] = (sum(n * v for n, v in att) / sum(n for n, _ in att)
                                              if att else None)  # fmt: skip
        table[m]["per_domain"] = {k: {x: t.get(x) for x in ("oracle_recall_at_fpr1", "pr_auc",
                                                             "window_recall", "fpr",
                                                             "entity_recall")}
                                  for k, _, t in rows}  # fmt: skip
    out = {"label": "[E] development data; decisions by the pre-registered rules",
           "decisions": dec, "holm_pass": hp, "p_values": pv, "H1a": h1a, "H1b": h1b, "H2": h2,
           "H2_secondary": sec2, "H3": h3, "macro_table_primary": table,
           "screening_kept": {k: r.get("screening", {}).get("kept") for k, r in primary.items()},
           "secondary_domains": {k: {"B-loc": sup(r, "B-loc"), "B-rz": r["B-rz"]["T0"],
                                     "F-or": fuse(r)}
                                 for k, r in res.items() if r["role"] == "secondary"}}  # fmt: skip
    OUT.write_text(json.dumps(out, indent=1, default=str), "utf-8")
    print(json.dumps({"decisions": dec, "p_values": pv}, indent=1))


if __name__ == "__main__":
    main()
