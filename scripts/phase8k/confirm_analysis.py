"""Phase 8k confirmatory analysis (docs/phase8k/PREREGISTRATION.md). Frozen before any fresh data.

Input: exactly one score file per evaluation UNIT and seed 0, 1, 2, in the Phase 8j
dev_scores.py schema (<unit>__seed<k>.npz: P1x calibration windows with the 70/30 hold-out flag;
evaluation windows with scores and labels), and a JSON map unit -> family. Every decision is
computed from calibration fields before any evaluation field of that unit is read.

Per unit and seed (decision time; calibration only):
  M0 always accept, threshold T0 (split-conformal, alpha = 1%; alert if strictly above)
  M1 PRIMARY: Phase 8i checks 1-3 (session n_eff >= 199; effective hosts >= 10 and top host
     <= 25%; host-grouped exceedance <= 2 alpha), threshold T0. (Check 4, block recency, is a
     time-coverage policy, not an adequacy decision: reported descriptively as K4.)
  M2 SECONDARY: >= 10 hosts and a PAC rank at the dependence-adjusted n_eff; threshold
     max(T0, PAC); a seed without a PAC rank uses the hold-out maximum (PAC count 0).
A unit is accepted by a rule when at least 2 of its 3 seeds accept.
Evaluation only, afterwards: adequacy per rule (seed-mean verified-benign FPR at the rule's own
threshold <= 2 alpha; >= 200 verified-benign windows, else indeterminate), a host-bootstrap
interval for it (borderline = the interval contains 2 alpha), and every registered metric.

Verdicts (pre-registration section 6): E1-E3, then K1 (M1) on criteria (a)-(f); K3 (M2) is read
only if K1 succeeds; sensitivity analyses are reported.

Usage:
  dry run on development data (writes under reports/phase8k/smoke only):
    uv run python scripts/phase8k/confirm_analysis.py --stand-in --scores data/derived/phase8j/dev
  confirmatory (refused unless docs/phase8k/FREEZE.md records this file's SHA-256):
    uv run python scripts/phase8k/confirm_analysis.py --confirm --scores DIR --families FILE.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8j"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
_spec = importlib.util.spec_from_file_location("phase8j_dev_compare",
                                               ROOT / "scripts/phase8j/dev_compare.py")  # fmt: skip
DC = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(DC)

ALPHA = 0.01
TOL = 2 * ALPHA
SEEDS = (0, 1, 2)
MIN_BENIGN_UNIT = 200
MIN_ENTITY_WINDOWS = 5
B_BOOT = 2000
RULES = ("M0", "M1", "M2")


# ----------------------------------------------------------------------------- decision time
def decisions(d) -> dict:
    """Calibration-only: the unit's full P1x hold-out. (accept, threshold) per rule."""
    h = d.cal["hold"]
    s = d.cal["s"][h]
    c = DC.calib(s, d.cal["key"][h], d.cal["win"][h], d.cal["end"][h], np.random.default_rng(0))
    m2 = c["t_m3"] is not None
    return {"M0": (True, c["t0"]), "M1": (DC.m1_network_pass(c), c["t0"]),
            "M2": (m2, c["t_m3"] if m2 else float(s.max())), "_t0": c["t0"],
            "_stats": {k: c[k] for k in ("n", "hosts", "eff_hosts", "top_share", "sess_neff",
                                         "m3_neff", "pac_l", "tie", "grouped")}}  # fmt: skip


# ----------------------------------------------------------------------------- evaluation
def unit_eval(d, thr: float, accept: bool, hold_end: float) -> dict:
    """Evaluation-period metrics of one unit and seed; an abstaining rule raises no alert.
    Attack entities come from the labels: sources with >= 5 attack windows."""
    ev = d.ev
    a = (ev["s"] > thr) & accept
    y, ben, key, end = ev["y"], ev["benign"], ev["key"], ev["end"]
    ek, ec = np.unique(key[y], return_counts=True)
    ents = ek[ec >= MIN_ENTITY_WINDOWS]
    det, delays = [], []
    for e in ents:
        m = y & (key == e)
        if (a & m).any():
            det.append(e)
            delays.append(float((end[a & m].min() - end[m].min()) / 1000))
    hosts, inv = np.unique(key[ben], return_inverse=True)
    early = end <= hold_end + 24 * 3.6e6  # K4: first 24 h after the hold-out
    hours = max(float(np.ptp(end)) / 3.6e6, 1e-9) if len(end) else 1e-9
    return {"benign": int(ben.sum()), "fp": int(a[ben].sum()),
            "fpr": float(a[ben].mean()) if ben.any() else None,
            "fpr_first_24h": float(a[ben & early].mean()) if (ben & early).any() else None,
            "fpr_after_24h": float(a[ben & ~early].mean()) if (ben & ~early).any() else None,
            "host_fp": np.bincount(inv, a[ben].astype(float), minlength=len(hosts)),
            "host_n": np.bincount(inv, minlength=len(hosts)).astype(float),
            "attack_windows": int(y.sum()), "detected_windows": int(a[y].sum()),
            "entities": len(ents), "entities_detected": len(det), "delays": delays,
            "false_alerts_per_h": float(a[ben].sum() / hours), "alerts_per_h": float(a.sum() / hours),
            "eval_windows": int(len(a))}  # fmt: skip


def seed_mean(ms: list[dict]) -> dict:
    m = dict(ms[0])
    for k in ("fpr", "fpr_first_24h", "fpr_after_24h", "false_alerts_per_h", "alerts_per_h"):
        vals = [x[k] for x in ms if x[k] is not None]
        m[k] = float(np.mean(vals)) if vals else None
    for k in ("fp", "detected_windows", "entities_detected"):
        m[k] = float(np.mean([x[k] for x in ms]))
    m["host_fp"] = np.mean([x["host_fp"] for x in ms], axis=0)
    m["delays"] = sum((x["delays"] for x in ms), [])
    return m


def host_rates(fp: np.ndarray, n: np.ndarray, size: int, rng: np.random.Generator,
               chunk: int = 200) -> np.ndarray:  # fmt: skip
    """`size` host-bootstrap FPR draws (hosts resampled with replacement), generated in chunks so
    that a unit with thousands of hosts never holds a size x hosts matrix at once."""
    h = len(n)
    out = []
    for s in range(0, size, chunk):
        w = rng.multinomial(h, np.full(h, 1 / h), size=min(chunk, size - s)).astype(float)
        out.append((w @ fp) / np.maximum(w @ n, 1))
    return np.concatenate(out) if out else np.zeros(0)


def host_interval(m: dict, rng: np.random.Generator) -> list | None:
    """95% host-bootstrap interval of a unit's verified-benign FPR (hosts are the clusters)."""
    if len(m["host_n"]) == 0:
        return None
    f = host_rates(m["host_fp"], m["host_n"], B_BOOT, rng)
    return [float(np.quantile(f, 0.025)), float(np.quantile(f, 0.975))]


def two_level_ucb(units: list[dict], fam: dict[str, str], rng: np.random.Generator) -> float | None:
    """95th percentile of the pooled FPR (mean over units within a family, then over families)
    when units are resampled within each family and hosts within each drawn unit (a fresh host
    resample per draw slot). Units without verified-benign windows are left out, as in
    `pooled`. Families themselves are not resampled (there are at most 2)."""
    by_fam: dict[str, list] = {}
    for u in units:
        if len(u["host_n"]):
            by_fam.setdefault(fam[u["unit"]], []).append(u)
    if not by_fam:
        return None
    draws = np.zeros(B_BOOT)
    for us in by_fam.values():
        k = len(us)
        pick = rng.integers(0, k, size=(B_BOOT, k))
        tot = np.zeros(B_BOOT)
        for j in range(k):
            for i, u in enumerate(us):
                sel = pick[:, j] == i
                if not sel.any():
                    continue
                tot[sel] += host_rates(u["host_fp"], u["host_n"], int(sel.sum()), rng)
        draws += tot / k
    return float(np.quantile(draws / len(by_fam), 0.95))


def pooled(units: list[dict], fam: dict[str, str], key: str) -> float | None:
    by_fam: dict[str, list] = {}
    for u in units:
        if u[key] is not None:
            by_fam.setdefault(fam[u["unit"]], []).append(u[key])
    return float(np.mean([np.mean(v) for v in by_fam.values()])) if by_fam else None


def hypergeom_p(n_units: int, n_unsafe: int, n_accepted: int, fa: int) -> float:
    """P(a uniformly random set of n_accepted units holds <= fa unsafe units)."""
    from scipy.stats import hypergeom

    return float(hypergeom.cdf(fa, n_units, n_unsafe, n_accepted))


def best_possible_p(n_units: int, n_unsafe: int) -> float:
    """(d)'s p-value for a perfect rule (accepts every adequate unit, no unsafe one): 1/C(N, K)."""
    return 1.0 / math.comb(n_units, n_unsafe) if 0 < n_unsafe < n_units else 1.0


def clopper(k: int, n: int) -> list | None:
    from scipy.stats import beta

    if n == 0:
        return None
    lo = 0.0 if k == 0 else float(beta.ppf(0.025, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(0.975, k + 1, n - k))
    return [lo, hi]


# ----------------------------------------------------------------------------- reports
def rule_report(rule: str, units: list[dict], fam: dict[str, str], rng) -> dict:
    """Every registered metric of one rule over the given units (adequacy at the rule's own
    threshold). Recall on accepted units is window-weighted; false alerts per hour is the plain
    mean over accepted units; FPR is pooled by family, then unit."""
    det = [u for u in units if u["adequate"][rule] is not None]
    acc = [u for u in units if u["accept"][rule]]
    ok = [u for u in det if u["adequate"][rule]]
    bad = [u for u in det if not u["adequate"][rule]]
    fa = sum(u["accept"][rule] for u in bad)
    fr = sum(not u["accept"][rule] for u in ok)
    acc_det = sum(u["accept"][rule] for u in det)
    met = lambda u: u["metrics"][rule]  # noqa: E731
    m = [met(u) for u in acc]
    ents_all = sum(met(u)["entities"] for u in units)
    ents_ok = sum(met(u)["entities"] for u in ok)
    ents_acc_ok = sum(met(u)["entities"] for u in ok if u["accept"][rule])
    ents_acc = sum(x["entities"] for x in m)
    accepted = [{"unit": u["unit"], **met(u)} for u in acc]
    att_all = sum(met(u)["attack_windows"] for u in units)
    return {
        "accepted_units": [u["unit"] for u in acc], "units": len(units), "determinable": len(det),
        "adequate": len(ok), "unsafe": len(bad), "accepted_determinable": acc_det,
        "false_accept": fa, "false_reject": fr,
        "far": fa / len(bad) if bad else None, "far_ci95": clopper(fa, len(bad)),
        "frr": fr / len(ok) if ok else None, "frr_ci95": clopper(fr, len(ok)),
        "coverage_units": len(acc) / len(units) if units else None,
        "coverage_given_adequate": (len(ok) - fr) / len(ok) if ok else None,
        "coverage_given_unsafe": fa / len(bad) if bad else None,
        "coverage_eval_windows": sum(x["eval_windows"] for x in m) / max(sum(met(u)["eval_windows"] for u in units), 1),
        "coverage_attack_windows": sum(x["attack_windows"] for x in m) / att_all if att_all else None,
        "coverage_attack_entities": ents_acc / ents_all if ents_all else None,
        "coverage_attack_entities_on_adequate": ents_acc_ok / ents_ok if ents_ok else None,
        "fpr_accepted_pooled": pooled(accepted, fam, "fpr"),
        "fpr_accepted_ucb95": two_level_ucb(accepted, fam, rng) if accepted else None,
        "recall_accepted": (sum(x["detected_windows"] for x in m) / max(sum(x["attack_windows"] for x in m), 1)) if m else None,
        "recall_overall": sum(met(u)["detected_windows"] for u in units) / att_all if att_all else None,
        "entity_recall_accepted": sum(x["entities_detected"] for x in m) / ents_acc if ents_acc else None,
        "entity_recall_overall": sum(met(u)["entities_detected"] for u in units) / ents_all if ents_all else None,
        "median_delay_s_accepted": float(np.median(sum((x["delays"] for x in m), []))) if any(x["delays"] for x in m) else None,
        "false_alerts_per_h_accepted": float(np.mean([x["false_alerts_per_h"] for x in m])) if m else None,
        "alerts_per_h_overall": float(np.mean([met(u)["alerts_per_h"] for u in units])) if units else None,
        "k4_fpr_first_24h_accepted": pooled(accepted, fam, "fpr_first_24h"),
        "k4_fpr_after_24h_accepted": pooled(accepted, fam, "fpr_after_24h"),
        "random_selection_p": hypergeom_p(len(det), len(bad), acc_det, fa) if det else None,
        "random_selection_best_possible_p": best_possible_p(len(det), len(bad)),
        "per_family": {f: {"unsafe": sum(fam[u["unit"]] == f for u in bad),
                           "false_accept": sum(fam[u["unit"]] == f and u["accept"][rule] for u in bad),
                           "fpr_accepted_pooled": pooled([x for x in accepted if fam[x["unit"]] == f], fam, "fpr")}
                       for f in sorted(set(fam[u["unit"]] for u in units))},
    }  # fmt: skip


def verdict(r: dict) -> dict:
    """Criteria (a)-(f) of the pre-registration, section 6."""
    a = r["far"] is not None and r["far"] <= 0.25
    b = r["frr"] is not None and r["frr"] <= 0.5 and r["accepted_determinable"] >= 2
    c = (r["fpr_accepted_pooled"] is not None and r["fpr_accepted_pooled"] <= TOL
         and r["fpr_accepted_ucb95"] is not None and r["fpr_accepted_ucb95"] <= 0.03)  # fmt: skip
    d = r["random_selection_p"] is not None and r["random_selection_p"] <= 0.05
    e = (r["entity_recall_accepted"] is not None and r["entity_recall_accepted"] >= 0.5
         and r["coverage_attack_entities_on_adequate"] is not None
         and r["coverage_attack_entities_on_adequate"] >= 0.5)  # fmt: skip
    f = all((v["unsafe"] == 0 or v["false_accept"] / v["unsafe"] <= 0.25)
            and (v["fpr_accepted_pooled"] is None or v["fpr_accepted_pooled"] <= TOL)
            for v in r.get("per_family", {}).values())  # fmt: skip
    crit = {"a_false_acceptance": a, "b_false_rejection": b, "c_accepted_fpr": c,
            "d_beats_random": d, "e_detection": e, "f_each_family": f}  # fmt: skip
    return {"criteria": crit, "verdict": "success" if all(crit.values()) else "failure"}


def gates(units: list[dict], rule: str, fam: dict[str, str]) -> dict:
    det = [u for u in units if u["adequate"][rule] is not None]
    n_ok = sum(u["adequate"][rule] for u in det)
    n_bad = len(det) - n_ok
    return {"E1_at_least_4_determinable_units": len(det) >= 4,
            "E2_two_adequate_and_two_unsafe": n_ok >= 2 and n_bad >= 2,
            "E3_d_attainable": best_possible_p(len(det), n_bad) <= 0.05,
            "determinable_families": sorted({fam[u["unit"]] for u in det})}  # fmt: skip


def judge(units: list[dict], rule: str, fam: dict[str, str], rng) -> dict:
    rep = rule_report(rule, units, fam, rng)
    g = gates(units, rule, fam)
    rep["gates"] = g
    if not g["E1_at_least_4_determinable_units"]:
        rep["verdict"] = "not evaluable (E1)"
    elif not g["E2_two_adequate_and_two_unsafe"]:
        rep["verdict"] = "discrimination not evaluable (E2); conditional detection descriptive"
    elif not g["E3_d_attainable"]:
        rep["verdict"] = (
            "discrimination not evaluable (E3: even a perfect rule cannot reach p <= 0.05)"
        )
    else:
        rep.update(verdict(rep))
        if len(g["determinable_families"]) == 1:
            rep["verdict"] += " (single environment family)"
    return rep


def collapse_family(units: list[dict], family: str, fam: dict[str, str]) -> tuple[list, dict]:
    """Sensitivity: one family's units merged into ONE unit (accepted / adequate by majority of
    its units; counts summed), so that (d) does not rely on those units being exchangeable."""
    inside = [u for u in units if fam[u["unit"]] == family]
    if len(inside) < 2:
        return units, fam
    merged = {"unit": f"{family}__merged", "accept": {}, "adequate": {}, "metrics": {}}
    for r in RULES:
        det = [u for u in inside if u["adequate"][r] is not None]
        merged["accept"][r] = sum(u["accept"][r] for u in inside) * 2 > len(inside)
        merged["adequate"][r] = (sum(u["adequate"][r] for u in det) * 2 > len(det)) if det else None
        ms = [u["metrics"][r] for u in inside]
        m = {k: sum(x[k] for x in ms) for k in ("benign", "fp", "attack_windows", "detected_windows",
                                                "entities", "entities_detected", "eval_windows")}  # fmt: skip
        m.update(fpr=m["fp"] / m["benign"] if m["benign"] else None,
                 host_fp=np.concatenate([x["host_fp"] for x in ms]),
                 host_n=np.concatenate([x["host_n"] for x in ms]), delays=sum((x["delays"] for x in ms), []),
                 false_alerts_per_h=float(np.mean([x["false_alerts_per_h"] for x in ms])),
                 alerts_per_h=float(np.mean([x["alerts_per_h"] for x in ms])),
                 fpr_first_24h=None, fpr_after_24h=None)  # fmt: skip
        merged["metrics"][r] = m
    out = [u for u in units if fam[u["unit"]] != family] + [merged]
    return out, {**fam, merged["unit"]: family}


# ----------------------------------------------------------------------------- main analysis
def analyse(scores: Path, fam: dict[str, str]) -> dict:
    rng = np.random.default_rng(8)
    names = sorted({p.name.split("__seed")[0] for p in scores.glob("*__seed*.npz")})
    missing = [
        f"{n}__seed{k}" for n in names for k in SEEDS if not (scores / f"{n}__seed{k}.npz").exists()
    ]
    if missing:
        sys.exit(f"every unit needs exactly seeds 0-2; missing: {missing}")
    units = []
    for name in names:
        per = []
        for k in SEEDS:
            d = DC.Domain(scores / f"{name}__seed{k}.npz")
            per.append((d, decisions(d)))  # calibration fields only
        acc = {r: sum(dec[r][0] for _, dec in per) >= 2 for r in RULES}
        ends = [float(d.cal["end"][d.cal["hold"]].max()) for d, _ in per]
        metrics, adequate, ci = {}, {}, {}
        for r in RULES:
            metrics[r] = seed_mean([unit_eval(d, dec[r][1], acc[r], e)
                                    for (d, dec), e in zip(per, ends, strict=True)])  # fmt: skip
            cand = seed_mean(
                [unit_eval(d, dec[r][1], True, e) for (d, dec), e in zip(per, ends, strict=True)]
            )
            ci[r] = host_interval(cand, rng)
            adequate[r] = None if cand["benign"] < MIN_BENIGN_UNIT else bool(cand["fpr"] <= TOL)
            if r == "M0":
                fpr_t0 = cand["fpr"]
        units.append({"unit": name, "accept": acc, "metrics": metrics, "adequate": adequate,
                      "fpr_t0": fpr_t0, "adequacy_ci95": ci,
                      "borderline": {r: ci[r] is not None and ci[r][0] <= TOL <= ci[r][1] for r in RULES},
                      "stats_seed0": per[0][1]["_stats"]})  # fmt: skip
    out = {"units": {u["unit"]: {"family": fam[u["unit"]], "accept": u["accept"], "fpr_t0": u["fpr_t0"],
                                 "adequate": u["adequate"], "adequacy_ci95": u["adequacy_ci95"],
                                 "borderline": u["borderline"], "stats_seed0": u["stats_seed0"]}
                     for u in units},
           "rules": {}, "sensitivity": {}}  # fmt: skip
    for r in RULES:
        out["rules"][r] = (
            judge(units, r, fam, rng) if r != "M0" else rule_report(r, units, fam, rng)
        )
    k1 = out["rules"]["M1"]["verdict"]
    if not k1.startswith("success"):
        out["rules"]["M2"]["verdict"] = (
            f"not read (K1: {k1}); computed: {out['rules']['M2']['verdict']}"
        )
    # sensitivity 1: units whose host interval contains 2 alpha (borderline) left out
    for r in ("M1", "M2"):
        firm = [u for u in units if not u["borderline"][r]]
        out["sensitivity"][f"{r}_without_borderline_units"] = (
            judge(firm, r, fam, rng)["verdict"] if firm else None
        )
    # sensitivity 2: each multi-unit family collapsed to one unit (exchangeability of (d))
    for f in sorted(set(fam.values())):
        cu, cf = collapse_family(units, f, fam)
        if cu is not units:
            out["sensitivity"][f"M1_{f}_as_one_unit"] = judge(cu, "M1", cf, rng)["verdict"]
    out["hypotheses"] = {"K1_primary_M1": k1, "K3_secondary_M2": out["rules"]["M2"]["verdict"],
                         "K2_conditional_detection": "descriptive: rules.M1 *_accepted metrics",
                         "K4_recency": "descriptive: rules.M1 k4_fpr_first_24h_accepted vs k4_fpr_after_24h_accepted"}  # fmt: skip
    return out


def frozen_hash_ok() -> bool:
    freeze = Path("docs/phase8k/FREEZE.md")
    if not freeze.exists():
        return False
    digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return digest in freeze.read_text("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scores", type=Path, required=True)
    ap.add_argument("--families", type=Path)
    ap.add_argument("--confirm", action="store_true")
    ap.add_argument("--stand-in", action="store_true")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if a.confirm == a.stand_in:
        sys.exit("pass exactly one of --confirm / --stand-in")
    if a.confirm and (not a.families or not frozen_hash_ok()):
        sys.exit("confirmatory run refused: --families is required and docs/phase8k/FREEZE.md must "
                 "record this file's SHA-256")  # fmt: skip
    out = a.out or (Path("reports/phase8k/confirm/verdicts.json") if a.confirm
                    else Path("reports/phase8k/smoke/verdicts.json"))  # fmt: skip
    if a.stand_in and not out.as_posix().startswith("reports/phase8k/smoke"):
        sys.exit("a stand-in dry run must write under reports/phase8k/smoke")
    names = {p.name.split("__seed")[0] for p in a.scores.glob("*__seed*.npz")}
    fam = (
        json.loads(a.families.read_text("utf-8"))
        if a.families
        else {n: n.split("__")[0] for n in names}
    )
    if not names <= set(fam):
        sys.exit(f"every unit needs a family; missing: {sorted(names - set(fam))}")
    mode = "confirm" if a.confirm else "stand-in (development data; NOT a result)"
    res = {"mode": mode, **analyse(a.scores, {n: fam[n] for n in names})}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, default=float), "utf-8")
    print(
        json.dumps({"hypotheses": res["hypotheses"], "sensitivity": res["sensitivity"]}, indent=1)
    )


if __name__ == "__main__":
    main()
