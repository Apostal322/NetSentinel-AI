"""Phase 8k confirmatory analysis (docs/phase8k/PREREGISTRATION.md). Frozen before any fresh data.

Input: one score file per evaluation UNIT and seed, in the Phase 8j dev_scores.py schema
(<unit>__seed<k>.npz: P1x calibration windows with the 70/30 hold-out flag, evaluation windows
with scores; evaluation labels are used ONLY after every decision below is computed), and a JSON
map unit -> family.

Per unit and seed, from the calibration only (decision time):
  M0 always accept, threshold T0 (split-conformal, alpha = 1%)
  M1 PRIMARY: Phase 8i checks 1-3 (session n_eff >= 199; effective hosts >= 10 and top host
     <= 25%; host-grouped exceedance <= 2 alpha), threshold T0
  M2 SECONDARY: >= 10 hosts and a PAC rank exists at the dependence-adjusted n_eff, threshold
     max(T0, PAC)
  controls: always abstain; random selection (exact hypergeometric)
Then, evaluation only: adequacy (seed-mean realised verified-benign FPR at T0 <= 2 alpha; needs
>= 200 verified-benign windows, else the unit is indeterminate) and every registered metric.
Decisions are the majority over seeds 0-2; metrics are seed means.

Verdicts (section 6 of the pre-registration): evaluability E1/E2, then K1 (M1) and K3 (M2) on
criteria (a)-(e); K2 conditional detection is descriptive.

Usage:
  dry run on development data (writes under reports/phase8k/smoke only):
    uv run python scripts/phase8k/confirm_analysis.py --stand-in --scores data/derived/phase8j/dev
  confirmatory (refused unless docs/phase8k/FREEZE.md exists):
    uv run python scripts/phase8k/confirm_analysis.py --confirm --scores DIR --families FILE.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
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
B_BOOT = 2000
RULES = ("M0", "M1", "M2")


# ----------------------------------------------------------------------------- decision time
def decisions(d) -> dict:
    """Calibration-only: the full P1x hold-out of the unit. Returns (accept, threshold) per rule."""
    h = d.cal["hold"]
    c = DC.calib(d.cal["s"][h], d.cal["key"][h], d.cal["win"][h], d.cal["end"][h],
                 np.random.default_rng(0))  # fmt: skip
    m2 = c["t_m3"] is not None
    return {"M0": (True, c["t0"]), "M1": (DC.m1_network_pass(c), c["t0"]),
            "M2": (m2, c["t_m3"] if m2 else c["t0"]), "_t0": c["t0"],
            "_stats": {k: c[k] for k in ("n", "hosts", "eff_hosts", "top_share", "sess_neff",
                                         "m3_neff", "pac_l", "tie", "grouped")}}  # fmt: skip


# ----------------------------------------------------------------------------- evaluation
def unit_eval(d, thr: float, accept: bool) -> dict:
    """Evaluation-period metrics of one unit; an abstaining rule raises no alert."""
    ev = d.ev
    a = (ev["s"] > thr) & accept
    y, ben, key = ev["y"], ev["benign"], ev["key"]
    ents, det, delays = 0, 0, []
    for e in d.attackers:
        m = y & (key == e)
        if m.sum() < 5:
            continue
        ents += 1
        if (a & m).any():
            det += 1
            delays.append(float((ev["end"][a & m].min() - ev["end"][m].min()) / 1000))
    bk = key[ben]
    _, inv = np.unique(bk, return_inverse=True)
    hours = max(float(np.ptp(ev["end"])) / 3.6e6, 1e-9)
    return {"benign": int(ben.sum()), "fp": int(a[ben].sum()),
            "fpr": float(a[ben].mean()) if ben.any() else None,
            "host_fp": np.bincount(inv, a[ben].astype(float)), "host_n": np.bincount(inv).astype(float),
            "attack_windows": int(y.sum()), "detected_windows": int(a[y].sum()),
            "entities": ents, "entities_detected": det, "delays": delays,
            "false_alerts_per_h": float(a[ben].sum() / hours), "alerts_per_h": float(a.sum() / hours),
            "eval_windows": int(len(a))}  # fmt: skip


def two_level_ucb(units: list[dict], fam: dict[str, str], rng: np.random.Generator) -> float | None:
    """95th percentile of the pooled FPR (mean over units within a family, mean over families)
    when units are resampled within each family and hosts within each unit."""
    by_fam: dict[str, list] = {}
    for u in units:
        by_fam.setdefault(fam[u["unit"]], []).append(u)
    if not by_fam:
        return None
    draws = np.zeros(B_BOOT)
    for us in by_fam.values():
        per_unit = []
        for u in us:
            h = len(u["host_n"])
            w = rng.multinomial(h, np.full(h, 1 / h), size=B_BOOT).astype(float)
            per_unit.append((w @ u["host_fp"]) / np.maximum(w @ u["host_n"], 1))
        per_unit = np.array(per_unit)  # units x B
        pick = rng.integers(0, len(us), size=(B_BOOT, len(us)))
        draws += per_unit[pick, np.arange(B_BOOT)[:, None]].mean(axis=1)
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


def clopper(k: int, n: int) -> list | None:
    from scipy.stats import beta

    if n == 0:
        return None
    lo = 0.0 if k == 0 else float(beta.ppf(0.025, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(0.975, k + 1, n - k))
    return [lo, hi]


def rule_report(rule: str, units: list[dict], fam: dict[str, str], rng) -> dict:
    det = [u for u in units if u["adequate"] is not None]
    acc = [u for u in units if u["accept"][rule]]
    n_ok = sum(u["adequate"] for u in det)
    n_bad = len(det) - n_ok
    fa = sum(1 for u in det if u["accept"][rule] and not u["adequate"])
    fr = sum(1 for u in det if not u["accept"][rule] and u["adequate"])
    acc_det = sum(1 for u in det if u["accept"][rule])
    m = [u["metrics"][rule] for u in acc]
    ents_all = sum(u["metrics"][rule]["entities"] for u in units)
    ents_ok = sum(u["metrics"][rule]["entities"] for u in det if u["adequate"])
    ents_acc_ok = sum(
        u["metrics"][rule]["entities"] for u in det if u["adequate"] and u["accept"][rule]
    )
    ents_acc = sum(x["entities"] for x in m)
    accepted_units = [{"unit": u["unit"], **u["metrics"][rule]} for u in acc]
    r = {
        "accepted_units": [u["unit"] for u in acc], "units": len(units), "determinable": len(det),
        "adequate": n_ok, "unsafe": n_bad, "false_accept": fa, "false_reject": fr,
        "far": fa / n_bad if n_bad else None, "far_ci95": clopper(fa, n_bad),
        "frr": fr / n_ok if n_ok else None, "frr_ci95": clopper(fr, n_ok),
        "coverage_units": len(acc) / len(units),
        "coverage_given_adequate": (n_ok - fr) / n_ok if n_ok else None,
        "coverage_given_unsafe": fa / n_bad if n_bad else None,
        "coverage_eval_windows": sum(x["eval_windows"] for x in m) / sum(u["metrics"][rule]["eval_windows"] for u in units),
        "coverage_attack_windows": (sum(x["attack_windows"] for x in m) / max(sum(u["metrics"][rule]["attack_windows"] for u in units), 1)),
        "coverage_attack_entities": ents_acc / ents_all if ents_all else None,
        "coverage_attack_entities_on_adequate": ents_acc_ok / ents_ok if ents_ok else None,
        "fpr_accepted_pooled": pooled(accepted_units, fam, "fpr"),
        "fpr_accepted_ucb95": two_level_ucb(accepted_units, fam, rng) if accepted_units else None,
        "recall_accepted": sum(x["detected_windows"] for x in m) / max(sum(x["attack_windows"] for x in m), 1) if m else None,
        "recall_overall": sum(u["metrics"][rule]["detected_windows"] for u in units) / max(sum(u["metrics"][rule]["attack_windows"] for u in units), 1),
        "entity_recall_accepted": sum(x["entities_detected"] for x in m) / ents_acc if ents_acc else None,
        "entity_recall_overall": sum(u["metrics"][rule]["entities_detected"] for u in units) / ents_all if ents_all else None,
        "median_delay_s_accepted": float(np.median(sum((x["delays"] for x in m), []))) if any(x["delays"] for x in m) else None,
        "false_alerts_per_h_accepted": float(np.mean([x["false_alerts_per_h"] for x in m])) if m else None,
        "alerts_per_h_overall": float(np.mean([u["metrics"][rule]["alerts_per_h"] for u in units])),
        "random_selection_p": hypergeom_p(len(det), n_bad, acc_det, fa) if det else None,
    }  # fmt: skip
    return r


def verdict(r: dict) -> dict:
    """Criteria (a)-(e) of the pre-registration, section 6."""
    a = r["far"] is not None and r["far"] <= 0.25
    b = r["frr"] is not None and r["frr"] <= 0.5 and len(r["accepted_units"]) >= 2
    c = (r["fpr_accepted_pooled"] is not None and r["fpr_accepted_pooled"] <= TOL
         and r["fpr_accepted_ucb95"] is not None and r["fpr_accepted_ucb95"] <= 0.03)  # fmt: skip
    d = r["random_selection_p"] is not None and r["random_selection_p"] <= 0.05
    e = (r["entity_recall_accepted"] is not None and r["entity_recall_accepted"] >= 0.5
         and r["coverage_attack_entities_on_adequate"] is not None
         and r["coverage_attack_entities_on_adequate"] >= 0.5)  # fmt: skip
    crit = {"a_false_acceptance": a, "b_false_rejection": b, "c_accepted_fpr": c,
            "d_beats_random": d, "e_detection": e}  # fmt: skip
    return {"criteria": crit, "verdict": "success" if all(crit.values()) else "failure"}


def analyse(scores: Path, fam: dict[str, str]) -> dict:
    rng = np.random.default_rng(8)
    names = sorted({p.name.split("__seed")[0] for p in scores.glob("*__seed*.npz")})
    units = []
    for name in names:
        per = []
        for k in SEEDS:
            p = scores / f"{name}__seed{k}.npz"
            if not p.exists():
                continue
            d = DC.Domain(p)
            dec = decisions(d)  # reads calibration fields only; no evaluation field is touched
            per.append((d, dec))
        acc = {r: sum(dec[r][0] for _, dec in per) * 2 > len(per) for r in RULES}
        metrics = {}
        for r in RULES:
            ms = [unit_eval(d, dec[r][1], acc[r]) for d, dec in per]
            m = ms[0].copy()
            for k in ("fpr", "false_alerts_per_h", "alerts_per_h"):
                vals = [x[k] for x in ms if x[k] is not None]
                m[k] = float(np.mean(vals)) if vals else None
            for k in ("fp", "detected_windows", "entities_detected"):
                m[k] = float(np.mean([x[k] for x in ms]))
            m["host_fp"] = np.mean([x["host_fp"] for x in ms], axis=0)
            m["delays"] = sum((x["delays"] for x in ms), [])
            metrics[r] = m
        t0 = [unit_eval(d, dec["_t0"], True) for d, dec in per]
        benign = t0[0]["benign"]
        fpr_t0 = float(np.mean([x["fpr"] for x in t0])) if benign else None
        units.append({"unit": name, "accept": acc, "metrics": metrics, "fpr_t0": fpr_t0,
                      "adequate": None if benign < MIN_BENIGN_UNIT else bool(fpr_t0 <= TOL),
                      "stats_seed0": per[0][1]["_stats"]})  # fmt: skip
    det = [u for u in units if u["adequate"] is not None]
    e1 = len(det) >= 4
    e2 = sum(u["adequate"] for u in det) >= 2 and sum(not u["adequate"] for u in det) >= 2
    out = {"units": {u["unit"]: {"family": fam[u["unit"]], "accept": u["accept"], "fpr_t0": u["fpr_t0"],
                                 "adequate": u["adequate"], "stats_seed0": u["stats_seed0"]} for u in units},
           "evaluability": {"E1_at_least_4_determinable_units": e1, "E2_two_adequate_and_two_unsafe": e2},
           "rules": {}}  # fmt: skip
    for r in RULES:
        rep = rule_report(r, units, fam, rng)
        if r in ("M1", "M2"):
            if not e1:
                rep["verdict"] = "not evaluable (E1)"
            elif not e2:
                rep["verdict"] = (
                    "discrimination not evaluable (E2); conditional detection descriptive"
                )
            else:
                rep.update(verdict(rep))
        out["rules"][r] = rep
    out["controls"] = {"always_abstain": {"coverage_units": 0.0, "recall_overall": 0.0, "false_accept": 0},
                       "always_accept": "rule M0", "random_selection": "random_selection_p per rule"}  # fmt: skip
    out["hypotheses"] = {"K1_primary_M1": out["rules"]["M1"].get("verdict"),
                         "K3_secondary_M2": out["rules"]["M2"].get("verdict"),
                         "K2_conditional_detection": "descriptive (rules.M1 *_accepted metrics)"}  # fmt: skip
    return out


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
    if a.confirm and not Path("docs/phase8k/FREEZE.md").exists():
        sys.exit("confirmatory run refused: docs/phase8k/FREEZE.md does not exist")
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
    if set(fam) < names:
        sys.exit("every unit needs a family")
    res = {
        "mode": "confirm" if a.confirm else "stand-in (development data; NOT a result)",
        **analyse(a.scores, fam),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, default=float), "utf-8")
    print(
        json.dumps({"evaluability": res["evaluability"], "hypotheses": res["hypotheses"]}, indent=1)
    )


if __name__ == "__main__":
    main()
