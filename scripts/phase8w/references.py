"""Phase 8w reference tables and the disclosed no-fit diagnostic
(docs/phase8w/REFERENCE_ESTIMATION.md, IDENTIFIABILITY.md). Fits no model.

For every evaluated domain it fits three network references on windows that end before the
threshold hold-out and before the evaluation period:
- `T`  label-benign calibration windows (`d["cal"]`; what Phase 8h used; needs labels);
- `Z1` every unlabelled calibration window before the hold-out cut (deployable);
- `Z2` a simulated review: `REVIEW_BUDGET` of those windows drawn uniformly, kept if a perfect
  simulated reviewer (the window label) calls them benign. Not real analyst evidence;
- `Z3` the same windows without those that contain a labelled attack flow (oracle diagnostic);
- `Z3h` the same windows without every host that attacks during calibration (oracle sensitivity:
  it also removes those hosts' benign windows, which changes the benign reference itself).

It records the population, the interval, the contamination that the labels reveal, the floored
scales and how far the deployable reference sits from the oracle one.

**Exploratory, uses evaluation labels of consumed networks (disclosed in PREREGISTRATION):** the
univariate AUC of each feature on the audited evaluation windows as a raw value (identical to the
signed deviation inside a domain, a monotone map) and as an unsigned deviation |z| under each
reference, and the number of features whose direction conflicts between networks (the Phase 8v
rule). `abs_host_Z1` uses own-host references (≥ 30 unlabelled reference windows; network
fallback): the no-fit view of the context candidate, which is not fitted in this phase.

Output: reports/phase8w/references.json.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import zlib
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


RL = _load("phase8w_rl", "scripts/phase8w/relative.py")
X = _load("phase8u_x", "scripts/phase8u/experiment.py")
SEL = _load("phase8v_sel", "scripts/phase8v/selection.py")
OF = _load("phase8t_of", "scripts/phase8t/oracle_feasibility.py")
S, LA = X.S, X.LA
CD = OF.FG.CD
REP = ROOT / "reports" / "phase8w"
NETS = ("nfcic", "nfunsw", "nfton", "nfbot")
FEATS = list(S.FEATS)
REVIEW_BUDGET = 800  # windows a simulated analyst reviews per target domain (Z2)
KINDS = ("raw", "abs_T", "abs_Z1", "abs_Z2", "abs_Z3", "abs_Z3h", "abs_host_Z1")


def calibration_parts(d: dict, name: str) -> dict:
    """The unlabelled calibration windows split at the hold-out cut, with the attacker-host flag
    (labels; used only for the oracle reference and the contamination diagnostic)."""
    cu, eu = LA.unlabelled(d)
    hold = (cu["win"] >= S.split_cut(cu)).to_numpy()
    att = np.isin(cu["key"].to_numpy().astype(str), np.array(sorted(CD.calibration_attackers(name)), dtype=str))  # fmt: skip
    truth = pl.read_parquet(X.C.DERIVED / d["network"] / d["name"] / "cal_truth.parquet")
    y = cu.select("key", "win").join(truth, on=["key", "win"], how="left")["y"].fill_null(False)
    return {"cu": cu, "eu": eu, "hold": hold, "att_host": att, "att_win": y.to_numpy()}


def interval(f: pl.DataFrame) -> tuple[int, int] | None:
    if f.height == 0:
        return None
    return int(f["window_start_ms"].min()), int(f["window_end_ms"].max())


def reviewed(p: dict, name: str, budget: int = REVIEW_BUDGET, draw: int = 0) -> np.ndarray:
    """Mask of the pre-hold-out windows a simulated analyst reviews: a uniform draw without
    replacement, seeded by the domain name (label-free selection)."""
    idx = np.flatnonzero(~p["hold"])
    rng = np.random.default_rng([zlib.crc32(name.encode()), draw])
    m = np.zeros(p["hold"].size, bool)
    m[rng.choice(idx, size=min(budget, idx.size), replace=False)] = True
    return m


def target_references(d: dict, name: str, p: dict | None = None) -> dict:
    p = p or calibration_parts(d, name)
    fit = p["cu"].filter(pl.Series(~p["hold"]))
    clean = p["cu"].filter(pl.Series(~p["hold"] & ~p["att_win"]))
    clean_h = p["cu"].filter(pl.Series(~p["hold"] & ~p["att_host"]))
    vetted = p["cu"].filter(pl.Series(reviewed(p, name) & ~p["att_win"]))
    return {
        "T": RL.fit_reference(S._x(d["cal"]), FEATS, "label_benign_training", interval(d["cal"])),
        "Z1": RL.fit_reference(S._x(fit), FEATS, "unlabelled_history", interval(fit)),
        "Z2": RL.fit_reference(S._x(vetted), FEATS, "vetted_benign_simulated", interval(vetted)),
        "Z3": RL.fit_reference(S._x(clean), FEATS, "oracle_benign", interval(clean)),
        "Z3h": RL.fit_reference(S._x(clean_h), FEATS, "oracle_benign", interval(clean_h)),
    }


def aligned(ev: dict, eu: pl.DataFrame, name: str) -> None:
    """The audited evaluation population and the scored windows must be the same rows."""
    if not (
        np.array_equal(ev["key"].astype(str), eu["key"].to_numpy().astype(str))
        and np.array_equal(np.asarray(ev["win"]), eu["win"].to_numpy())
    ):
        raise RuntimeError(f"{name}: audited windows and scored windows are not aligned")


def conflicts(table: dict[str, dict[str, float]], margin: float = 0.1) -> list[str]:
    """Features with two networks on opposite sides of AUC 0.5 by at least `margin`."""
    out = []
    for f in FEATS:
        a = [table[n][f] for n in table if np.isfinite(table[n][f])]
        if a and max(a) >= 0.5 + margin and min(a) <= 0.5 - margin:
            out.append(f)
    return out


def main() -> None:
    _, groups = X.load_groups()
    doms = {name: d for items in groups.values() for name, d, _ in items}
    res, auc = {}, {k: {} for k in KINDS}
    for name in sorted(doms):
        d = doms[name]
        p = calibration_parts(d, name)
        refs = target_references(d, name, p)
        fitm = ~p["hold"]
        ev = OF.load(name)
        aligned(ev, p["eu"], name)
        xe = S._x(p["eu"])
        pos, neg = ev["pos"], ev["neg"]
        row = {"network": d["network"],
               "calibration_windows": int(p["cu"].height), "reference_windows": int(fitm.sum()),
               "holdout_windows": int(p["hold"].sum()),
               "attacker_host_share_reference": float(p["att_host"][fitm].mean()),
               "attack_window_share_reference": float(p["att_win"][fitm].mean()),
               "attacker_host_share_holdout": float(p["att_host"][p["hold"]].mean()),
               "references": {k: r.to_json() for k, r in refs.items()}}  # fmt: skip
        if refs["Z1"].status == "ok" and refs["Z3"].status == "ok":
            sh = (refs["Z1"].location - refs["Z3"].location) / refs["Z3"].scale
            row["max_abs_location_shift"] = float(np.abs(sh).max())
            row["z1_minus_z3_location_in_z3_scales"] = dict(
                zip(FEATS, sh.round(3).tolist(), strict=True)
            )
            row["z1_over_z3_scale"] = dict(zip(FEATS, (refs["Z1"].scale / refs["Z3"].scale).round(3).tolist(), strict=True))  # fmt: skip
        res[name] = row
        auc["raw"][name] = {f: SEL.auc(xe[pos, j], xe[neg, j]) for j, f in enumerate(FEATS)}
        for k in ("T", "Z1", "Z2", "Z3", "Z3h"):
            if refs[k].status != "ok":
                continue
            a = np.abs(RL.zscore(xe, refs[k]))
            auc[f"abs_{k}"][name] = {f: SEL.auc(a[pos, j], a[neg, j]) for j, f in enumerate(FEATS)}
        fit = p["cu"].filter(pl.Series(fitm))
        hk, ek = fit["key"].to_numpy().astype(str), p["eu"]["key"].to_numpy().astype(str)
        href = RL.host_reference(S._x(fit), hk, FEATS, "unlabelled_history")
        a = np.abs(RL.zscore_host(xe, ek, href))
        auc["abs_host_Z1"][name] = {f: SEL.auc(a[pos, j], a[neg, j]) for j, f in enumerate(FEATS)}
        att_hosts = np.unique(ek[pos])
        row["host_context"] = {
            "hosts_with_own_reference": int(href.hosts.size),
            "evaluation_window_coverage": href.coverage(ek),
            "attack_window_coverage": href.coverage(ek[pos]),
            "benign_window_coverage": href.coverage(ek[neg]),
            "attacker_hosts": int(att_hosts.size),
            "attacker_hosts_with_own_reference": int(np.isin(att_hosts, href.hosts).sum()),
        }
        print(name, row["reference_windows"], round(row["attacker_host_share_reference"], 3),
              {k: r.status for k, r in refs.items()}, flush=True)  # fmt: skip

    def by_network(t: dict) -> dict:
        return {n: {f: float(np.mean([v[f] for k, v in t.items() if k.startswith(n + "/")]))
                    for f in FEATS} for n in NETS if any(k.startswith(n + "/") for k in t)}  # fmt: skip

    diag = {}
    for k, t in auc.items():
        net = by_network(t)
        diag[k] = {"per_network_auc": net, "conflicting_features": conflicts(net),
                   "n_conflicts": len(conflicts(net)),
                   "features_above_0.6_in_all_networks": [f for f in FEATS if min(net[n][f] for n in net) >= 0.6]}  # fmt: skip
        print(k, diag[k]["n_conflicts"], diag[k]["features_above_0.6_in_all_networks"], flush=True)
    out = {"status": "Phase 8w references and exploratory no-fit diagnostic (evaluation labels of "
                     "consumed development networks are used for the AUC tables only)",
           "schema": RL.SCHEMA_VERSION, "features": FEATS, "domains": res, "univariate": diag,
           "per_domain_auc": auc}  # fmt: skip
    body = json.dumps(out, indent=1, default=float).encode()
    REP.mkdir(parents=True, exist_ok=True)
    tmp = REP / "references.partial"
    tmp.write_bytes(body)
    os.replace(tmp, REP / "references.json")
    (REP / "references.sha256").write_text(hashlib.sha256(body).hexdigest())


if __name__ == "__main__":
    main()
