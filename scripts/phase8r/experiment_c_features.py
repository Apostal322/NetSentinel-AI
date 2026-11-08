"""Phase 8r Experiment C, feature level: destination-memory policies under contamination
(docs/phase8r/PREREGISTRATION.md section 6). No model is scored here: scoring a new memory needs
refits of the frozen M2 construction (Phase 8o saved no boosters), which are gated on these
feature-level results and on authorization.

**Memories** (all frozen at the midpoint, built from calibration flows ending before it):
- M0 `P1x` (oracle): destinations contacted by at least one non-attacker source;
- M1 `U` (unlabelled, forward-only): every contacted destination;
- M2a `purge_vetted`: U minus the destinations contacted ONLY by hosts the vetting found
  malicious (trusted evidence used as a purge; equals P1x when every attacker is vetted);
- M2b `trusted_only`: destinations contacted by at least one vetted-benign host (allowlist);
- M3 `quarantine`: a destination is provisional until it has been contacted by ≥ 2 distinct
  sources in ≥ 2 distinct 1-h blocks; then it is promoted;
- M4 `no_novelty`: the feature is removed (refit-only arm; nothing to measure here).

M2 vetting reproduces Experiment A's ORACLE-SIMULATED selections for fit `base_r6`: the modest
budget (10 hosts), `random` draws 0-4 and `admin_persistent`.

**Reported per domain and memory:**
- memory size, and its growth at 25/50/75/100 % of the calibration span;
- attack-only destinations accepted (contacted in calibration only by calibration attackers);
- legitimate destinations rejected (contacted by ≥ 1 non-attacker source, not in memory);
- M3 promotion delay (hours from first contact to promotion) for legitimate and attack-only
  destinations;
- evaluation novelty: the share of documented-attack (V2) and benign windows with
  `new_dst_frac` > 0, and the mean novelty of documented-attack windows;
- build runtime.

**Gate for the scored part** (registered; `scored_gate`): a memory variant (memory x vetting
policy, draws pooled by their median) is scored only if, on 02-22 or 03-02, it restores ≥ 50 % of
the documented-attack novelty-share gap between U and P1x, while raising the benign novelty share
by ≤ 5 percentage points over U.

Output: reports/phase8r/experiment_c_features.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8r/experiment_c_features.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
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


AB = _load("phase8r_ab", "scripts/phase8r/experiment_ab.py")
TM, BM, LA = AB.TM, AB.BM, AB.BM.LA
I8 = ROOT / "data" / "derived" / "phase8i"
CONTACTS = ROOT / "data" / "derived" / "phase8m" / "novelty"
OUT = ROOT / "reports" / "phase8r" / "experiment_c_features.json"
HOUR_MS = 3_600_000
V2 = LA.VIEWS["V2_documented_attackers"]


def calibration_contacts(net: str, dom: str, mid: int) -> pl.DataFrame:
    """Per (dst, src): first contact time, and the set of 1-h blocks (as first time per block)."""
    src, dev_cut, per_day = LA.BW.NETWORKS[net]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    files = [f for f in files if f.stem == dom] if per_day else files
    e = pl.col("flow_end_milliseconds")
    return pl.concat([pl.scan_parquet(f).select("ipv4_src_addr", "ipv4_dst_addr", "flow_end_milliseconds").filter(e < mid)
                      for f in files]).select(pl.col("ipv4_src_addr").cast(pl.Utf8).alias("src"),
                                              pl.col("ipv4_dst_addr").cast(pl.Utf8).alias("dst"),
                                              (e // HOUR_MS).alias("hour"), e.alias("t")).group_by(
        "dst", "src", "hour").agg(pl.col("t").min()).collect(engine="streaming")  # fmt: skip


def promotion(c: pl.DataFrame) -> pl.DataFrame:
    """Per dst: first contact, M3 promotion time (2nd distinct source AND 2nd distinct hour)."""
    by_src = c.group_by("dst", "src").agg(pl.col("t").min()).group_by("dst").agg(
        pl.col("t").sort().get(1, null_on_oob=True).alias("t_src2"), pl.col("t").min().alias("t_first"))  # fmt: skip
    by_hr = c.group_by("dst", "hour").agg(pl.col("t").min()).group_by("dst").agg(
        pl.col("t").sort().get(1, null_on_oob=True).alias("t_hr2"))  # fmt: skip
    # Amendment R-1 (after review): `max_horizontal` ignores nulls, which made the rule "OR".
    # Promotion needs BOTH conditions; a missing one leaves the destination unpromoted (null).
    both = pl.col("t_src2").is_not_null() & pl.col("t_hr2").is_not_null()
    return by_src.join(by_hr, on="dst").with_columns(
        pl.when(both).then(pl.max_horizontal("t_src2", "t_hr2")).otherwise(None).alias("t_promo")
    )


def novelty(name: str, mem: set[str], ev: pl.DataFrame, audit: pl.DataFrame) -> dict:
    nov = ev.with_columns((~pl.col("dst").is_in(sorted(mem))).alias("new")).group_by("key", "win").agg(
        pl.col("new").mean().alias("nov"))  # fmt: skip
    j = audit.join(nov, on=["key", "win"], how="left")
    cat = j["category"].to_numpy().astype(str)
    nv = j["nov"].fill_null(0.0).to_numpy()
    pos, ben = np.isin(cat, V2), np.isin(cat, BM.BENIGN)
    return {"doc_attack_novel_share": float((nv[pos] > 0).mean()) if pos.any() else None,
            "benign_novel_share": float((nv[ben] > 0).mean()) if ben.any() else None,
            "doc_attack_mean_novelty": float(nv[pos].mean()) if pos.any() else None}  # fmt: skip


def scored_gate(gates: dict[str, dict]) -> dict:
    """A variant (memory x vetting policy, draws pooled) passes on a day when the MEDIAN over its
    draws restores >= 50 % of the novelty gap with a benign increase <= 5 points; it is scored
    if it passes on 02-22 or 03-02."""
    import re

    out: dict = {}
    for day, g in gates.items():
        by: dict = {}
        for k, v in g.items():
            by.setdefault(re.sub(r"_d\d+$", "", k), []).append(v)
        for var, vs in by.items():
            r = [v["restored_share"] for v in vs if v["restored_share"] is not None]
            inc = float(np.median([v["benign_novelty_increase"] for v in vs]))
            ok = bool(r and np.median(r) >= 0.5 and inc <= 0.05)
            out.setdefault(var, {})[day] = {"median_restored": float(np.median(r)) if r else None,
                                            "median_benign_increase": inc, "passes": ok}  # fmt: skip
    for var in out:
        out[var]["scored"] = any(v["passes"] for k, v in out[var].items() if k != "scored")
    return out


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--domains")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    names = sorted(p.stem.replace("__", "/") for p in BM.AUDIT.glob("*.parquet"))
    if args.domains:
        names = [n for n in names if n in args.domains.split(",")]
    res: dict = {"status": "Experiment C feature level (no model scored; ORACLE-SIMULATED vetting for M2)",
                 "domains": {}}  # fmt: skip
    for name in names:
        t_dom = time.perf_counter()
        net, dom = name.split("/")
        meta = json.loads((I8 / net / dom / "meta.json").read_text("utf-8"))
        mid = int(meta["mid_ms"])
        d = AB.load(name)
        attackers = set(d["meta"]["uniq"][d["mal_host"]].tolist()) | AB.CD.calibration_attackers(
            name
        )
        c = calibration_contacts(net, dom, mid)
        t0 = time.perf_counter()
        pr = promotion(c)
        dst_src = c.select("dst", "src").unique()
        att_list = sorted(attackers)
        per_dst = dst_src.group_by("dst").agg((~pl.col("src").is_in(att_list)).any().alias("legit"))
        legit = set(per_dst.filter(pl.col("legit"))["dst"].to_list())
        attack_only = set(per_dst.filter(~pl.col("legit"))["dst"].to_list())
        mems: dict[str, set[str]] = {"M0_P1x": legit, "M1_U": set(per_dst["dst"].to_list()),
                                     "M3_quarantine": set(pr.filter(pl.col("t_promo") < mid)["dst"].to_list())}  # fmt: skip
        runtime = {"M3_quarantine": time.perf_counter() - t0}
        vet_sets = {}
        for policy, draws in (("random", range(5)), ("admin_persistent", range(1))):
            for dr in draws:
                rng = AB.seed(name, "base_r6", "modest", policy, "e0", dr)
                chosen = TM.select(policy, d["meta"], AB.BUDGETS["modest"], rng)
                acc, found = TM.vet(chosen, d["mal_host"], rng)
                vet_sets[f"{policy}_d{dr}"] = (
                    set(d["meta"]["uniq"][acc].tolist()),
                    set(d["meta"]["uniq"][found].tolist()),
                )
        for vid, (acc, found) in vet_sets.items():
            t1 = time.perf_counter()
            only_found = dst_src.group_by("dst").agg(
                (~pl.col("src").is_in(sorted(found))).any().alias("keep")
            )
            mems[f"M2a_purge_vetted|{vid}"] = set(
                only_found.filter(pl.col("keep"))["dst"].to_list()
            )
            mems[f"M2b_trusted_only|{vid}"] = set(
                dst_src.filter(pl.col("src").is_in(sorted(acc)))["dst"].unique().to_list()
            )
            runtime[f"M2|{vid}"] = time.perf_counter() - t1
        mid_win = mid // 30_000
        ev = pl.scan_parquet(str(CONTACTS / net / dom / "contacts_p1x" / "*.parquet")).filter(
            pl.col("win") >= mid_win).select(pl.col("src").alias("key"), "win", "dst").unique().collect()  # fmt: skip
        audit = pl.read_parquet(BM.AUDIT / f"{name.replace('/', '__')}.parquet").select(
            "key", "win", "category"
        )
        t_lo = int(c["t"].min())
        out = {"vetting": {k: {"accepted": len(a), "malicious_found": len(f)} for k, (a, f) in vet_sets.items()},
               "legit_destinations": len(legit), "attack_only_destinations": len(attack_only), "memories": {}}  # fmt: skip
        first = pr.select("dst", "t_first", "t_promo")
        for mname, m in mems.items():
            row = {"size": len(m), "attack_only_accepted": len(m & attack_only),
                   "legit_rejected": len(legit - m), **novelty(name, m, ev, audit)}  # fmt: skip
            if mname == "M3_quarantine":
                pdel = first.filter(pl.col("t_promo") < mid).with_columns(
                    ((pl.col("t_promo") - pl.col("t_first")) / HOUR_MS).alias("delay_h"))  # fmt: skip
                for grp, sset in (("legit", legit), ("attack_only", attack_only)):
                    dl = pdel.filter(pl.col("dst").is_in(sorted(sset)))["delay_h"].to_numpy()
                    row[f"promotion_delay_h_{grp}"] = ([float(np.median(dl)), float(np.quantile(dl, 0.9))]
                                                       if dl.size else None)  # fmt: skip
                growth_t = first.filter(pl.col("t_promo") < mid)["t_promo"].to_numpy()
            else:
                growth_t = first.filter(pl.col("dst").is_in(sorted(m)))["t_first"].to_numpy()
            row["growth"] = {
                f"{q:.2f}": int((growth_t <= t_lo + q * (mid - t_lo)).sum())
                for q in (0.25, 0.5, 0.75, 1.0)
            }
            out["memories"][mname] = row
        out["runtime_s"] = runtime
        u, p = out["memories"]["M1_U"], out["memories"]["M0_P1x"]
        gate = {}
        for mname, row in out["memories"].items():
            if mname in ("M0_P1x", "M1_U") or p["doc_attack_novel_share"] is None:
                continue
            gap = p["doc_attack_novel_share"] - u["doc_attack_novel_share"]
            restored = (
                (row["doc_attack_novel_share"] - u["doc_attack_novel_share"]) / gap
                if gap > 1e-9
                else None
            )
            gate[mname] = {"restored_share": restored,
                           "benign_novelty_increase": row["benign_novel_share"] - u["benign_novel_share"],
                           "passes": bool(restored is not None and restored >= 0.5 and
                                          row["benign_novel_share"] - u["benign_novel_share"] <= 0.05)}  # fmt: skip
        out["gate"] = gate
        out["domain_seconds"] = time.perf_counter() - t_dom
        res["domains"][name] = out
        print(name, round(out["domain_seconds"], 1), "s", flush=True)
        del c, pr, dst_src, ev
    gate_days = [n for n in ("nfcic/2018-02-22", "nfcic/2018-03-02") if n in res["domains"]]
    res["scored_part_gate"] = scored_gate({n: res["domains"][n]["gate"] for n in gate_days})
    out_p = Path(args.out)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_bytes(json.dumps(res, indent=1).encode())
    print("gate computed", flush=True)


if __name__ == "__main__":
    main()
