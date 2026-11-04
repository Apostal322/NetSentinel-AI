"""Phase 8q exploratory (PREREGISTRATION section 6): a label-free destination-memory guard,
measured at the feature level only (no model is scored; rescoring needs refits).

**Frozen memories** (from calibration flows, those ending before the midpoint):
- `P1x` (oracle): destinations of calibration flows of non-attacker hosts (Phase 8j);
- `U` (unlabelled): destinations of every calibration flow;
- `F` (guard, label-free): destinations contacted by ≥ 2 distinct calibration sources.

**For every evaluation window:** the share of its distinct destinations NOT in the memory (the
`new_dst_frac` value under that memory). The evaluation contacts are Phase 8m's `contacts_p1x`
for windows from the midpoint on.

**Reported per domain:**
- the share of documented-attack windows (V2) with novelty > 0;
- the share of benign windows with novelty > 0, under each memory.

A useful guard restores the attack novelty that U loses (towards P1x) without making benign
windows much more novel than U.

Output: reports/phase8q/memory_guard_diag.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8q/memory_guard_diag.py
"""

from __future__ import annotations

import importlib.util
import json
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
I8 = ROOT / "data" / "derived" / "phase8i"
CONTACTS = ROOT / "data" / "derived" / "phase8m" / "novelty"
OUT = ROOT / "reports" / "phase8q" / "memory_guard_diag.json"
V2 = LA.VIEWS["V2_documented_attackers"]
BENIGN = ("benign_uninvolved", "benign_involved_host")


def calibration_destinations(net: str, dom: str, attackers: set[str]) -> pl.DataFrame:
    mid = int(json.loads((I8 / net / dom / "meta.json").read_text("utf-8"))["mid_ms"])
    src, dev_cut, per_day = LA.BW.NETWORKS[net]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    files = [f for f in files if f.stem == dom] if per_day else files
    e = pl.col("flow_end_milliseconds")
    cal = pl.concat([pl.scan_parquet(f).select("ipv4_src_addr", "ipv4_dst_addr", "flow_end_milliseconds").filter(e < mid)
                     for f in files]).select(pl.col("ipv4_src_addr").cast(pl.Utf8).alias("src"),
                                             pl.col("ipv4_dst_addr").cast(pl.Utf8).alias("dst"))  # fmt: skip
    return cal.group_by("dst").agg(
        pl.col("src").n_unique().alias("sources"),
        (~pl.col("src").is_in(sorted(attackers))).any().alias("non_attacker"),
    ).collect(engine="streaming")  # fmt: skip


def main() -> None:
    names = sorted(p.stem.replace("__", "/") for p in AUDIT.glob("*.parquet"))
    res: dict = {"status": "EXPLORATORY (feature level; no model scored)", "domains": {}}
    for name in names:
        net, dom = name.split("/")
        a = pl.read_parquet(AUDIT / f"{name.replace('/', '__')}.parquet").select(
            "key", "win", "category"
        )
        ct = I8 / net / dom / "cal_truth.parquet"
        attackers = (
            set(pl.read_parquet(ct).filter(pl.col("y"))["key"].to_list()) if ct.exists() else set()
        )
        mem = calibration_destinations(net, dom, attackers)
        memories = {"P1x": set(mem.filter(pl.col("non_attacker"))["dst"].to_list()),
                    "U": set(mem["dst"].to_list()),
                    "F": set(mem.filter(pl.col("sources") >= 2)["dst"].to_list())}  # fmt: skip
        mid_win = (
            int(json.loads((I8 / net / dom / "meta.json").read_text("utf-8"))["mid_ms"]) // 30_000
        )
        c = pl.scan_parquet(str(CONTACTS / net / dom / "contacts_p1x" / "*.parquet")).filter(
            pl.col("win") >= mid_win).select(pl.col("src").alias("key"), "win", "dst").unique().collect()  # fmt: skip
        out = {"memory_sizes": {k: len(v) for k, v in memories.items()}}
        for mname, m in memories.items():
            nov = c.with_columns((~pl.col("dst").is_in(sorted(m))).alias("new")).group_by("key", "win").agg(
                pl.col("new").mean().alias("nov"))  # fmt: skip
            j = a.join(nov, on=["key", "win"], how="left")
            cat = j["category"].to_numpy().astype(str)
            nv = j["nov"].fill_null(0.0).to_numpy()
            pos, ben = np.isin(cat, V2), np.isin(cat, BENIGN)
            out[mname] = {"doc_attack_novel_share": round(float((nv[pos] > 0).mean()), 4) if pos.any() else None,
                          "benign_novel_share": round(float((nv[ben] > 0).mean()), 4) if ben.any() else None,
                          "doc_attack_mean_novelty": round(float(nv[pos].mean()), 4) if pos.any() else None}  # fmt: skip
        res["domains"][name] = out
        print(name, {k: v for k, v in out.items()}, flush=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    main()
