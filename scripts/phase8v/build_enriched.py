"""Phase 8v Stage 1 and Stage 5: telemetry field audit and the enriched window build.

Both read the interim NetFlow v3 parquet files through the Phase 8i chunk reader, so the same
development cut applies (NF-CIC and NF-UNSW: the first 78 % of each file's span; the rest stays
withheld) and every chunk holds complete 30 s windows.

- `audit`: per network, one 100k-flow batch from each of 6 evenly spaced row groups lying wholly
  inside the development part, with all 78 columns → per-field
  statistics and the semantic checks of docs/phase8v/TELEMETRY_AUDIT.md.
  Output: reports/phase8v/telemetry_audit.json
- `build`: per domain, `flow_features.window_features` per chunk (written per slice), then the
  causal context features over the domain's whole window table.
  Output: data/derived/phase8v/enriched/<network>/<domain>.parquet, reports/phase8v/build_enriched.json
  Consistency: n_flows must equal the Phase 8i unlabelled windows on every (key, win).

Usage: python scripts/run_capped.py -- <python> scripts/phase8v/build_enriched.py audit|build [--networks a,b]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
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


BW = _load("bw_8v", "scripts/phase8i/build_windows.py")  # private instance: COLS is set below
FF = _load("phase8v_ff", "scripts/phase8v/flow_features.py")
REP = ROOT / "reports" / "phase8v"
OUT = ROOT / "data" / "derived" / "phase8v" / "enriched"
I8 = ROOT / "data" / "derived" / "phase8i"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")


def domains(net: str) -> tuple[list[tuple[str, list[Path]]], bool]:
    src, dev_cut, per_day = BW.NETWORKS[net]
    files = sorted((ROOT / src).glob("[0-9]*.parquet"))
    return ([(f.stem, [f]) for f in files] if per_day else [("all", files)]), dev_cut


# ----------------------------------------------------------------------------- audit
def audit_network(net: str) -> dict:
    doms, dev_cut = domains(net)
    files = [f for _, fs in doms for f in fs]
    cuts = BW._cuts(files, dev_cut)
    # only row groups lying wholly inside the development part; one 100k-row batch from each of
    # 6 evenly spaced groups (reading a whole row group with all 78 columns exceeds the cap)
    inside = [(pf, g) for pf, g, mn, mx, cut in BW._row_groups(files, cuts) if mx < cut]
    pick = sorted({int(i) for i in np.linspace(0, len(inside) - 1, 6)})
    parts = []
    for i in pick:
        pf, g = inside[i]
        parts.append(pl.from_arrow(next(pf.iter_batches(batch_size=100_000, row_groups=[g]))))
    df = pl.concat(parts)
    del parts
    n = df.height
    fields = {}
    for c, t in df.schema.items():
        s = df[c]
        row = {"dtype": str(t), "null_frac": s.null_count() / n}
        if t.is_numeric():
            v = s.drop_nulls().cast(pl.Float64)
            row.update({"nan_frac": float(v.is_nan().mean() or 0), "zero_frac": float((v == 0).mean() or 0),
                        "min": v.min(), "q50": v.median(), "q99": v.quantile(0.99), "max": v.max()})  # fmt: skip
        elif t == pl.String:
            row["n_unique_in_sample"] = int(s.n_unique())
        fields[c] = row
    st, en = pl.col("flow_start_milliseconds"), pl.col("flow_end_milliseconds")
    dur = pl.col("flow_duration_milliseconds")
    tcp = pl.col("protocol") == 6
    cli, srv = pl.col("client_tcp_flags"), pl.col("server_tcp_flags")
    binned = sum(pl.col(b).fill_null(0) for b in FF.BINS)
    checks = df.select(
        (st % 1000 != 0).mean().alias("start_has_ms_precision"),
        (en % 1000 != 0).mean().alias("end_has_ms_precision"),
        ((en - st) == dur).mean().alias("end_minus_start_equals_duration"),
        ((en - st - dur).abs() <= 1).mean().alias("end_minus_start_within_1ms"),
        (dur > 30_000).mean().alias("duration_over_30s"),
        (dur > 120_000).mean().alias("duration_over_120s"),
        dur.max().alias("max_duration_ms"),
        (tcp).mean().alias("tcp_share"),
        (pl.col("protocol") == 17).mean().alias("udp_share"),
        ((cli & 2) > 0).filter(tcp).mean().alias("tcp_client_syn"),
        ((srv & 18) == 18).filter(tcp & (pl.col("out_pkts") > 0)).mean().alias("tcp_server_synack_when_replied"),
        ((srv & 2) > 0).filter(tcp & ((cli & 2) == 0)).mean().alias("tcp_server_syn_without_client_syn"),
        (pl.col("l4_src_port") > pl.col("l4_dst_port")).filter(tcp).mean().alias("tcp_src_port_gt_dst_port"),
        (pl.col("out_pkts") == 0).mean().alias("no_reverse_packets"),
        (binned == (pl.col("in_pkts") + pl.col("out_pkts"))).mean().alias("size_bins_equal_total_pkts"),
        (binned > 0).mean().alias("size_bins_populated"),
        (pl.col("src_to_dst_iat_avg") > 0).filter(pl.col("in_pkts") >= 2).mean().alias("fwd_iat_positive_when_2plus_pkts"),
        (pl.col("src_to_dst_iat_avg") > 0).filter(pl.col("in_pkts") < 2).mean().alias("fwd_iat_positive_when_1_pkt"),
        ((pl.col("retransmitted_in_pkts") + pl.col("retransmitted_out_pkts")) > 0).mean().alias("any_retransmission"),
        (pl.col("dns_query_id") > 0).mean().alias("dns_fields_populated"),
        (pl.col("l7_proto") > 0).mean().alias("l7_proto_populated"),
        (pl.col("label") != "benign").mean().alias("attack_flow_share_in_sample"),
    ).row(0, named=True)  # fmt: skip
    return {"flows_sampled": n, "slices": len(pick), "dev_cut": dev_cut, "files": [f.name for f in files],
            "columns": len(fields), "fields": fields, "checks": {k: (None if v is None else float(v)) for k, v in checks.items()}}  # fmt: skip


# ----------------------------------------------------------------------------- build
def build_domain(net: str, dom: str, files: list[Path], dev_cut: bool) -> dict:
    t0 = time.perf_counter()
    BW.COLS = [*FF.RAW_COLUMNS, "label"]
    tmp = OUT / net / f"_{dom}_slices"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    flows = 0
    for i, df in enumerate(BW.chunks(files, dev_cut)):
        flows += df.height
        FF.window_features(df).write_parquet(tmp / f"{i:05d}.parquet")
        del df
    w = pl.read_parquet(str(tmp / "*.parquet"))
    if w.select("key", "win").is_duplicated().any():
        raise RuntimeError(f"{net}/{dom}: a window was split across chunks")
    w = w.join(
        FF.context_features(w.select("key", "win", "n_flows_v")), on=["key", "win"], how="left"
    )
    w = w.select("key", "win", "n_flows_v", *FF.ALL).sort("win", "key")
    # consistency with the Phase 8i unlabelled windows
    base = I8 / net / dom
    ref = pl.concat([pl.read_parquet(base / f, columns=["key", "win", "n_flows"]) for f in ("cal_unlabelled.parquet", "eval_unlabelled.parquet")])  # fmt: skip
    j = ref.join(w.select("key", "win", "n_flows_v"), on=["key", "win"], how="left")
    cons = {"reference_windows": ref.height, "built_windows": w.height, "missing_in_build": int(j["n_flows_v"].null_count()),
            "n_flows_mismatch": int((j["n_flows"] != j["n_flows_v"]).fill_null(False).sum())}  # fmt: skip
    out = OUT / net / f"{dom}.parquet"
    part = out.with_suffix(".partial")
    w.write_parquet(part)
    part.replace(out)
    shutil.rmtree(tmp)
    miss = {f: float(w[f].null_count() / w.height) for f in FF.ALL if w[f].null_count()}
    return {"flows": flows, "windows": w.height, "seconds": round(time.perf_counter() - t0, 1), "consistency": cons,
            "missing_share": miss, "sha256": hashlib.sha256(out.read_bytes()).hexdigest()}  # fmt: skip


def main() -> None:
    from netsentinel.resources import peak_rss_mb

    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=("audit", "build"))
    ap.add_argument("--networks", default=",".join(NETWORKS))
    a = ap.parse_args()
    REP.mkdir(parents=True, exist_ok=True)
    nets = a.networks.split(",")
    if a.stage == "audit":
        res = {
            "status": "Stage 1 telemetry audit (sampled slices under the development cut)",
            "networks": {},
        }
        for net in nets:
            res["networks"][net] = audit_network(net)
            print(net, "audit", res["networks"][net]["flows_sampled"], flush=True)
        res["peak_rss_mb"] = peak_rss_mb()
        (REP / "telemetry_audit.json").write_bytes(
            json.dumps(res, indent=1, default=float).encode()
        )
        return
    p = REP / "build_enriched.json"
    res = (
        json.loads(p.read_text("utf-8"))
        if p.exists()
        else {"schema": FF.SCHEMA_VERSION, "domains": {}}
    )
    for net in nets:
        doms, dev_cut = domains(net)
        for dom, files in doms:
            if not (I8 / net / dom).exists():
                continue
            r = build_domain(net, dom, files, dev_cut)
            res["domains"][f"{net}/{dom}"] = r
            res["peak_rss_mb"] = peak_rss_mb()
            p.write_bytes(json.dumps(res, indent=1).encode())
            print(
                net, dom, r["flows"], r["windows"], r["seconds"], "s", r["consistency"], flush=True
            )


if __name__ == "__main__":
    main()
