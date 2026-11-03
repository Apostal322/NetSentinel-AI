"""Phase 8p Stage 1: missed-attack inventory (EXPLORATORY; consumed development networks; no fit).

For every attacker entity of the Phase 8n/8o evaluation (a source with >= 5 attack windows in a
target domain), this script joins:
- the Phase 8o F0 K = 5 outcome over 6 fits (`reports/phase8o/experiment_d.json`, H3): share of
  fits detected at >= 1 window / >= 20 % / >= 50 %, median recall, margin to T0, and
  ranking vs threshold failures;
- what its evaluation-period flows look like (raw flows, Phase 8i order and development cut):
  - attack labels and their flow counts;
  - share of the source's flows that are labelled attack (a malicious host is not malicious
    in every flow);
  - victims (distinct destinations of its attack flows, and the top victim's share);
  - destination ports and protocols;
  - flows per attack window, bytes and packets per attack flow, median duration, no-reply
    share.

Output: reports/phase8p/missed_inventory.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8p/missed_inventory.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8i"))
import build_windows as BW  # noqa: E402, N812

from netsentinel.resources import peak_rss_mb  # noqa: E402

DERIVED = ROOT / "data" / "derived" / "phase8i"
P1X = ROOT / "data" / "derived" / "phase8j" / "p1x"
ED = ROOT / "reports" / "phase8o" / "experiment_d.json"
OUT = ROOT / "reports" / "phase8p" / "missed_inventory.json"
W_MS = 30_000


def target_domains() -> list[tuple[str, str]]:
    return sorted(tuple(p.parent.relative_to(P1X).parts) for p in P1X.glob("*/*/eval_p1x.parquet"))


def files_of(network: str, domain: str) -> tuple[list[Path], bool]:
    src, dev_cut, per_day = BW.NETWORKS[network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    return ([f for f in files if f.stem == domain] if per_day else files), dev_cut


def scan_eval(network: str, domain: str) -> pl.LazyFrame:
    """Lazy, column-pruned evaluation-period flows of the Phase 8i development part. One 30 s
    window of a flood can hold millions of flows, so the window-complete chunks of `BW.chunks`
    are not used, and only aggregates are ever collected."""
    mid = int(json.loads((DERIVED / network / domain / "meta.json").read_text("utf-8"))["mid_ms"])
    files, dev_cut = files_of(network, domain)
    cuts = BW._cuts(files, dev_cut)
    e = pl.col("flow_end_milliseconds")
    return pl.concat([pl.scan_parquet(f).select(BW.COLS).filter((e >= mid) & (e < cuts[f]))
                      for f in files]).with_columns(
        pl.col("ipv4_src_addr").cast(pl.Utf8).alias("src"),
        pl.col("ipv4_dst_addr").cast(pl.Utf8).alias("dst"), (e // W_MS).alias("win"),
        (pl.col("label") != "benign").alias("att"))  # fmt: skip


def collect(q: pl.LazyFrame) -> pl.DataFrame:
    return q.collect(engine="streaming")


def entity_stats(ev: pl.LazyFrame, entities: list[str]) -> dict[str, dict]:
    """Per attacker entity: label counts, victims, ports and the flow shape of its attack flows."""
    a = ev.filter(pl.col("att") & pl.col("src").is_in(entities))
    tot = collect(ev.filter(pl.col("src").is_in(entities)).group_by("src").agg(
        pl.len().alias("flows"), pl.col("att").sum().alias("attack_flows")))  # fmt: skip
    labels = collect(a.group_by("src", "label").len())
    victims = collect(a.group_by("src", "dst").len())
    ports = collect(a.group_by("src", "dst_port").len())
    wins = collect(a.group_by("src", "win").len())
    shape = collect(a.group_by("src").agg(
        pl.len().alias("n"), (pl.col("protocol") == 6).mean().alias("tcp_share"),
        pl.col("in_bytes").cast(pl.Float64).median().alias("up_bytes_per_flow_median"),
        pl.col("out_bytes").cast(pl.Float64).median().alias("down_bytes_per_flow_median"),
        (pl.col("in_pkts") + pl.col("out_pkts")).cast(pl.Float64).median().alias("pkts_per_flow_median"),
        pl.col("flow_duration_milliseconds").cast(pl.Float64).median().alias("dur_ms_median"),
        (pl.col("out_pkts") == 0).mean().alias("no_reply_share")))  # fmt: skip
    out = {}
    for src in entities:
        sh = shape.filter(pl.col("src") == src)
        if not sh.height:
            out[src] = {"attack_flows": 0}
            continue
        r = sh.row(0, named=True)
        t = tot.filter(pl.col("src") == src).row(0, named=True)
        v = victims.filter(pl.col("src") == src).sort("len", descending=True)
        pw = wins.filter(pl.col("src") == src)["len"].to_numpy()
        out[src] = {
            "labels": dict(labels.filter(pl.col("src") == src).select("label", "len").iter_rows()),
            "attack_flows": int(r["n"]),
            "attack_share_of_source_flows": round(t["attack_flows"] / t["flows"], 4),
            "victims": v.height, "top_victim": v["dst"][0],
            "top_victim_share": round(v["len"][0] / r["n"], 4),
            "top_ports": dict(ports.filter(pl.col("src") == src).sort("len", descending=True)
                              .head(5).select("dst_port", "len").iter_rows()),
            "attack_windows_flow_level": int(pw.size),
            "flows_per_attack_window_median": float(np.median(pw)),
            **{k: round(float(r[k]), 4) for k in ("tcp_share", "up_bytes_per_flow_median",
               "down_bytes_per_flow_median", "pkts_per_flow_median", "dur_ms_median", "no_reply_share")},
        }  # fmt: skip
    return out


def main() -> None:
    t0 = time.perf_counter()
    h3 = json.loads(ED.read_text("utf-8"))["H3"]
    k5, single = h3["entities_K5"], h3["entities_single"]
    res: dict = {"status": "EXPLORATORY (Stage 1; consumed development networks; no model fitted)",
                 "entities": {}, "domains": {}}  # fmt: skip
    for network, domain in target_domains():
        name = f"{network}/{domain}"
        ev = scan_eval(network, domain)
        dl = collect(ev.filter(pl.col("att")).group_by("label").agg(
            pl.len().alias("flows"), pl.col("src").n_unique().alias("sources")))  # fmt: skip
        res["domains"][name] = {r["label"]: {"flows": r["flows"], "sources": r["sources"]}
                                for r in dl.iter_rows(named=True)}  # fmt: skip
        ents = [ek.split("|")[1] for ek in k5 if ek.split("|")[0] == name]
        stats = entity_stats(ev, ents)
        for src in ents:
            ek = f"{name}|{src}"
            res["entities"][ek] = {"K5": k5[ek],
                                   "single": {k: single[ek][k] for k in ("det_ge20", "recall_min", "margin_median")},
                                   **stats[src]}  # fmt: skip
        print(name, res["domains"][name], flush=True)
    res["seconds"], res["peak_rss_mb"] = round(time.perf_counter() - t0, 1), peak_rss_mb()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    main()
