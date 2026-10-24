"""Phase 8e, Mission 1 (RETROSPECTIVE on the consumed ToN_IoT files 1-4; no choices, no new
claims, frozen X1-X5 unchanged).

Why do the attack-labelled source addresses not match the documented attacker range
192.168.159.30-39? Profiles every attack-labelled flow by role:
* label x type composition;
* for each address: flows as source / destination, attack-labelled share in each direction,
  attack types, ports, conn_state, packets in each direction;
* whether 192.168.159.x appears at all, and in which role;
* candidate explanations, each with a measurable signature:
  - NAT / address translation: attack flows concentrated on a gateway-like address
    (one address in many attack flows with many peers);
  - direction convention: attack-labelled flows whose SOURCE is a victim (responses / reverse
    connections): the documented attacker appears as DESTINATION;
  - time-based labelling: benign-looking flows (e.g. DNS, NTP, link-local) labelled attack
    only because they fall in an attack time interval;
  - per-IP tagging of a different attacker subnet in these files.
Writes reports/phase8e/label_provenance.json. Usage: uv run python scripts/phase8e/label_provenance.py
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import polars as pl

OUT = Path("reports/phase8e/label_provenance.json")
COLS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "conn_state",
        "src_pkts", "dst_pkts", "label", "type"]  # fmt: skip


def load() -> pl.DataFrame:
    files = sorted(glob.glob("data/raw/toniot/Network_dataset_[1-4].csv"))
    return (pl.scan_csv(files, infer_schema_length=10000, encoding="utf8-lossy")
            .select(COLS)
            .with_columns(pl.col("src_ip").cast(pl.Utf8), pl.col("dst_ip").cast(pl.Utf8),
                          pl.col("label").cast(pl.Int8), pl.col("type").cast(pl.Utf8),
                          pl.col("ts").cast(pl.Float64))
            .collect())  # fmt: skip


def addr_class(col: str) -> pl.Expr:
    c = pl.col(col)
    return (pl.when(c.str.starts_with("192.168.159.")).then(pl.lit("192.168.159.x (documented attackers' subnet)"))
            .when(c.str.starts_with("192.168.1.")).then(pl.lit("192.168.1.x"))
            .when(c.str.starts_with("169.254.")).then(pl.lit("169.254.x (link-local)"))
            .when(c.str.starts_with("10.") | c.str.starts_with("172.16.") | c.str.starts_with("192.168."))
            .then(pl.lit("other private")).when(c.str.contains(":")).then(pl.lit("IPv6"))
            .otherwise(pl.lit("public / other")))  # fmt: skip


def main() -> None:
    df = load()
    a = df.filter(pl.col("label") == 1)
    res: dict = {"role": "retrospective label audit of consumed ToN_IoT files 1-4",
                 "rows": df.height, "attack_rows": a.height,
                 "label_by_type": df.group_by("label", "type").len().sort("len", descending=True).to_dicts()}  # fmt: skip
    res["documented_subnet_192_168_159"] = {
        "as_source": df.filter(pl.col("src_ip").str.starts_with("192.168.159.")).height,
        "as_destination": df.filter(pl.col("dst_ip").str.starts_with("192.168.159.")).height}  # fmt: skip
    res["attack_rows_by_address_class"] = {
        "source": a.group_by(addr_class("src_ip").alias("c")).len().sort("len", descending=True).to_dicts(),
        "destination": a.group_by(addr_class("dst_ip").alias("c")).len().sort("len", descending=True).to_dicts()}  # fmt: skip
    res["attack_rows_by_type_and_source_class"] = (
        a.group_by("type", addr_class("src_ip").alias("src_class"), addr_class("dst_ip").alias("dst_class"))
        .len().sort("len", descending=True).head(30).to_dicts())  # fmt: skip
    # per-address roles for every address that ever sources an attack-labelled flow
    srcs = a["src_ip"].unique().to_list()
    roles = []
    for ip in srcs:
        as_src = df.filter(pl.col("src_ip") == ip)
        as_dst = df.filter(pl.col("dst_ip") == ip)
        att_src = as_src.filter(pl.col("label") == 1)
        roles.append({
            "address": ip,
            "flows_as_source": as_src.height, "attack_flows_as_source": att_src.height,
            "attack_share_as_source": att_src.height / as_src.height if as_src.height else None,
            "flows_as_destination": as_dst.height,
            "attack_flows_as_destination": int((as_dst["label"] == 1).sum()),
            "attack_types_as_source": att_src.group_by("type").len().sort("len", descending=True).head(4).rows(),
            "top_dst_ports_in_attack_flows": att_src.group_by("dst_port").len().sort("len", descending=True).head(4).rows(),
            "distinct_attack_destinations": att_src["dst_ip"].n_unique(),
            "conn_states": att_src.group_by("conn_state").len().sort("len", descending=True).head(3).rows(),
            "services": att_src.group_by("service").len().sort("len", descending=True).head(3).rows(),
            "median_dst_pkts": float(att_src["dst_pkts"].median() or 0),
        })  # fmt: skip
    roles.sort(key=lambda r: -r["attack_flows_as_source"])
    res["attack_sources"] = roles
    # do attack labels follow time? share of all flows that are attack-labelled per minute
    m = df.with_columns((pl.col("ts") // 60).alias("minute")).group_by("minute").agg(
        pl.len().alias("n"), pl.col("label").mean().alias("attack_share"))  # fmt: skip
    res["minutes"] = {"total": m.height, "all_attack": int((m["attack_share"] == 1).sum()),
                      "all_benign": int((m["attack_share"] == 0).sum()),
                      "mixed": int(((m["attack_share"] > 0) & (m["attack_share"] < 1)).sum())}  # fmt: skip
    # link-local / infrastructure-like attack-labelled flows: DNS, NTP, mDNS, SSDP, NetBIOS
    infra = a.filter(pl.col("dst_port").is_in([53, 123, 5353, 1900, 137, 138, 67, 68])
                     | pl.col("src_ip").str.starts_with("169.254."))  # fmt: skip
    res["attack_labelled_infrastructure_like_flows"] = {
        "rows": infra.height, "share_of_attack_rows": infra.height / a.height if a.height else None,
        "by_type": infra.group_by("type").len().sort("len", descending=True).to_dicts()}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({k: res[k] for k in ("rows", "attack_rows", "documented_subnet_192_168_159",
                                          "attack_rows_by_address_class", "minutes",
                                          "attack_labelled_infrastructure_like_flows")}, indent=1, default=str))  # fmt: skip
    print("label_by_type", res["label_by_type"])
    for r in roles[:15]:
        print(json.dumps(r, default=str)[:420])


if __name__ == "__main__":
    main()
