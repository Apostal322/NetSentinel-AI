"""Phase 8q Experiment A: versioned ground-truth audit of the evaluation windows (no model fitted;
the raw labels are never modified).

For every Phase 8j P1x evaluation window of the 9 target domains (the row order of the Phase 8j
B0 files), the audit records:
- the raw dataset label: any attack flow in the (source, 30 s) window, Phase 8b;
- counts of its flows and attack flows, and its attack-label set (raw flows, Phase 8i order and
  development cut);
- the role of its source: documented attacker / attacked host's traffic / undocumented source,
  with rules stated in `ROLE_RULES`;
- for NF-CIC, whether the window lies inside the documented interval of an attack that names its
  source, and whether its raw label agrees with that attack's family.

Each window then gets one **evidence category**:

| category | rule |
|---|---|
| `documented_attack` | raw attack; documented attacker; NF-CIC: inside its own documented interval with a consistent family (other datasets publish no per-host intervals) |
| `documented_family_mismatch` | NF-CIC: inside a documented interval of the host, raw family differs from the documented attack |
| `documented_outside_interval` | NF-CIC: documented attacker, raw attack label, outside every documented interval of that host |
| `attacked_host_traffic` | raw attack; the source's attack-labelled flows go mainly to a documented attacker |
| `undocumented_source` | raw attack; no documentation names the source |
| `ambiguous_noisy` | NF-CIC `infiltration` windows (excluded since Phase 8h) |
| `attacker_host_other_window` | raw benign window of a host that carries an attack label in the domain (Phase 8i excludes these from the benign set; the source role is kept in `role`) |
| `benign_uninvolved` | raw benign; the source never carries an attack label in the domain and is not a documented attacker or victim |
| `benign_involved_host` | raw benign; otherwise |

**Verified benign is empty.** No dataset supplies independent benign evidence, so every
negative is dataset-labelled benign. `benign_uninvolved` is the stricter sensitivity population.

**Views (estimands):**
- V0 historical: all raw attack windows vs all raw benign;
- V2 documented attackers (Phase 8p primary): `documented_*`;
- V1 strict: `documented_attack` only;
- separately: attacked-host traffic and undocumented sources.

Output: data/derived/phase8q/label_audit/<domain>.parquet (one row per evaluation window, B0 order)
        reports/phase8q/label_audit.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8q/label_audit.py
"""

from __future__ import annotations

import ipaddress
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

AUDIT_VERSION = "label-audit-1.0.0"
B0 = ROOT / "data" / "derived" / "phase8j" / "dev"
I8 = ROOT / "data" / "derived" / "phase8i"
OUT = ROOT / "data" / "derived" / "phase8q" / "label_audit"
REPORT = ROOT / "reports" / "phase8q" / "label_audit.json"
W_MS = 30_000
UTC_OFFSET_H = 4  # CSE-CIC-IDS2018 local time: Atlantic standard time (UTC-4); DST began 2018-03-11

# Official CSE-CIC-IDS2018 Table 2 (https://www.unb.ca/cic/datasets/ids-2018.html, read 2026-11-03/04):
# (documented attack name, attacking or infected hosts ("valid IP"), local intervals, raw labels of that attack)
LOIC = ["18.218.115.60", "18.219.9.1", "18.219.32.43", "18.218.55.126", "52.14.136.135",
        "18.219.5.43", "18.216.200.189", "18.218.229.235", "18.218.11.51", "18.216.24.42"]  # fmt: skip
BOTS = ["172.31.69.23", "172.31.69.17", "172.31.69.14", "172.31.69.12", "172.31.69.10",
        "172.31.69.8", "172.31.69.6", "172.31.69.26", "172.31.69.29", "172.31.69.30"]  # fmt: skip
CIC_TABLE = {
    "2018-02-14": [("FTP-BruteForce", ["18.221.219.4"], [("10:32", "12:09")], {"ftp_bruteforce"}),
                   ("SSH-Bruteforce", ["13.58.98.64"], [("14:01", "15:31")], {"ssh_bruteforce"})],
    "2018-02-16": [("DoS-SlowHTTPTest", ["13.59.126.31"], [("10:12", "11:08")], {"dos_slowhttptest"}),
                   ("DoS-Hulk", ["18.219.193.20"], [("13:45", "14:19")], {"dos_hulk"})],
    "2018-02-20": [("DDoS-LOIC-HTTP", LOIC, [("10:12", "11:17")], {"ddos_loic_http"}),
                   ("DDoS-LOIC-UDP", LOIC, [("13:13", "13:32")], {"ddos_loic_udp"})],
    "2018-02-21": [("DDoS-LOIC-UDP", LOIC, [("10:09", "10:43")], {"ddos_loic_udp"}),
                   ("DDoS-HOIC", LOIC, [("14:05", "15:05")], {"ddos_hoic"})],
    "2018-02-22": [("Brute Force-Web", ["18.218.115.60"], [("10:17", "11:24")], {"web_bruteforce"}),
                   ("Brute Force-XSS", ["18.218.115.60"], [("13:50", "14:29")], {"web_xss"}),
                   ("SQL Injection", ["18.218.115.60"], [("16:15", "16:29")], {"web_sql_injection"})],
    "2018-03-02": [("Bot", BOTS + ["18.219.211.138"], [("10:11", "11:34"), ("14:24", "15:55")], {"bot"})],
}  # fmt: skip
CIC_VICTIMS = {"2018-02-14": ["172.31.69.25"], "2018-02-16": ["172.31.69.25"], "2018-02-20": ["172.31.69.25"],
               "2018-02-21": ["172.31.69.28"], "2018-02-22": ["172.31.69.28"], "2018-03-02": []}  # fmt: skip
ROLE_RULES = {
    "nfcic": "documented attacker or documented infected host (03-02 Bot victims): named in an official Table 2 row of that day",
    "nfunsw": "documented attacker: 175.45.176.0-3 (UNSW-NB15 attack hosts)",
    "nfton": "documented attacker: 192.168.1.30-39 (ToN-IoT attacker range); attacked host: its attack-labelled flows go mainly to one",
    "nfbot": "data-derived (no published addresses): documented attacker = > 100,000 evaluation attack flows; attacked host: its attack-labelled flows go mainly to one",
}  # fmt: skip
CATEGORIES = ("documented_attack", "documented_family_mismatch", "documented_outside_interval",
              "attacked_host_traffic", "undocumented_source", "ambiguous_noisy",
              "attacker_host_other_window", "benign_uninvolved", "benign_involved_host")  # fmt: skip
VIEWS = {"V0_historical": ("documented_attack", "documented_family_mismatch", "documented_outside_interval",
                           "attacked_host_traffic", "undocumented_source"),
         "V2_documented_attackers": ("documented_attack", "documented_family_mismatch", "documented_outside_interval"),
         "V1_strict": ("documented_attack",),
         "attacked_host_traffic": ("attacked_host_traffic",),
         "undocumented_source": ("undocumented_source",)}  # fmt: skip


def local_minutes(end_ms: np.ndarray) -> np.ndarray:
    return (end_ms // 60_000 - UTC_OFFSET_H * 60) % (24 * 60)


def in_rows(day: str, end_ms: np.ndarray, src: np.ndarray) -> np.ndarray:
    """Per window: index of the first documented row naming `src` whose interval contains the
    window end (local time), or -1."""
    t = local_minutes(end_ms)
    out = np.full(end_ms.size, -1)
    for i, (_, hosts, ivs, _) in enumerate(CIC_TABLE.get(day, [])):
        mine = np.isin(src, np.array(hosts, dtype=str))
        for a, b in ivs:
            ha, ma = map(int, a.split(":"))
            hb, mb = map(int, b.split(":"))
            hit = mine & (t >= ha * 60 + ma) & (t <= hb * 60 + mb) & (out < 0)
            out[hit] = i
    return out


def source_role(
    net: str, day: str, src: str, attack_flows: int, top_dst: str | None, heavy: set[str]
) -> str:
    if net == "nfcic":
        return (
            "documented"
            if any(src in hosts for _, hosts, _, _ in CIC_TABLE.get(day, []))
            else "undocumented"
        )
    if net == "nfunsw":
        return (
            "documented"
            if ipaddress.ip_address(src) in ipaddress.ip_network("175.45.176.0/30")
            else "undocumented"
        )
    if net == "nfton":
        ton = ipaddress.ip_network("192.168.1.0/24")
        if ipaddress.ip_address(src) in ton and 30 <= int(src.split(".")[-1]) <= 39:
            return "documented"
        return (
            "attacked_host"
            if top_dst
            and ipaddress.ip_address(top_dst) in ton
            and 30 <= int(top_dst.split(".")[-1]) <= 39
            else "undocumented"
        )
    if src in heavy:
        return "documented"
    return "attacked_host" if top_dst in heavy else "undocumented"


def scan(network: str, domain: str) -> pl.LazyFrame:
    mid = int(json.loads((I8 / network / domain / "meta.json").read_text("utf-8"))["mid_ms"])
    src, dev_cut, per_day = BW.NETWORKS[network]
    files = sorted(Path(src).glob("[0-9]*.parquet"))
    files = [f for f in files if f.stem == domain] if per_day else files
    cuts = BW._cuts(files, dev_cut)
    e = pl.col("flow_end_milliseconds")
    return pl.concat([pl.scan_parquet(f).select(BW.COLS).filter((e >= mid) & (e < cuts[f])) for f in files]).with_columns(
        pl.col("ipv4_src_addr").cast(pl.Utf8).alias("key"), pl.col("ipv4_dst_addr").cast(pl.Utf8).alias("dst"),
        (e // W_MS).alias("win"), (pl.col("label") != "benign").alias("att"))  # fmt: skip


def audit_domain(name: str) -> tuple[pl.DataFrame, dict]:
    net, dom = name.split("/")
    z = np.load(B0 / f"{net}__{dom}__seed0.npz")
    base = pl.DataFrame({"key": z["ev_key"].astype(str), "win": z["ev_win"], "end_ms": z["ev_end"],
                         "raw_attack": z["ev_y"].astype(bool), "raw_benign": z["ev_benign"].astype(bool),
                         "noisy": z["ev_noisy"].astype(bool)})  # fmt: skip
    ev = scan(net, dom)
    per = ev.group_by("key", "win").agg(
        pl.len().alias("flows"), pl.col("att").sum().alias("attack_flows"),
        pl.col("label").filter(pl.col("att")).unique().sort().str.join("+").alias("attack_labels"),
    ).collect(engine="streaming")  # fmt: skip
    att = ev.filter(pl.col("att"))
    src_att = att.group_by("key").agg(pl.len().alias("n")).collect(engine="streaming")
    top = (att.group_by("key", "dst").len().collect(engine="streaming")
           .sort("len", descending=True).group_by("key").agg(pl.col("dst").first().alias("top_dst")))  # fmt: skip
    src_info = src_att.join(top, on="key", how="left")
    heavy = (
        set(src_info.filter(pl.col("n") > 100_000)["key"].to_list()) if net == "nfbot" else set()
    )
    roles = {
        k: source_role(net, dom, k, n, t, heavy)
        for k, n, t in src_info.select("key", "n", "top_dst").iter_rows()
    }
    v = base.join(per, on=["key", "win"], how="left", maintain_order="left")
    if v.height != base.height or not v["key"].equals(base["key"]):
        raise RuntimeError(f"{name}: audit join changed the rows")
    key = v["key"].to_numpy().astype(str)
    role = np.array([roles.get(k, "none") for k in key], dtype=object)
    raw_att, raw_ben, noisy = (
        v["raw_attack"].to_numpy(),
        v["raw_benign"].to_numpy(),
        v["noisy"].to_numpy(),
    )
    labels = v["attack_labels"].fill_null("").to_numpy().astype(str)
    row = in_rows(dom, v["end_ms"].to_numpy(), key) if net == "nfcic" else np.full(v.height, -2)
    fam_ok = np.ones(v.height, bool)
    if net == "nfcic":
        table = CIC_TABLE.get(dom, [])
        for i, (_, _, _, raw_names) in enumerate(table):
            m = row == i
            fam_ok[m] = [bool(set(s.split("+")) & raw_names) for s in labels[m]]
    involved = set(roles) | set(CIC_VICTIMS.get(dom, []))
    for _, hosts, _, _ in CIC_TABLE.get(dom, []) if net == "nfcic" else []:
        involved |= set(hosts)
    cat = np.full(v.height, "", dtype=object)
    for i in range(v.height):
        if noisy[i]:
            cat[i] = "ambiguous_noisy"
        elif raw_att[i]:
            r = role[i]
            if r == "documented":
                if net != "nfcic":
                    cat[i] = "documented_attack"
                elif row[i] < 0:
                    cat[i] = "documented_outside_interval"
                else:
                    cat[i] = "documented_attack" if fam_ok[i] else "documented_family_mismatch"
            elif r == "attacked_host":
                cat[i] = "attacked_host_traffic"
            else:
                cat[i] = "undocumented_source"
        elif raw_ben[i]:
            cat[i] = "benign_involved_host" if key[i] in involved else "benign_uninvolved"
        else:
            # Phase 8i `benign` excludes every window of a host that attacks in the domain
            cat[i] = "attacker_host_other_window"
    out = v.with_columns(pl.Series("role", role.astype(str)), pl.Series("category", cat.astype(str)),
                         pl.Series("documented_row", row), (pl.col("attack_flows") < pl.col("flows")).alias("mixed"),
                         pl.lit(AUDIT_VERSION).alias("audit_version"))  # fmt: skip
    counts = dict(out.group_by("category").len().iter_rows())
    summary = {"windows": out.height, "categories": {c: int(counts.get(c, 0)) for c in CATEGORIES},
               "attack_windows_mixed": int(out.filter(pl.col("raw_attack") & pl.col("mixed")).height),
               "attack_label_sets": dict(out.filter(pl.col("raw_attack")).group_by("attack_labels").len().iter_rows()),
               "sources_by_role": {r: sorted(k for k, rr in roles.items() if rr == r) if r != "undocumented" or len(roles) < 60
                                   else len([k for k, rr in roles.items() if rr == r])
                                   for r in ("documented", "attacked_host", "undocumented")}}  # fmt: skip
    return out, summary


def main() -> None:
    t0 = time.perf_counter()
    names = sorted(p.name.split("__seed0")[0].replace("__", "/") for p in B0.glob("*__seed0.npz"))
    res: dict = {"audit_version": AUDIT_VERSION, "role_rules": ROLE_RULES, "utc_offset_h": UTC_OFFSET_H,
                 "views": {k: list(v) for k, v in VIEWS.items()},
                 "status": "EXPLORATORY audit (official documentation + raw labels; raw labels unchanged)",
                 "domains": {}}  # fmt: skip
    OUT.mkdir(parents=True, exist_ok=True)
    for name in names:
        view, summary = audit_domain(name)
        tmp = OUT / f"{name.replace('/', '__')}.tmp.parquet"
        view.write_parquet(tmp)
        tmp.replace(OUT / f"{name.replace('/', '__')}.parquet")
        res["domains"][name] = summary
        print(name, summary["categories"], flush=True)
    res["seconds"], res["peak_rss_mb"] = round(time.perf_counter() - t0, 1), peak_rss_mb()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_bytes(json.dumps(res, indent=1, default=str).encode())


if __name__ == "__main__":
    main()
