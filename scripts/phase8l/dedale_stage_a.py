"""Phase 8l DEDALE Stage A gate (docs/phase8l/DEDALE_PREREGISTRATION.md section 7, N1-N6).

Calibration files only: green_internal days D1-D14 (`conn_labeled.csv`, `dhcp.log`), fetched by
dedale_fetch.py --stage A. Counts only: no source model is loaded and no window is scored.

1. N1: the fetch report holds all 28 members with matching CRC32s; the files exist.
2. Per day: parse checks (N2), calibration labels (N3), and the canonical flow frame in the
   Phase 6/8i NetFlow schema (`eval_nf_dev.COLS`) so that the registered streaming
   (`build_windows.chunks`) and the P1x builder run unchanged. Zeek resets map to bit 4 (RST)
   of client/server TCP flags, as `with_flags` reads them; label 0 -> "benign", 1 -> "attack",
   2 -> "attack_related". Flows ending at or after the boundary are dropped and counted.
3. DHCP leases: the MACs and host names behind each address.
4. P1x calibration windows (no exclusions: N3 must find no calibration attack), the hold-out
   cut (`split_cut`) and host eligibility (section 2), then N4-N6.

Output: data/derived/phase8l/dedale/{flows/D??.parquet, cal_p1x.parquet} and
reports/phase8l/dedale_stage_a.json
Usage: uv run python scripts/run_capped.py -- <abs python> scripts/phase8l/dedale_stage_a.py
"""

from __future__ import annotations

import gzip
import importlib.util
import ipaddress
import json
import math
import re
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "dedale" / "green_internal"
DERIVED = ROOT / "data" / "derived" / "phase8l" / "dedale"
FETCH_REPORT = ROOT / "reports" / "phase8l" / "dedale_fetch_stageA.json"
MANIFEST = ROOT / "reports" / "phase8l" / "dedale_manifest.json"
OUT = ROOT / "reports" / "phase8l" / "dedale_stage_a.json"

BOUNDARY = datetime(2025, 1, 6, tzinfo=UTC)
BOUNDARY_MS = int(BOUNDARY.timestamp() * 1000)
DAY0 = datetime(2024, 12, 23, tzinfo=UTC)
TOLERANCE_S = 2 * 3600
CLIENTS = ipaddress.ip_network("172.16.1.0/24")
ROUTER = "172.16.1.1"
COMPROMISED = ("172.16.1.2", "172.16.1.3")  # clients 1 and 2 (official timeline)
ALWAYS_EXCLUDED = {"172.19.0.2", "172.19.1.1", "172.19.2.1", "172.17.0.2", "172.16.0.2", ROUTER}
INFERRED_3_4 = ("172.16.1.4", "172.16.1.5")
MIN_CAL, MIN_HOLD = 100, 20
GAP_WINDOWS = 60  # calibration_audit.GAP_WINDOWS
NEED = ("ts", "ip_src", "ip_dst", "port_dst", "proto", "duration", "orig_ip_bytes",
        "resp_ip_bytes", "orig_pkts", "resp_pkts", "history", "label")  # fmt: skip
NUMERIC = ("ts", "port_dst", "duration", "orig_ip_bytes", "resp_ip_bytes", "orig_pkts",
           "resp_pkts", "label")  # fmt: skip


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def split_cut(win: np.ndarray) -> int:
    """`scripts/phase8b/scorers.split_cut`: the last 30% of the calibration window range."""
    lo, hi = int(win.min()), int(win.max())
    return lo + int(math.floor((hi - lo + 1) * 0.7))


def sessions(df: pl.DataFrame) -> np.ndarray:
    """`scripts/phase8i/calibration_audit.sessions`, inlined: importing that module binds
    `common` to the Phase 6 module (as in probe_f0.py). Rows of one host split at gaps > 60
    windows (30 min)."""
    s = df.with_row_index("i").sort("key", "win").with_columns(
        ((pl.col("key") != pl.col("key").shift()) | (pl.col("win").diff() > GAP_WINDOWS))
        .fill_null(True).cum_sum().alias("sid"))  # fmt: skip
    return s.sort("i")["sid"].to_numpy()


def kish(counts: np.ndarray) -> float:
    counts = counts.astype(float)
    return float(counts.sum() ** 2 / np.sum(counts**2)) if counts.size else 0.0


def canonical(raw: pl.DataFrame) -> pl.DataFrame:
    """Parsed conn_labeled rows -> the Phase 6/8i NetFlow column set."""
    proto = pl.col("proto").str.to_lowercase()
    start = (pl.col("ts") * 1000).cast(pl.Int64)
    dur = pl.col("duration") * 1000
    hist = pl.col("history").fill_null("")
    return raw.select(
        start.alias("flow_start_milliseconds"),
        (start + dur.cast(pl.Int64)).alias("flow_end_milliseconds"),
        pl.col("ip_src").alias("ipv4_src_addr"),
        pl.col("ip_dst").alias("ipv4_dst_addr"),
        pl.col("port_dst").cast(pl.Int64).alias("dst_port"),
        pl.when(proto == "tcp").then(6).when(proto == "udp").then(17).when(proto == "icmp").then(1)
        .otherwise(0).cast(pl.Int64).alias("protocol"),
        pl.col("orig_ip_bytes").cast(pl.Float64).alias("in_bytes"),
        pl.col("resp_ip_bytes").cast(pl.Float64).alias("out_bytes"),
        pl.col("orig_pkts").cast(pl.Float64).alias("in_pkts"),
        pl.col("resp_pkts").cast(pl.Float64).alias("out_pkts"),
        dur.cast(pl.Float64).alias("flow_duration_milliseconds"),
        pl.when(hist.str.contains("R", literal=True)).then(4).otherwise(0).cast(pl.Int64)
        .alias("client_tcp_flags"),
        pl.when(hist.str.contains("r", literal=True)).then(4).otherwise(0).cast(pl.Int64)
        .alias("server_tcp_flags"),
        pl.when(pl.col("label") == 0).then(pl.lit("benign"))
        .when(pl.col("label") == 1).then(pl.lit("attack"))
        .otherwise(pl.lit("attack_related")).alias("label"),
    ).sort("flow_end_milliseconds")  # fmt: skip


def parse_day(path: Path, day: int) -> tuple[pl.DataFrame, dict]:
    """One conn_labeled member -> (canonical calibration flows, N2/N3 counts)."""
    header = gzip.open(path, "rt", encoding="utf-8").readline().rstrip("\n").split(";")
    missing = [c for c in NEED if c not in header]
    if missing:
        return pl.DataFrame(), {"rows": 0, "missing_columns": missing, "header": header}
    raw = pl.read_csv(path, separator=";", columns=list(NEED), infer_schema_length=0)
    parsed = raw.with_columns(pl.col(c).cast(pl.Float64, strict=False) for c in NUMERIC)
    bad = parsed.select(pl.any_horizontal(pl.col(c).is_null() for c in NUMERIC)
                        | pl.col("ip_src").is_null() | pl.col("ip_dst").is_null())  # fmt: skip
    bad = bad.to_series()
    ok = parsed.filter(~bad)
    lo = (DAY0 + timedelta(days=day - 1)).timestamp()
    end = ok["ts"] + ok["duration"]
    out_of_day = int(((end < lo - TOLERANCE_S) | (end >= lo + 86400 + TOLERANCE_S)).sum())
    labels = ok["label"].value_counts().sort("label")
    flows = canonical(ok)
    after = int((flows["flow_end_milliseconds"] >= BOUNDARY_MS).sum())
    flows = flows.filter(pl.col("flow_end_milliseconds") < BOUNDARY_MS)
    info = {
        "rows": raw.height,
        "header": header,
        "unparseable": int(bad.sum()),
        "ending_outside_utc_day_2h": out_of_day,
        "ts_min_utc": datetime.fromtimestamp(float(ok["ts"].min()), UTC).isoformat(),
        "ts_max_utc": datetime.fromtimestamp(float(ok["ts"].max()), UTC).isoformat(),
        "labels": {str(int(r[0])): int(r[1]) for r in labels.iter_rows()},
        "dropped_ending_after_boundary": after,
        "calibration_flows": flows.height,
    }
    return flows, info


def dhcp_leases(path: Path) -> list[dict]:
    """Zeek dhcp.log rows with an assigned address: ts, mac, assigned_addr, host_name."""
    fields, rows = None, []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#") and fields:
                r = dict(zip(fields, line.split("\t"), strict=False))
                if r.get("assigned_addr", "-") != "-":
                    rows.append({k: r.get(k, "-") for k in ("ts", "mac", "assigned_addr",
                                                             "host_name", "client_fqdn")})  # fmt: skip
    return rows


def client_number(name: str) -> int | None:
    """Internal client number from a DHCP host name ending in its index, if any."""
    g = re.search(r"(?i)client\D*(\d+)\s*$", name or "")
    return int(g[1]) if g else None


def main() -> None:
    t0 = time.perf_counter()
    rep: dict = {"boundary_utc": BOUNDARY.isoformat(), "gate": {}}
    man = json.loads(MANIFEST.read_text("utf-8"))["stages"]["A"]["members"]
    fetched = json.loads(FETCH_REPORT.read_text("utf-8"))["members"]
    n1 = [m["name"] for m in man if fetched.get(m["name"], {}).get("crc32") != m["crc32"]]
    files = {m["name"]: RAW / f"D{m['day']:02d}_{m['date']}_{Path(m['name']).name}.gz" for m in man}
    n1 += [n for n, p in files.items() if not p.exists()]
    rep["gate"]["N1_integrity_failures"] = n1
    if n1:
        raise SystemExit(f"N1: {n1}")

    (DERIVED / "flows").mkdir(parents=True, exist_ok=True)
    days, leases, flow_files = {}, [], []
    for m in man:
        p = files[m["name"]]
        if m["name"].endswith("dhcp.log"):
            leases += [{**r, "day": m["day"]} for r in dhcp_leases(p)]
            continue
        flows, info = parse_day(p, m["day"])
        days[m["day"]] = info
        print(f"D{m['day']:02d}", {k: info[k] for k in ("rows", "unparseable", "labels")},
              flush=True)  # fmt: skip
        if flows.height:
            f = DERIVED / "flows" / f"D{m['day']:02d}.parquet"
            flows.write_parquet(f, row_group_size=100_000, statistics=True)
            flow_files.append(f)
        del flows
    rep["days"] = days
    n2 = {d: i for d, i in days.items() if i.get("missing_columns")
          or i["unparseable"] > 0.01 * i["rows"] or i["ending_outside_utc_day_2h"] > 0.01 * i["rows"]}  # fmt: skip
    n3 = {d: i["labels"] for d, i in days.items() if any(k != "0" for k in i.get("labels", {}))}
    rep["gate"]["N2_failing_days"] = sorted(n2)
    rep["gate"]["N3_days_with_nonzero_labels"] = n3

    # DHCP identity
    lease = pl.DataFrame(leases) if leases else pl.DataFrame(
        schema={"ts": pl.Utf8, "mac": pl.Utf8, "assigned_addr": pl.Utf8, "host_name": pl.Utf8,
                "client_fqdn": pl.Utf8, "day": pl.Int64})  # fmt: skip
    internal = lease.filter(pl.col("assigned_addr").map_elements(
        lambda a: ipaddress.ip_address(a) in CLIENTS, return_dtype=pl.Boolean))  # fmt: skip
    ip_macs = {ip: sorted(set(g["mac"])) for (ip,), g in internal.group_by("assigned_addr")}
    mac_ips = {mac: sorted(set(g["assigned_addr"])) for (mac,), g in internal.group_by("mac")}
    mac_names = {mac: sorted(set(g["host_name"]) - {"-"}) for (mac,), g in internal.group_by("mac")}
    identity = "mac" if ip_macs else "ip"
    comp_macs = {mac for ip in COMPROMISED for mac in ip_macs.get(ip, [])}
    excluded = set(ALWAYS_EXCLUDED) | set(COMPROMISED)
    excluded |= {ip for mac in comp_macs for ip in mac_ips[mac]}
    by_name = {ip: client_number(n) for mac, ips in mac_ips.items() for ip in ips
               for n in mac_names.get(mac, [])}  # fmt: skip
    named_3_4 = sorted(ip for ip, k in by_name.items() if k in (3, 4))
    clients_3_4 = named_3_4 if len(named_3_4) == 2 else list(INFERRED_3_4)
    unstable = sorted(ip for ip, macs in ip_macs.items() if len(macs) > 1)
    rep["identity"] = {
        "mode": identity, "internal_leases": internal.height,
        "addresses_with_leases": len(ip_macs), "macs": len(mac_ips),
        "addresses_with_several_macs": unstable,
        "macs_with_several_addresses": sorted(m for m, ips in mac_ips.items() if len(ips) > 1),
        "host_names": {ip: mac_names.get(ip_macs[ip][0], []) for ip in sorted(ip_macs)},
        "client_numbers_from_names": {ip: k for ip, k in sorted(by_name.items()) if k is not None},
        "clients_3_4": clients_3_4, "clients_3_4_rule": "host name" if len(named_3_4) == 2
        else "inferred numbering 172.16.1.(k+1)",
        "compromised_macs": sorted(comp_macs),
    }  # fmt: skip

    # P1x calibration windows (registered streaming and builder, unchanged)
    p1x = _load("phase8j_build_p1x", ROOT / "scripts" / "phase8j" / "build_p1x.py")
    bw = p1x.BW
    builder = p1x.P1xBuilder(BOUNDARY_MS, set())
    for frame in bw.chunks(flow_files, False, bw.MAX_ROWS):
        builder.add(frame)
    cal = pl.concat(builder.cal, how="diagonal_relaxed")
    builder.cal.clear()
    cal.write_parquet(DERIVED / "cal_p1x.parquet")
    cut = split_cut(cal["win"].to_numpy())
    rep["windows"] = {
        "calibration": cal.height, "sources": cal["key"].n_unique(),
        "memory_destinations": len(builder.seen), "split_cut_win": cut,
        "holdout_start_utc": datetime.fromtimestamp(cut * bw.W, UTC).isoformat(),
        "holdout": int((cal["win"] >= cut).sum()),
    }  # fmt: skip

    # host eligibility (section 2)
    per = (cal.group_by("key").agg(pl.len().alias("cal"), (pl.col("win") >= cut).sum().alias("hold"))
           .sort("key"))  # fmt: skip
    keys = per["key"].to_list()
    src = [k.split("|")[0] if isinstance(k, str) else str(k) for k in keys]

    def internal_ip(a: str) -> bool:
        try:
            return ipaddress.ip_address(a) in CLIENTS
        except ValueError:
            return False

    rows = []
    for k, a, c, h in zip(keys, src, per["cal"], per["hold"], strict=True):
        why = ("excluded" if a in excluded else "clients_3_4" if a in clients_3_4
               else "several_macs" if a in unstable else "inactive" if c < MIN_CAL or h < MIN_HOLD
               else "eligible")  # fmt: skip
        rows.append({"key": k, "addr": a, "internal": internal_ip(a), "cal": int(c),
                     "hold": int(h), "status": why})  # fmt: skip
    prim = [r for r in rows if r["internal"]]
    elig = [r for r in prim if r["status"] == "eligible"]
    hold = np.array([r["hold"] for r in elig])
    sub = cal.filter(pl.col("key").is_in([r["key"] for r in elig]) & (pl.col("win") >= cut))
    sid = sessions(sub.select("key", "win")) if sub.height else np.array([])
    sess = np.unique(sid, return_counts=True)[1] if sid.size else np.array([])
    rep["hosts"] = {"primary": prim, "secondary_eligible": sum(
        1 for r in rows if not r["internal"] and r["addr"] not in excluded and r["cal"] >= MIN_CAL
        and r["hold"] >= MIN_HOLD)}  # fmt: skip
    g = rep["gate"]
    g["N4_eligible_primary_hosts"] = len(elig)
    g["N5_kish_effective_hosts"] = kish(hold)
    g["N5_top_host_share"] = float(hold.max() / hold.sum()) if hold.size else float("nan")
    g["N6_eligible_holdout_windows"] = int(hold.sum())
    g["N6_descriptive_sessions"] = int(sess.size)
    g["N6_descriptive_kish_effective_sessions_rho1"] = kish(sess)
    fails = []
    if n2:
        fails.append("N2")
    if n3:
        fails.append("N3")
    if len(elig) < 20:
        fails.append("N4")
    if not hold.size or g["N5_kish_effective_hosts"] < 10 or g["N5_top_host_share"] > 0.25:
        fails.append("N5")
    if g["N6_eligible_holdout_windows"] < 590:
        fails.append("N6")
    g["failed"] = fails
    g["outcome"] = "PASS" if not fails else "NOT EVALUABLE"
    from netsentinel.resources import peak_rss_mb

    rep["peak_rss_mb"] = peak_rss_mb()
    rep["seconds"] = round(time.perf_counter() - t0, 1)
    OUT.write_text(json.dumps(rep, indent=1, default=str), "utf-8")
    print(json.dumps(g, indent=1), flush=True)


if __name__ == "__main__":
    main()
