"""Phase 8p Stage 1: label audit and attack observability (EXPLORATORY; label-using diagnostics on
consumed development networks; nothing here selects or evaluates a candidate).

1. **Label audit.** Each attacker entity of the Phase 8n/8o evaluation (75) gets a role:
   - `documented_attacker`: the source is a documented attacking (or infected) host. For NF-CIC
     the source is the official CSE-CIC-IDS2018 table (docs/phase8p/ATTACK_OBSERVABILITY.md);
     for NF-ToN-IoT, the documented attacker range ending .30–.39; for NF-UNSW, 175.45.176.0–3;
     for NF-BoT, the hosts sending attack flows to several attacked hosts (data-derived).
   - `attacked_host_traffic`: the source's attack-labelled flows go to a documented or
     data-derived attacker (responses or callbacks of an attacked host). Data-derived role.
   - `undocumented_source`: neither. Attack labels on a host the documentation does not name.
   A documented attacker's evaluation windows outside its documented attack interval are flagged.
2. **Observability per group** (attack windows of a group's entities vs verified-benign windows
   of the same domain's evaluation period), on two representations:
   - source windows: the 12 registered features (Phase 8j P1x evaluation windows);
   - victim windows: `netsentinel.behavior.victim.VICTIM_FEATURES` (Phase 8p VW). The VW of
     the group's victims count as positive where a group entity sent an attack flow in that
     window.
   Two diagnostics per group and representation:
   - per feature: AUC, and the share of benign windows at or beyond the attack median (in the
     direction of the attack);
   - an **optimistic in-domain ceiling**: LightGBM (100 trees) with 5 time-blocked folds (10-min
     blocks). Host identity can leak across folds, so this is an upper bound on what the
     features carry, never a deployable result.

   Classes, a diagnostic convention fixed in this file before it was run:
   - **observable:** ceiling recall at a 1 % benign FPR ≥ 0.5, or best single-feature AUC ≥ 0.95;
   - **weakly observable:** ceiling AUC ≥ 0.7;
   - **not established as observable:** otherwise.

Output: reports/phase8p/observability.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8p/observability.py
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.behavior.victim import VICTIM_FEATURES  # noqa: E402
from netsentinel.behavior.windows import WINDOW_FEATURES  # noqa: E402

INV = ROOT / "reports" / "phase8p" / "missed_inventory.json"
P1X = ROOT / "data" / "derived" / "phase8j" / "p1x"
B0 = ROOT / "data" / "derived" / "phase8j" / "dev"
VW = ROOT / "data" / "derived" / "phase8p" / "victim"
OUT = ROOT / "reports" / "phase8p" / "observability.json"
BLOCK_MS = 600_000
HOUR_UTC = 3_600_000

# Official CSE-CIC-IDS2018 table (https://www.unb.ca/cic/datasets/ids-2018.html, read 2026-11-03):
# attacking (or, for Bot, infected) hosts and the documented local-time intervals. Local time is
# UTC-4 (UNB, Atlantic time): the 02-20 LOIC-HTTP flows begin at 14:13 UTC against a documented
# 10:12 start, which fixes the offset from the data itself.
LOIC = ["18.218.115.60", "18.219.9.1", "18.219.32.43", "18.218.55.126", "52.14.136.135",
        "18.219.5.43", "18.216.200.189", "18.218.229.235", "18.218.11.51", "18.216.24.42"]  # fmt: skip
# One row per documented attack: (attacking or infected hosts, local-time intervals). Intervals
# are applied per row, so a host is in-interval only during ITS attack (corrected after the Phase 8p
# review: 02-14 and 02-16 had been pooled across attackers, and 02-20's DDoS-LOIC-UDP row, 13:13-13:32,
# was missing).
BOTS = [
    "172.31.69.23",
    "172.31.69.17",
    "172.31.69.14",
    "172.31.69.12",
    "172.31.69.10",
    "172.31.69.8",
    "172.31.69.6",
    "172.31.69.26",
    "172.31.69.29",
    "172.31.69.30",
]
CIC_DOC = {
    "2018-02-14": [(["18.221.219.4"], [("10:32", "12:09")]), (["13.58.98.64"], [("14:01", "15:31")])],
    "2018-02-16": [(["13.59.126.31"], [("10:12", "11:08")]), (["18.219.193.20"], [("13:45", "14:19")])],
    "2018-02-20": [(LOIC, [("10:12", "11:17")]), (LOIC, [("13:13", "13:32")])],
    "2018-02-21": [(LOIC, [("10:09", "10:43")]), (LOIC, [("14:05", "15:05")])],
    "2018-02-22": [(["18.218.115.60"], [("10:17", "11:24"), ("13:50", "14:29"), ("16:15", "16:29")])],
    "2018-03-02": [(BOTS + ["18.219.211.138"], [("10:11", "11:34"), ("14:24", "15:55")])],
}  # fmt: skip
UTC_OFFSET_H = 4


def role(domain: str, src: str, inv: dict) -> str:
    net, day = domain.split("/")
    if net == "nfcic":
        return (
            "documented_attacker"
            if any(src in hosts for hosts, _ in CIC_DOC.get(day, []))
            else "undocumented_source"
        )
    if net == "nfton":
        last = int(src.split(".")[-1])
        if 30 <= last <= 39:
            return "documented_attacker"
        return (
            "attacked_host_traffic"
            if inv.get("top_victim", "").split(".")[-1].isdigit()
            and 30 <= int(inv["top_victim"].split(".")[-1]) <= 39
            else "undocumented_source"
        )
    if net == "nfunsw":
        ip = ipaddress.ip_address(src)
        return (
            "documented_attacker"
            if ip in ipaddress.ip_network("175.45.176.0/30")
            else "undocumented_source"
        )
    # NF-BoT: data-derived. Heavy attackers send to several hosts; an entity whose attack flows go to
    # one of those heavy attackers is an attacked host's traffic.
    return (
        "documented_attacker" if inv.get("attack_flows", 0) > 100_000 else "attacked_host_traffic"
    )


def in_documented_interval(day: str, end_ms: np.ndarray, src: np.ndarray | None) -> np.ndarray:
    """Whether each window (end time, source host) falls in a documented interval of an attack
    that names that host; with `src` None, of any documented attack that day (time only)."""
    t = (end_ms // 60_000 - UTC_OFFSET_H * 60) % (24 * 60)  # local minutes of the day
    ok = np.zeros(end_ms.size, bool)
    for hosts, iv in CIC_DOC[day]:
        mine = (
            np.ones(end_ms.size, bool) if src is None else np.isin(src, np.array(hosts, dtype=str))
        )
        for a, b in iv:
            ha, ma = map(int, a.split(":"))
            hb, mb = map(int, b.split(":"))
            ok |= mine & (t >= ha * 60 + ma) & (t <= hb * 60 + mb)
    return ok


def auc(pos: np.ndarray, neg: np.ndarray) -> float | None:
    if pos.size == 0 or neg.size == 0:
        return None
    from scipy.stats import rankdata

    r = rankdata(np.r_[pos, neg])  # average ranks: tied values (e.g. a mass at 0) count one half
    return float((r[: pos.size].sum() - pos.size * (pos.size + 1) / 2) / (pos.size * neg.size))


def univariate(x: np.ndarray, y: np.ndarray, names: tuple[str, ...]) -> dict:
    out = {}
    for j, n in enumerate(names):
        a = auc(x[y, j], x[~y, j])
        if a is None:
            continue
        sign = 1 if a >= 0.5 else -1
        med = np.median(x[y, j])
        tail = float(np.mean(sign * x[~y, j] >= sign * med))
        out[n] = {"auc": round(a, 4), "benign_share_beyond_attack_median": round(tail, 5)}
    return out


def ceiling(x: np.ndarray, y: np.ndarray, end_ms: np.ndarray) -> dict:
    """Optimistic in-domain separability: time-blocked 5-fold LightGBM, out-of-fold scores."""
    import lightgbm as lgb

    blocks = end_ms // BLOCK_MS
    ub = np.unique(blocks)
    fold_of = {b: i % 5 for i, b in enumerate(ub)}
    fold = np.array([fold_of[b] for b in blocks])
    s = np.full(y.size, np.nan)
    for k in range(5):
        tr, te = fold != k, fold == k
        if y[tr].sum() < 5 or (~y[tr]).sum() < 50 or not te.any():
            continue
        w = np.where(y[tr], 0.5 / y[tr].sum(), 0.5 / (~y[tr]).sum()) * tr.sum()
        m = lgb.LGBMClassifier(n_estimators=100, num_leaves=15, learning_rate=0.1, min_child_samples=5,
                               n_jobs=2, verbose=-1, random_state=0).fit(x[tr], y[tr], sample_weight=w)  # fmt: skip
        s[te] = m.predict_proba(x[te])[:, 1]
    ok = ~np.isnan(s)
    if y[ok].sum() == 0 or (~y[ok]).sum() == 0:
        return {"status": "not estimable (positives confined to too few time blocks)"}
    thr = np.quantile(s[ok & ~y], 0.99)
    return {"auc": round(auc(s[ok & y], s[ok & ~y]), 4),
            "recall_at_1pct_benign_fpr": round(float((s[ok & y] > thr).mean()), 4),
            "positives_scored": int((ok & y).sum()), "positive_blocks": int(np.unique(blocks[y]).size)}  # fmt: skip


def verdict(uni: dict, ceil: dict) -> str:
    best = (
        max((v["auc"] if v["auc"] >= 0.5 else 1 - v["auc"]) for v in uni.values()) if uni else 0.5
    )
    rec, a = ceil.get("recall_at_1pct_benign_fpr"), ceil.get("auc")
    if (rec is not None and rec >= 0.5) or best >= 0.95:
        return "observable"
    if a is not None and a >= 0.7:
        return "weakly observable"
    return "not established as observable"


def source_frames(name: str) -> tuple[pl.DataFrame, np.ndarray, np.ndarray]:
    net, dom = name.split("/")
    z = np.load(B0 / f"{net}__{dom}__seed0.npz")
    order = pl.DataFrame({"key": z["ev_key"].astype(str), "win": z["ev_win"]})
    ev = pl.read_parquet(P1X / net / dom / "eval_p1x.parquet")
    ev = order.join(ev, on=["key", "win"], how="left", maintain_order="left")
    return ev, z["ev_y"].astype(bool), z["ev_benign"].astype(bool)


def victim_frames(name: str) -> pl.DataFrame:
    net, dom = name.split("/")
    return pl.read_parquet(VW / net / dom / "vw" / "*.parquet").filter(pl.col("period") == "eval")


def main() -> None:
    inv = json.loads(INV.read_text("utf-8"))["entities"]
    res: dict = {"status": "EXPLORATORY (label audit and in-domain, label-using observability diagnostics)",
                 "roles": {}, "role_outcomes": {}, "groups": {}}  # fmt: skip
    for ek, v in inv.items():
        dom, src = ek.split("|")
        res["roles"][ek] = role(dom, src, v)
    for r in ("documented_attacker", "attacked_host_traffic", "undocumented_source"):
        es = [ek for ek, rr in res["roles"].items() if rr == r]
        k = [inv[e]["K5"] for e in es]
        res["role_outcomes"][r] = {"entities": len(es),
                                   "detected_ge20_in_all_fits": sum(1 for x in k if x["det_ge20"] == 1.0),
                                   "never_ge20": sum(1 for x in k if x["det_ge20"] == 0.0),
                                   "never_alerted": sum(1 for x in k if x["det_ge1"] == 0.0)}  # fmt: skip
    groups = {
        "nfcic/2018-02-20|loic_http_documented": ("nfcic/2018-02-20", [e.split("|")[1] for e in inv if e.startswith("nfcic/2018-02-20")]),
        "nfcic/2018-02-22|documented_attacker": ("nfcic/2018-02-22", ["18.218.115.60"]),
        "nfcic/2018-02-22|undocumented_sources": ("nfcic/2018-02-22", [e.split("|")[1] for e in inv
                                                   if e.startswith("nfcic/2018-02-22") and res["roles"][e] == "undocumented_source"]),
        "nfton/all|192.168.1.37": ("nfton/all", ["192.168.1.37"]),
        "nfton/all|192.168.1.193": ("nfton/all", ["192.168.1.193"]),
        "nfbot/all|attacked_host_traffic": ("nfbot/all", [e.split("|")[1] for e in inv
                                            if e.startswith("nfbot") and res["roles"][e] == "attacked_host_traffic"]),
        "nfcic/2018-02-16|dos_hulk": ("nfcic/2018-02-16", ["18.219.193.20"]),
        "nfcic/2018-02-14|ssh_bruteforce": ("nfcic/2018-02-14", ["13.58.98.64"]),
    }  # fmt: skip
    for gname, (dom, srcs) in groups.items():
        g: dict = {"entities": srcs}
        ev, y_all, ben = source_frames(dom)
        key = ev["key"].to_numpy().astype(str)
        y = y_all & np.isin(key, srcs)
        keep = y | ben
        xs = np.nan_to_num(
            ev.select([pl.col(f).cast(pl.Float64) for f in WINDOW_FEATURES]).to_numpy()
        )
        end = ev["window_end_ms"].to_numpy()
        if dom.startswith("nfcic") and dom.split("/")[1] in CIC_DOC and y.any():
            day = dom.split("/")[1]
            g["source_attack_windows_in_documented_interval"] = round(
                float(in_documented_interval(day, end[y], key[y]).mean()), 4
            )
            g["source_attack_windows_in_any_documented_interval_time_only"] = round(
                float(in_documented_interval(day, end[y], None).mean()), 4
            )
        g["source"] = {"attack_windows": int(y.sum()), "benign_windows": int(ben.sum()),
                       "univariate": univariate(xs[keep], y[keep], WINDOW_FEATURES),
                       "ceiling": ceiling(xs[keep], y[keep], end[keep])}  # fmt: skip
        g["source"]["verdict"] = verdict(g["source"]["univariate"], g["source"]["ceiling"])
        net, d = dom.split("/")
        vw = victim_frames(dom)
        ac = pl.read_parquet(VW / net / d / "attacker_contacts.parquet").filter(
            pl.col("src").is_in(srcs)
        )
        pos = vw.join(ac.select("dst", "win").unique().with_columns(pl.lit(True).alias("g")),
                      on=["dst", "win"], how="left")["g"].fill_null(False).to_numpy()  # fmt: skip
        vben = ((vw["attack_flows"] == 0) & ~vw["noisy"]).to_numpy()
        vkeep = pos | vben
        xv = np.nan_to_num(
            vw.select([pl.col(f).cast(pl.Float64) for f in VICTIM_FEATURES]).to_numpy()
        )
        vend = ((vw["win"] + 1) * 30_000).to_numpy()
        g["victim"] = {"attack_windows": int(pos.sum()), "benign_windows": int(vben.sum()),
                       "victims": ac["dst"].n_unique(),
                       "positive_mixed_share": round(float(((vw["attack_flows"] < vw["flows"]).to_numpy() & pos).sum() / max(pos.sum(), 1)), 4),
                       "univariate": univariate(xv[vkeep], pos[vkeep], VICTIM_FEATURES),
                       "ceiling": ceiling(xv[vkeep], pos[vkeep], vend[vkeep])}  # fmt: skip
        g["victim"]["verdict"] = verdict(g["victim"]["univariate"], g["victim"]["ceiling"])
        res["groups"][gname] = g
        print(gname, "source", g["source"]["verdict"], g["source"]["ceiling"], "| victim", g["victim"]["verdict"],
              g["victim"]["ceiling"], flush=True)  # fmt: skip
        del vw, xv
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    print(json.dumps(res["role_outcomes"]))


if __name__ == "__main__":
    main()
