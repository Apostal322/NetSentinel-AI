"""Phase 8 confirmatory evaluation - implements docs/phase8/RESEARCH_PLAN.md exactly.

Usage:
  uv run --extra torch python scripts/phase8/confirm_49_1.py <conn.log.labeled> <out.json>

The plan's confirmatory data is IoT-23 CTU-IoT-Malware-Capture-49-1. The same code can be
dry-run on an already-inspected development scenario to check it runs (its output is then a
software check, not evidence). Fixed settings: window 30 s, target FPR 0.01, levels
device+service, lateness 3,700 s in every pass (buffer cap 1.5M records), bootstrap blocks 1 h x 2,000
(seed 0), incident gap 300 s.

Passes over the file (bounded memory, streamed):
  0  time span (flow END times) -> midpoint
  1  calibration windows (clean / unlabelled, expanding destination sets), evaluation windows
     (frozen calibration destinations), window truth, application-ID tallies
  2  H6 run A: evaluation half through StreamMonitor in file order (also H7 throughput)
  3  H6 run B: evaluation half with seeded +/-20 s jitter and 1% duplicates
"""

from __future__ import annotations

import json
import math
import random
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app_abstention import decide, raw_predict  # noqa: E402
from compare_temporal import compare_windows  # noqa: E402
from eval_incidents import summarise  # noqa: E402

from netsentinel.behavior.calibrate import calibrate_windows, save_profile  # noqa: E402
from netsentinel.behavior.profile import BehaviorProfile  # noqa: E402
from netsentinel.behavior.windows import _key_expr, aggregate, prepare_flows  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402
from netsentinel.streaming.live import END, START, StreamMonitor, WindowStream  # noqa: E402
from netsentinel.telemetry.frames import records_to_frame  # noqa: E402
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log  # noqa: E402

W, TARGET, LEVELS, VARIANTS = 30, 0.01, ("device", "service"), ("clean", "unlabelled")
APP7 = Path("models/appintel/appid-portable-20261020T184500Z")  # Phase 7 product (hybrid)
APP8 = Path("models/appintel/appid-portable-20261020T201432Z")  # Phase 8 product (+consistency)
CANDIDATES = [("robust_z", "base", {}), ("guarded_ewma", "base", {})]
SERVICES = ["dns", "ssl", "http", "ssh", "ftp", "ftp-data", "smtp", "irc", "telnet", "dhcp",
            "ntp", "snmp", "sip", "radius", "krb", "krb_tcp", "smb", "mysql", "rdp", "imap",
            "pop3", "quic", "ldap", "tftp", "mqtt", "syslog"]  # fmt: skip
ZEEK_TO_APP = {"dns": "dns", "ssl": "tls", "http": "http", "ssh": "ssh", "ftp": "ftp_control",
               "ftp-data": "ftp_data", "smtp": "smtp", "irc": "irc", "telnet": "telnet",
               "dhcp": "dhcp", "ntp": "ntp", "snmp": "snmp", "sip": "sip", "radius": "radius",
               "krb": "kerberos", "krb_tcp": "kerberos", "smb": "smbv23", "mysql": "mysql",
               "rdp": "rdp", "imap": "imap", "pop3": "pop3", "quic": "quic", "ldap": "ldap",
               "tftp": "tftp", "mqtt": "mqtt", "syslog": "syslog"}  # fmt: skip
REFERENCE = {"dns": "dns", "ssl": "tls", "http": "http"}  # H5 (a)
APP_VARIANTS = ("port_only", "ml_only", "hybrid", "hybrid+consistency")
# Zeek writes a connection after its inactivity timeout: development logs need up to 3,595 s
# (reports/phase8/zeek_lateness.json), so both passes allow 3,700 s.
LATENESS_S, MAX_BUFFER = 3700, 1_500_000


def is_attack(d: dict) -> float:
    return 1.0 if str(d.get("label", "")).lower().startswith("malicious") else 0.0


def svc_code(d: dict) -> float:
    s = str(d.get("service", "-")).split(",")[0]
    if s in ("-", "", "(empty)"):
        return 0.0
    return float(SERVICES.index(s) + 1) if s in SERVICES else 99.0


EXTRAS = {"IS_ATTACK": is_attack, "ZEEK_SVC": svc_code}


def records(path: Path, stats: ZeekStats | None = None):
    return read_conn_log(path, stats, extras=EXTRAS)


def clopper_pearson(k: int, n: int, a: float = 0.05) -> tuple[float | None, float | None]:
    from scipy.stats import beta

    if n == 0:
        return None, None
    lo = 0.0 if k == 0 else float(beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a / 2, k + 1, n - k))
    return lo, hi


def block_bootstrap_delta(end_ms, y, s1, s2, B=2000, block_ms=3_600_000, seed=0) -> dict:
    from sklearn.metrics import average_precision_score as ap

    blocks = ((end_ms - end_ms.min()) // block_ms).astype(np.int64)
    ids = np.unique(blocks)
    idx = [np.where(blocks == b)[0] for b in ids]
    rng = np.random.default_rng(seed)
    deltas, skipped = [], 0
    for _ in range(B):
        pick = np.concatenate([idx[i] for i in rng.integers(0, len(ids), len(ids))])
        yy = y[pick]
        if yy.sum() == 0 or yy.sum() == len(yy):
            skipped += 1
            continue
        deltas.append(ap(yy, s1[pick]) - ap(yy, s2[pick]))
    d = np.array(deltas)
    point = ap(y, s1) - ap(y, s2)
    return {"delta": float(point), "ci95": [float(np.quantile(d, 0.025)), float(np.quantile(d, 0.975))]
            if len(d) else None, "blocks": int(len(ids)), "resamples": int(len(d)),
            "skipped": skipped}  # fmt: skip


def verdict_ci(ci, side: str) -> str:
    if ci is None:
        return "not_testable"
    lo, hi = ci
    if side == "pos":
        return "supported" if lo > 0 else ("refuted" if hi < 0 else "inconclusive")
    raise ValueError(side)


def window_truth(ev: pl.DataFrame, lv: str) -> pl.DataFrame:
    start = pl.col("end_ms") - pl.col("dur_ms")
    return (ev.with_columns((pl.col("end_ms") // (W * 1000)).alias("win"), _key_expr(lv))
            .group_by("key", "win")
            .agg((pl.col("is_attack").max() > 0).alias("y"),
                 start.filter(pl.col("is_attack") > 0).min().alias("first_attack_ms")))  # fmt: skip


# ----------------------------------------------------------------------------- passes
def pass0(path: Path) -> dict:
    t0 = time.perf_counter()
    st = ZeekStats()
    lo, hi, n, att = math.inf, -math.inf, 0, 0
    for r in records(path, st):
        e = r[END]
        lo, hi = min(lo, e), max(hi, e)
        n += 1
        att += r["IS_ATTACK"] > 0
    return {"records": n, "attack_records": int(att), "min_end_ms": int(lo), "max_end_ms": int(hi),
            "mid_ms": int(lo + (hi - lo) // 2), "parse": {"lines": st.lines,
            "skipped": st.skipped}, "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip


class MainPass:
    def __init__(self, mid: int, clf8, classes: list[str]):
        self.mid, self.clf8, self.classes = mid, clf8, set(classes)
        self.seen = {v: set() for v in VARIANTS}
        self.cal = {v: {lv: [] for lv in LEVELS} for v in VARIANTS}
        self.ev = {v: {lv: [] for lv in LEVELS} for v in VARIANTS}
        self.truth = {lv: [] for lv in LEVELS}
        self.ev_span = [math.inf, -math.inf]
        self.app = {v: Counter() for v in APP_VARIANTS}
        self.app_per_ref = {v: Counter() for v in APP_VARIANTS}
        self.outside_services: Counter = Counter()
        self.flows = Counter()

    def process(self, recs: list[dict]) -> None:
        frame = records_to_frame(recs)
        flows = prepare_flows(frame)
        cal = flows.filter(pl.col("end_ms") < self.mid)
        ev = flows.filter(pl.col("end_ms") >= self.mid)
        self.flows["cal"] += cal.height
        self.flows["eval"] += ev.height
        for v in VARIANTS:
            sub = cal if v == "unlabelled" else cal.filter(pl.col("is_attack") == 0)
            if sub.height:
                for lv in LEVELS:
                    self.cal[v][lv].append(aggregate(sub, lv, W, prior_dst=self.seen[v]))
                self.seen[v] |= set(sub["dst"].unique().to_list())
        if ev.height:
            self.ev_span = [min(self.ev_span[0], int(ev["end_ms"].min())),
                            max(self.ev_span[1], int(ev["end_ms"].max()))]  # fmt: skip
            for lv in LEVELS:
                self.truth[lv].append(window_truth(ev, lv))
                for v in VARIANTS:
                    self.ev[v][lv].append(aggregate(ev, lv, W, known_dst=self.seen[v]))
        self._app(frame)

    def _app(self, frame: pl.DataFrame) -> None:
        f = frame.filter(pl.col("zeek_svc") > 0)
        if not f.height:
            return
        codes = f["zeek_svc"].cast(pl.Int64).to_numpy()
        names = np.array([SERVICES[c - 1] if 0 < c <= len(SERVICES) else None for c in codes],
                         dtype=object)  # fmt: skip
        ref = np.array([REFERENCE.get(n) for n in names], dtype=object)
        outside = np.array([n is not None and n not in REFERENCE
                            and ZEEK_TO_APP.get(n) not in self.classes for n in names])  # fmt: skip
        for n in names[outside]:
            self.outside_services[n] += 1
        r = raw_predict(self.clf8, f)
        for v in APP_VARIANTS:
            lab = decide(r, v, self.clf8, self.clf8.class_profiles, {})
            cov = np.array([x is not None for x in lab])
            ok = np.array([a == b for a, b in zip(lab, ref, strict=True)])
            m = ref != None  # noqa: E711
            c = self.app[v]
            c["ref_n"] += int(m.sum())
            c["ref_covered"] += int((m & cov).sum())
            c["ref_correct"] += int((m & cov & ok).sum())
            c["outside_n"] += int(outside.sum())
            c["outside_abstained"] += int((outside & ~cov).sum())
            for k in REFERENCE.values():
                mk = ref == k
                self.app_per_ref[v][f"{k}_n"] += int(mk.sum())
                self.app_per_ref[v][f"{k}_covered"] += int((mk & cov).sum())
                self.app_per_ref[v][f"{k}_correct"] += int((mk & cov & ok).sum())

    def frames(self):
        cat = {v: {lv: pl.concat(self.cal[v][lv], how="diagonal_relaxed") if self.cal[v][lv]
                   else pl.DataFrame() for lv in LEVELS} for v in VARIANTS}  # fmt: skip
        evf = {v: {lv: pl.concat(self.ev[v][lv], how="diagonal_relaxed") if self.ev[v][lv]
                   else pl.DataFrame() for lv in LEVELS} for v in VARIANTS}  # fmt: skip
        tr = {lv: pl.concat(self.truth[lv]) if self.truth[lv] else pl.DataFrame()
              for lv in LEVELS}  # fmt: skip
        return cat, evf, tr


def run_main(path: Path, mid: int, clf8, batch_flows: int = 200_000) -> tuple[MainPass, dict]:
    t0 = time.perf_counter()
    mp = MainPass(mid, clf8, list(clf8.classes))
    ws = WindowStream(W, lateness_s=LATENESS_S, max_buffer=MAX_BUFFER)
    pending: list[dict] = []
    for rec in records(path):
        for _, rs in ws.push(rec):
            pending += rs
        if len(pending) >= batch_flows:
            mp.process(pending)
            pending = []
    for _, rs in ws.flush():
        pending += rs
    if pending:
        mp.process(pending)
    return mp, {"stream": ws.stats.as_dict(), "seconds": round(time.perf_counter() - t0, 1),
                "peak_rss_mb": peak_rss_mb()}  # fmt: skip


def jittered(gen, seed=0, chunk=20_000, jitter_ms=20_000, dup_rate=0.01):
    rng = random.Random(seed)
    buf: list[dict] = []
    stats = {"duplicates_inserted": 0}

    def emit(b):
        b.sort(key=lambda r: r[START] + rng.uniform(-jitter_ms, jitter_ms))
        out = []
        for r in b:
            out.append(r)
            if rng.random() < dup_rate:
                out.insert(max(0, len(out) - 1 - rng.randint(0, 5)), dict(r))
                stats["duplicates_inserted"] += 1
        return out

    for r in gen:
        buf.append(r)
        if len(buf) >= chunk:
            yield from emit(buf)
            buf = []
    if buf:
        yield from emit(buf)
    jittered.stats = stats


def h6_run(cal_dir: Path, path: Path, mid: int, jitter: bool) -> tuple[pl.DataFrame, list, dict]:
    from netsentinel.inference.pipeline import AnalysisPipeline

    pipe = AnalysisPipeline(None, cal_dir)
    mon = StreamMonitor(pipe, None, source="h6", lateness_s=LATENESS_S, max_buffer=MAX_BUFFER,
                        batch_flows=100_000)  # fmt: skip
    mon.keep_windows = True
    zs = ZeekStats()
    gen = (r for r in records(path, zs) if r[END] >= mid)
    t0 = time.perf_counter()
    mon.feed(jittered(gen) if jitter else gen)
    res = mon.close()
    secs = time.perf_counter() - t0
    w = pl.concat(mon.windows_out, how="diagonal_relaxed") if mon.windows_out else pl.DataFrame()
    info = {"flows": res.flows, "stats": res.stats, "seconds": round(secs, 1),
            "file_records": zs.records,
            "records_per_s": zs.records / secs if secs else None,  # all records read (H7)
            "incidents": res.incidents}  # fmt: skip
    if jitter:
        info["duplicates_inserted"] = jittered.stats["duplicates_inserted"]
    return w, [i.incident_id for i in mon.tracker.incidents()], info


# ----------------------------------------------------------------------------- analysis
def testable(cal_dev: pl.DataFrame, ev_dev: pl.DataFrame, tr_dev: pl.DataFrame) -> dict:
    y = ev_dev.join(tr_dev, on=["key", "win"], how="left")["y"].fill_null(False)
    return {"cal_windows": cal_dev.height, "eval_attack_windows": int(y.sum()),
            "eval_benign_windows": int((~y).sum()),
            "ok": cal_dev.height >= 60 and int(y.sum()) >= 5 and int((~y).sum()) >= 30}  # fmt: skip


def product_profile(cal: dict, seen: set, period: dict) -> BehaviorProfile:
    lv = calibrate_windows({k: cal[k] for k in LEVELS}, 0, target_fpr=TARGET, min_windows=30,
                           mode="vetted_benign", top_k=2, threshold_method="crossfit")  # fmt: skip
    return BehaviorProfile(window_s=W, mode="vetted_benign", target_fpr=TARGET, min_windows=30,
                           top_k=2, levels=lv, known_dst=seen, status="baseline_ready",
                           period=period, diagnostics={"threshold_method": "crossfit",
                                                       "source": "phase8 confirmatory"})  # fmt: skip


def main() -> None:
    path, out = Path(sys.argv[1]), Path(sys.argv[2])
    import importlib.metadata as md

    from netsentinel.appintel.model import load_classifier
    from netsentinel.ledger import git_sha

    t_all = time.perf_counter()
    res: dict = {"plan": "docs/phase8/RESEARCH_PLAN.md", "git": git_sha(), "capture": path.name,
                 "versions": {p: md.version(p) for p in ("polars", "numpy", "scikit-learn",
                                                         "lightgbm", "torch")}}  # fmt: skip
    p0 = pass0(path)
    res["pass0"] = p0
    print("pass0", p0, flush=True)
    mid = p0["mid_ms"]
    clf8, man8 = load_classifier(APP8)
    load_classifier(APP7)  # integrity check of the Phase 7 artifact named in the plan
    res["app_artifacts"] = {"phase7": APP7.name, "phase8": APP8.name}
    mp, info = run_main(path, mid, clf8)
    res["pass1"] = {**info, "flows": dict(mp.flows)}
    print("pass1", res["pass1"], flush=True)
    cal, ev, tr = mp.frames()
    hours = (mp.ev_span[1] - mid) / 3.6e6
    res["eval_hours"] = hours
    tests = {v: testable(cal[v]["device"], ev[v]["device"], tr["device"]) for v in VARIANTS}
    res["testability"] = tests
    H: dict = {}

    # H1a / H1b ---------------------------------------------------------------------------
    for h, v, first in (
        ("H1a", "clean", "robust_z/base"),
        ("H1b", "unlabelled", "guarded_ewma/base"),
    ):
        if not tests[v]["ok"]:
            H[h] = {"verdict": "not_testable", "testability": tests[v]}
            continue
        r = compare_windows(cal[v]["device"], ev[v]["device"], tr["device"], CANDIDATES, hours,
                            keep_scores=True)  # fmt: skip
        other = "guarded_ewma/base" if first == "robust_z/base" else "robust_z/base"
        if r.get("status"):
            H[h] = {"verdict": "not_testable", "detail": r}
            continue
        d = ev[v]["device"].select("key", "win", "window_end_ms").join(
            tr["device"], on=["key", "win"], how="left").with_columns(pl.col("y").fill_null(False))  # fmt: skip
        boot = block_bootstrap_delta(d["window_end_ms"].to_numpy(), d["y"].to_numpy().astype(int),
                                     r[first]["_scores"], r[other]["_scores"])  # fmt: skip
        for k in CANDIDATES:
            m = r[f"{k[0]}/{k[1]}"]
            m.pop("_scores")
            m.pop("_threshold")
        H[h] = {"variant": v, "statistic": f"PR-AUC({first}) - PR-AUC({other})", **boot,
                "verdict": verdict_ci(boot["ci95"], "pos"), "metrics": r}  # fmt: skip
        print(h, H[h]["verdict"], boot, flush=True)

    # H2 / H3 (product calibration, clean) ------------------------------------------------
    prof = None
    if tests["clean"]["ok"]:
        period = {"start_utc_ms": p0["min_end_ms"], "end_utc_ms": mid - 1, "fit_end_utc_ms": mid,
                  "global_windows": None, "flows": mp.flows["cal"]}  # fmt: skip
        prof = product_profile(cal["clean"], mp.seen["clean"], period)
        evw = pl.concat([ev["clean"][lv].with_columns(pl.lit(lv).alias("level"))
                         for lv in LEVELS], how="diagonal_relaxed")  # fmt: skip
        sc = prof.score(evw)
        dev = sc.filter(pl.col("level") == "device").join(tr["device"], on=["key", "win"],
                                                          how="left").with_columns(
            pl.col("y").fill_null(False))  # fmt: skip
        ben = dev.filter(~pl.col("y"))
        k, n = int(ben["anomalous"].sum()), ben.height
        lo, hi = clopper_pearson(k, n)
        fpr = k / n if n else None
        v2 = ("supported" if fpr is not None and fpr <= 0.03 and hi <= 0.05
              else "refuted" if lo is not None and lo > 0.03 else "inconclusive")  # fmt: skip
        H["H2"] = {"fpr": fpr, "ci95": [lo, hi], "false_alerts": k, "benign_windows": n,
                   "threshold": prof.levels["device"].threshold,
                   "threshold_diag": prof.levels["device"].threshold_diag,
                   "recall": float(dev.filter(pl.col("y"))["anomalous"].mean()),
                   "verdict": v2}  # fmt: skip
        print("H2", H["H2"], flush=True)
        truth = {}
        for lv in LEVELS:
            truth |= {(lv, str(a), int(b)): bool(c)
                      for a, b, c in tr[lv].select("key", "win", "y").iter_rows()}  # fmt: skip
        inc = summarise(sc, truth, hours, W, levels=LEVELS)
        d3 = inc.get("device", {})
        if d3.get("incidents", 0) < 5:
            H["H3"] = {"verdict": "not_testable", "detail": d3}
        else:
            ok = (d3["alert_reduction"] or 0) >= 5 and (d3["mean_purity"] or 0) >= 0.8
            H["H3"] = {"alert_reduction": d3["alert_reduction"], "mean_purity": d3["mean_purity"],
                       "verdict": "supported" if ok else "refuted", "device": d3,
                       "service_exploratory": inc.get("service")}  # fmt: skip
        print("H3", H["H3"].get("verdict"), {k: d3.get(k) for k in ("alert_reduction",
              "mean_purity", "incidents", "alerts")}, flush=True)  # fmt: skip
        # exploratory: FPR by hour of day (UTC) of benign device windows
        hod = ben.with_columns(((pl.col("window_end_ms") // 3_600_000) % 24).alias("h")).group_by(
            "h").agg(pl.col("anomalous").mean().alias("fpr"), pl.len().alias("n")).sort("h")  # fmt: skip
        res["exploratory_fpr_by_hour_utc"] = hod.to_dicts()
    else:
        H["H2"] = H["H3"] = {"verdict": "not_testable", "testability": tests["clean"]}

    # H5 ------------------------------------------------------------------------------------
    a7, a8 = mp.app["hybrid"], mp.app["hybrid+consistency"]

    def acc(c):
        return c["ref_correct"] / c["ref_covered"] if c["ref_covered"] else None

    def abst(c):
        return c["outside_abstained"] / c["outside_n"] if c["outside_n"] else None

    h5 = {v: {"ref_n": c["ref_n"], "coverage": c["ref_covered"] / c["ref_n"] if c["ref_n"] else None,
              "accepted_accuracy": acc(c), "outside_n": c["outside_n"],
              "outside_abstention": abst(c), "per_reference": dict(mp.app_per_ref[v])}
          for v, c in mp.app.items()}  # fmt: skip
    ta, tb = a8["ref_n"] >= 500, a8["outside_n"] >= 100
    ca = ta and acc(a7) - acc(a8) <= 0.005
    cb = tb and (abst(a8) - abst(a7)) >= 0.05
    H["H5"] = {"variants": h5, "outside_services": dict(mp.outside_services),
               "a_testable": ta, "b_testable": tb, "a": ca if ta else None,
               "b": cb if tb else None,
               "verdict": "not_testable" if not (ta and tb) else (
                   "supported" if ca and cb else "refuted")}  # fmt: skip
    print("H5", H["H5"]["verdict"], {v: (x["accepted_accuracy"], x["outside_abstention"])
                                     for v, x in h5.items()}, flush=True)  # fmt: skip

    # H6 / H7 -------------------------------------------------------------------------------
    if prof is not None:
        tmp = Path(tempfile.mkdtemp(prefix="ns-h6-"))
        cal_dir = save_profile(prof, tmp, sources=[{"path": path.name, "kind": "zeek"}],
                               operator_statement="confirmatory oracle-clean calibration")  # fmt: skip
        wa, ia, inf_a = h6_run(cal_dir, path, mid, jitter=False)
        print("H6 A", inf_a, flush=True)
        wb, ib, inf_b = h6_run(cal_dir, path, mid, jitter=True)
        print("H6 B", inf_b, flush=True)
        cols = ["level", "key", "win", "score", "anomalous"]
        sa, sb = wa.select(cols).sort(cols[:3]), wb.select(cols).sort(cols[:3])
        same_keys = sa.select(cols[:3]).equals(sb.select(cols[:3]))
        maxdiff = float(np.max(np.abs(sa["score"].to_numpy() - sb["score"].to_numpy()))) if (
            same_keys and sa.height) else None  # fmt: skip
        eq = (same_keys and maxdiff is not None and maxdiff < 1e-9 and ia == ib
              and inf_b["stats"]["duplicates"] == inf_b["duplicates_inserted"])  # fmt: skip
        H["H6"] = {"run_file_order": inf_a, "run_jittered": inf_b, "same_window_keys": same_keys,
                   "max_abs_score_diff": maxdiff, "same_incident_ids": ia == ib,
                   "windows": sa.height, "verdict": "supported" if eq else "refuted"}  # fmt: skip
        # exploratory: stream (file order, lateness 60) vs main pass product scores
        mpw = sc.select(cols).sort(cols[:3])
        res["exploratory_stream_vs_main_pass"] = {
            "same_keys": mpw.select(cols[:3]).equals(sa.select(cols[:3])), "main": mpw.height,
            "stream": sa.height}  # fmt: skip
    else:
        H["H6"] = {"verdict": "not_testable"}
    rss = peak_rss_mb()
    thr = H["H6"].get("run_file_order", {}).get("records_per_s")
    if thr is None:
        h7 = "not_testable"
    else:
        h7 = "supported" if rss is not None and rss < 3584 and thr >= 20_000 else "refuted"
    H["H7"] = {"peak_rss_mb": rss, "records_per_s": thr, "verdict": h7}
    res["hypotheses"] = H
    res["seconds"] = round(time.perf_counter() - t_all, 1)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({h: v.get("verdict") for h, v in H.items()}, indent=1), res["seconds"])


if __name__ == "__main__":
    main()
