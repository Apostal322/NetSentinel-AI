"""NetSentinel dashboard (Streamlit). Reads the SAME event store the API writes and the
generated experiment reports; it never fabricates numbers.

Run:  uv run --extra dashboard streamlit run dashboard/app.py -- --events-db artifacts/events.sqlite
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument(
    "--events-db",
    default=os.environ.get("NETSENTINEL_EVENTS_DB", str(ROOT / "artifacts/events.sqlite")),
)
parser.add_argument(
    "--models-dir", default=os.environ.get("NETSENTINEL_MODELS_DIR", str(ROOT / "models"))
)
args, _ = parser.parse_known_args(sys.argv[1:])

st.set_page_config(page_title="NetSentinel AI", layout="wide")
VERDICT_ORDER = ["attack", "suspicious", "unusual", "benign", "insufficient_data"]
COLORS = {"attack": "#c0392b", "suspicious": "#e67e22", "unusual": "#f1c40f",
          "benign": "#7f8c8d", "insufficient_data": "#bdc3c7"}  # fmt: skip


@st.cache_data(ttl=10)
def load_events(db: str, limit: int = 200_000) -> pd.DataFrame:
    if not Path(db).exists():
        return pd.DataFrame()
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        have = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        v2 = [c for c in ("threat_status", "behavior_status", "behavior_score", "app_protocol",
                          "app_status") if c in have]  # fmt: skip
        cols = "".join(", " + c for c in v2)
        df = pd.read_sql_query(
            "SELECT observation_id, ts, source, verdict, service, anomaly_score, p_malicious, "
            f"attack_category, bundle{cols} FROM events ORDER BY ts LIMIT ?", conn,
            params=(limit,))  # fmt: skip
    df["ts"] = pd.to_datetime(df["ts"], format="ISO8601")  # mixed with/without fractions
    return df


@st.cache_data(ttl=10)
def load_behavior(db: str) -> pd.DataFrame:
    if not Path(db).exists():
        return pd.DataFrame()
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        q = "SELECT name FROM sqlite_master WHERE name='behavior_events'"
        if not conn.execute(q).fetchone():
            return pd.DataFrame()
        df = pd.read_sql_query("SELECT * FROM behavior_events ORDER BY window_end", conn)
    df["window_end"] = pd.to_datetime(df["window_end"], format="ISO8601")
    df["anomalous"] = df["anomalous"].astype(bool)  # SQLite stores 0/1
    return df


def manifests(pattern: str) -> list[dict]:
    out = []
    for m in sorted(Path(args.models_dir).glob(pattern)):
        try:
            out.append({"_path": str(m.parent), **json.loads(m.read_text("utf-8"))})
        except (OSError, ValueError):
            continue
    return out


def hhmm(obj: pd.DataFrame | pd.Series):
    """Label a time index as explicit 24-hour local capture time (the default chart axis uses a
    12-hour clock without AM/PM - exactly the ambiguity fixed in the raw data)."""
    obj = obj.copy()
    obj.index = obj.index.strftime("%H:%M:%S")
    obj.index.name = "capture time (24 h)"
    return obj


def event_payload(db: str, oid: str) -> dict | None:
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        row = conn.execute("SELECT payload FROM events WHERE observation_id=?", (oid,)).fetchone()
    return json.loads(row[0]) if row else None


st.title("NetSentinel AI")
st.warning(
    "**Detection only.** Events are model outputs on recorded traffic (captures you analyse, "
    "replayed benchmark flows) or on the Zeek log that YOUR Zeek writes, read by the opt-in "
    "`netsentinel monitor`. NetSentinel never captures, intercepts, scans or blocks traffic. "
    "Scores are local-baseline deviations, not attack probabilities."
)
PAGES = ["Live traffic", "Behavior intelligence", "Application intelligence",
         "Incident explorer", "Traffic explorer", "Anomalies", "Threats", "Analyze capture",
         "Model management", "Research & diagnostics"]  # fmt: skip
STANDALONE = ("Model management", "Incident explorer", "Research & diagnostics")
page = st.sidebar.radio("Page", PAGES)


def calibration_manifest(cid: str) -> dict | None:
    for m in manifests("calibrations/*/manifest.json"):
        if m.get("calibration_id") == cid:
            return m
    return None


def reports(name: str) -> dict | None:
    f = ROOT / "reports" / name
    try:
        return json.loads(f.read_text("utf-8")) if f.exists() else None
    except (OSError, ValueError):
        return None


if page == "Analyze capture":
    import tempfile

    sys.path.insert(0, str(ROOT / "src"))
    from netsentinel.streaming.offline import analyze_capture

    bundles = sorted(Path(args.models_dir).glob("bundle-*"))
    st.subheader("Analyze a PCAP / pcapng file or Zeek conn.log")
    st.caption("Parsed locally by NetSentinel's defensive readers; payloads are never stored. "
               "Use a bundle trained on a feature set your source provides (nf_portable* for "
               "Zeek). Fields the source lacks are listed as missing.")  # fmt: skip
    if not bundles:
        st.info(f"No bundles in {args.models_dir}.")
        st.stop()
    bundle = st.selectbox("Model bundle", [b.name for b in bundles], index=len(bundles) - 1)
    cals = ["(none)"] + [m["_path"] for m in manifests("calibrations/*/manifest.json")]
    cal = st.selectbox("Local calibration (behaviour profile)", cals, index=len(cals) - 1)
    apps = ["(none)"] + [m["_path"] for m in manifests("appintel/*/manifest.json")]
    app_dir = st.selectbox("Application classifier", apps, index=len(apps) - 1)
    offset = st.number_input("Capture UTC offset (hours)", -14.0, 14.0, 0.0, 0.5)
    up = st.file_uploader("Capture file", type=None, accept_multiple_files=False)
    if up is not None and st.button("Analyze"):
        with tempfile.TemporaryDirectory(prefix="netsentinel-ui-") as tmp:
            path = Path(tmp) / "capture.bin"
            path.write_bytes(up.getbuffer())
            try:
                summary = analyze_capture(
                    path, Path(args.models_dir) / bundle, args.events_db, offset,
                    source_name=Path(up.name).name[:128],
                    calibration_dir=None if cal == "(none)" else cal,
                    appid_dir=None if app_dir == "(none)" else app_dir)  # fmt: skip
            except ValueError as exc:
                st.error(str(exc))
                st.stop()
        load_events.clear()
        load_behavior.clear()
        c = st.columns(4)
        c[0].metric("flows", summary["flows"])
        for col, v in zip(c[1:], ("attack", "suspicious", "unusual"), strict=True):
            col.metric(v, summary.get("verdicts", {}).get(v, 0))
        keys = ("threat_mode", "threat_status", "behavior_status", "app_status", "baseline_state")
        st.write("**Evidence sources**", {k: summary.get(k) for k in keys})
        st.write("**Parsing**", summary["parse"])
        if summary.get("missing_features"):
            st.warning(f"{len(summary['missing_features'])} model features missing from this "
                       f"source: {', '.join(summary['missing_features'][:12])}...")  # fmt: skip
        st.write("**Top alerts**")
        st.json(summary.get("top_alerts", [])[:5])
    st.stop()

if page == "Incident explorer":
    sys.path.insert(0, str(ROOT / "src"))
    from netsentinel.incidents import STATUSES
    from netsentinel.storage.events import EventStore

    st.subheader("Incident explorer")
    st.caption(
        "An incident groups the anomalous windows of ONE entity (device, service or the whole "
        "network) separated by at most 5 minutes. Severity ranks deviation strength "
        "(score/threshold, duration); it is not an attack probability. `threat_status` is the "
        "supervised evidence of the linked flows (unverified by default)."
    )
    if not Path(args.events_db).exists():
        st.info(f"No event store at {args.events_db}.")
        st.stop()
    store = EventStore(args.events_db)
    c = st.columns(4)
    status = c[0].multiselect("Status", list(STATUSES),
                              default=[x for x in STATUSES if x != "resolved"])  # fmt: skip
    sev = c[1].multiselect("Severity", ["high", "medium", "low"], default=["high", "medium", "low"])
    level = c[2].selectbox("Level", ["(all)", "device", "service", "global"])
    size = 50
    pg = int(c[3].number_input("Page", min_value=1, value=1, step=1))
    items, total = store.incidents(status=status or None, severity=sev or None,
                                   level=None if level == "(all)" else level, limit=size,
                                   offset=(pg - 1) * size)  # fmt: skip
    st.caption(f"{total} matching incidents; page {pg} of {max(1, -(-total // size))}")
    if not items:
        st.info("No incidents match. Incidents are created by `analyze` or `monitor` with a "
                "behaviour calibration.")  # fmt: skip
        st.stop()
    cols = ("incident_id", "severity", "status", "level", "entity", "first_seen", "last_seen",
            "n_windows", "n_flow_events", "max_ratio", "threat_status_worst")  # fmt: skip
    tab = pd.DataFrame(
        [
            {**{k: d.get(k) for k in cols}, "explanation": ", ".join(d.get("explanation", [])[:3])}
            for d in items
        ]
    )
    st.dataframe(tab, use_container_width=True, hide_index=True)
    pick = st.selectbox("Inspect incident", tab["incident_id"].tolist())
    d = store.get_incident(pick)
    m = st.columns(4)
    m[0].metric("severity", d["severity"])
    m[1].metric("windows", d["n_windows"])
    m[2].metric("linked flow events", d["n_flow_events"])
    m[3].metric("duration", f"{d['duration_s'] / 60:.1f} min")
    st.write("**Why it was raised** (largest deviations from the local baseline)")
    for e in d.get("explanation") or ["no explanation recorded"]:
        st.write(f"- {e}")
    st.caption(d.get("severity_semantics", ""))
    st.subheader("Window evidence")
    st.dataframe(pd.DataFrame(d.get("window_evidence", [])), use_container_width=True,
                 hide_index=True)  # fmt: skip
    if d.get("app_protocols"):
        st.subheader("Application protocols of linked flows")
        st.bar_chart(pd.Series(d["app_protocols"], name="flows"))
    with st.expander("Linked flow events, threat status and model versions"):
        st.json(
            {
                "flow_evidence": d.get("flow_evidence"),
                "threat_status": d.get("threat_status"),
                "flow_verdicts": d.get("flow_verdicts"),
                "model_versions": d.get("model_versions"),
                "calibration": d.get("calibration"),
                "baseline_status": d.get("baseline_status"),
            }
        )
    st.subheader("Lifecycle")
    if d.get("status_history"):
        st.dataframe(pd.DataFrame(d["status_history"]), use_container_width=True, hide_index=True)
    with st.form("status"):
        new = st.selectbox("Set status", list(STATUSES), index=list(STATUSES).index(d["status"]))
        note = st.text_input("Note (optional)", max_chars=500)
        if st.form_submit_button("Update status"):
            store.set_incident_status(pick, new, note, by="dashboard")
            st.success(f"{pick}: {d['status']} -> {new}")
    st.stop()

if page == "Research & diagnostics":
    st.subheader("Research & diagnostics (development and historical results, not live)")
    st.caption("Numbers on this page come from the committed experiment reports. They describe "
               "the research datasets, not your traffic.")  # fmt: skip
    conf = reports("phase8/confirm_49_1.json")
    if conf:
        st.markdown("**Phase 8 confirmatory test** (IoT-23 49-1, pre-registered in "
                    "docs/phase8/RESEARCH_PLAN.md)")  # fmt: skip
        st.dataframe(
            pd.DataFrame(
                [
                    {"hypothesis": h, "verdict": v.get("verdict")}
                    for h, v in conf["hypotheses"].items()
                ]
            ),
            hide_index=True,
        )
    sel = reports("phase8/temporal_selection.json")
    if sel:
        st.markdown("**Temporal scorers on development data** (device level, clean "
                    "calibration; exploratory)")  # fmt: skip
        st.dataframe(pd.DataFrame([{"config": k, **{x: v[x] for x in (
            "mean_pr_auc", "median_fpr", "median_fa_per_h", "median_score_us")}}
            for k, v in sel["primary"]["configs"].items()]).sort_values(
            "mean_pr_auc", ascending=False), hide_index=True)  # fmt: skip
    lat = reports("phase8/zeek_lateness.json")
    if lat:
        st.markdown("**Zeek record lateness** (why `monitor` defaults to 360 s)")
        st.dataframe(pd.DataFrame(lat).T, use_container_width=True)
    for fig in ("binary_recall_by_label.png", "openset_recall.png", "adaptation_calibration.png"):
        f = ROOT / "reports/figures" / fig
        if f.exists():
            st.image(str(f), caption=f"historical research figure: {fig}")
    st.stop()

events = load_events(args.events_db)
if events.empty and page not in STANDALONE:
    st.info(f"No events in {args.events_db}. Run `netsentinel replay ...` first.")
    st.stop()

if page not in STANDALONE:
    sources = sorted(events["source"].unique())
    # One replay source (capture day) at a time: time spans and timelines across different
    # days would be meaningless.
    pick = st.sidebar.selectbox("Source", sources)
    events = events[events["source"] == pick]
    t0, t1 = events["ts"].min().to_pydatetime(), events["ts"].max().to_pydatetime()
    if t0 < t1:
        rng = st.sidebar.slider("Time window", min_value=t0, max_value=t1, value=(t0, t1),
                                format="HH:mm:ss")  # fmt: skip
        events = events[(events["ts"] >= rng[0]) & (events["ts"] <= rng[1])]
    bucket = st.sidebar.selectbox("Timeline bucket", ["10s", "1min", "5min"], index=1)

if page == "Live traffic":
    st.caption(
        "Sources named `zeek-stream:*` are written continuously by "
        "`netsentinel monitor --zeek-log ... --follow`; this page refreshes every 10 s."
    )
    counts = events["verdict"].value_counts()
    cols = st.columns(5)
    for c, v in zip(cols, VERDICT_ORDER, strict=True):
        c.metric(v, f"{int(counts.get(v, 0)):,}")
    span = (events["ts"].max() - events["ts"].min()).total_seconds() / 3600
    st.caption(f"{len(events):,} replayed flows over {span:.2f} h of capture time; bundle(s): "
               f"{', '.join(events['bundle'].dropna().unique())}")  # fmt: skip
    tl = hhmm(events.set_index("ts").groupby("verdict").resample(bucket).size()
              .unstack(0).fillna(0))  # fmt: skip
    st.subheader("Flows per bucket by verdict")
    st.area_chart(tl[[v for v in VERDICT_ORDER if v in tl.columns]],
                  color=[COLORS[v] for v in VERDICT_ORDER if v in tl.columns])  # fmt: skip
    alerts = events[events["verdict"].isin(["attack", "suspicious"])]
    st.subheader("Alert episodes")
    st.caption("Consecutive alert flows less than 60 s apart are grouped into one episode, so a "
               "single incident is not counted as thousands of alerts.")  # fmt: skip
    if alerts.empty:
        st.write("No alerts in the selected window.")
    else:
        a = alerts.sort_values("ts").copy()
        a["episode"] = (a["ts"].diff().dt.total_seconds().fillna(1e9) > 60).cumsum()
        ep = a.groupby("episode").agg(start=("ts", "min"), end=("ts", "max"),
                                      flows=("ts", "size"),
                                      top_category=("attack_category",
                                                    lambda s: s.mode().iat[0] if s.notna().any()
                                                    else "unknown"),
                                      max_p=("p_malicious", "max"))  # fmt: skip
        st.dataframe(ep, use_container_width=True)

elif page == "Traffic explorer":
    st.subheader("Service categories (port heuristic)")
    st.bar_chart(events["service"].value_counts())
    st.subheader("Flows per bucket")
    st.line_chart(hhmm(events.set_index("ts").resample(bucket).size().rename("flows")))
    st.subheader("Inspect an event")
    verdicts = st.multiselect("Verdicts", VERDICT_ORDER, default=["attack", "suspicious",
                                                                  "unusual"])  # fmt: skip
    sub = events[events["verdict"].isin(verdicts)].tail(500)
    st.dataframe(sub, use_container_width=True, hide_index=True)
    oid = st.text_input("observation_id")
    if oid:
        st.json(event_payload(args.events_db, oid) or {"error": "not found"})

elif page == "Anomalies":
    st.subheader("Anomaly score over time")
    st.caption(
        "Score = percentile of the detector's raw score among held-out benign training "
        "flows of the same service context. Threshold set on validation benign flows."
    )
    st.line_chart(hhmm(events.set_index("ts")["anomaly_score"].resample(bucket).max()
                       .rename("max")))  # fmt: skip
    st.subheader("Score distribution by verdict")
    hist = (events.assign(bin=(events["anomaly_score"] // 5) * 5)
            .groupby(["bin", "verdict"]).size().unstack(1).fillna(0))  # fmt: skip
    st.bar_chart(hist)
    top = events.sort_values("anomaly_score", ascending=False).head(50)
    st.subheader("Most anomalous flows")
    st.dataframe(top, use_container_width=True, hide_index=True)

elif page == "Threats":
    alerts = events[events["verdict"].isin(["attack", "suspicious"])]
    st.metric("alert flows", f"{len(alerts):,}")
    st.subheader("Attack categories")
    st.caption("`unknown` = malicious evidence but attack-type confidence below threshold.")
    st.bar_chart(alerts["attack_category"].fillna("(no type model)").value_counts())
    st.subheader("Highest-probability alerts")
    show = alerts.sort_values("p_malicious", ascending=False).head(100)
    st.dataframe(show, use_container_width=True, hide_index=True)
    if not show.empty:
        pick_id = st.selectbox("Evidence for", show["observation_id"].tolist())
        payload = event_payload(args.events_db, pick_id)
        if payload:
            st.write("**Evidence (measured deviations from benign training baseline)**")
            for e in payload["evidence"] or ["no feature beyond |z| >= 4"]:
                st.write(f"- {e}")
            st.caption("Evidence describes how this flow differs from typical benign traffic; "
                       "it is not a causal explanation of the model's decision.")  # fmt: skip
            st.json(payload)

elif page == "Behavior intelligence":
    beh = load_behavior(args.events_db)
    beh = beh[beh["source"] == pick] if not beh.empty else beh
    if beh.empty:
        st.info(
            "No behaviour windows for this source. Run `netsentinel calibrate` on vetted "
            "local traffic, then `netsentinel analyze ... --calibration <profile>`."
        )
        st.stop()
    st.caption(
        "Each row is a closed time window of one entity (the whole network, one "
        "originating device, or one service), compared with the LOCAL calibrated "
        "baseline. Severity is a percentile among held-out calibration windows: a "
        "normalized non-probability, not an attack probability."
    )
    lv = st.radio("Level", ["global", "device", "service"], horizontal=True)
    d = beh[beh["level"] == lv]
    c = st.columns(4)
    c[0].metric("windows", len(d))
    c[1].metric("anomalous", int(d["anomalous"].sum()))
    c[2].metric("entities", d["entity"].nunique())
    c[3].metric("calibration", d["calibration"].iloc[-1] if len(d) else "-")
    man = calibration_manifest(d["calibration"].iloc[-1]) if len(d) else None
    with st.expander("Baseline metadata (local calibration)"):
        if man is None:
            st.write("Calibration manifest not found under the models directory.")
        else:
            lvm = man.get("levels", {}).get(lv, {})
            diag = lvm.get("threshold_diagnostics") or {}
            st.json(
                {
                    "status": man.get("status"),
                    "mode": man.get("mode"),
                    "operator_statement": man.get("operator_statement"),
                    "period": man.get("period"),
                    "window_s": man.get("hyperparameters", {}).get("window_s"),
                    "target_fpr": man.get("hyperparameters", {}).get("target_fpr"),
                    "threshold": lvm.get("threshold"),
                    "threshold_method": lvm.get("threshold_method"),
                    "holdout_windows": lvm.get("holdout_windows"),
                    "expected_fpr": diag.get("expected_fpr"),
                    "fpr_upper95": diag.get("fpr_upper95"),
                    "warnings": lvm.get("warnings"),
                }
            )
            st.caption("fpr_upper95: 95% upper bound of the false-alert rate implied by the "
                       "number of held-out calibration windows (sampling uncertainty only; "
                       "drift is not included).")  # fmt: skip
    if len(d):
        st.subheader("Window score vs local alert threshold")
        g = d.groupby("window_end").agg(score=("score", "max"), threshold=("threshold", "max"))
        st.line_chart(hhmm(g))
        st.subheader("Flows per window (observed)")
        st.line_chart(hhmm(d.groupby("window_end")["n_flows"].sum().rename("flows")))
        st.subheader("Anomalous windows")
        top = d[d["anomalous"]].sort_values("score", ascending=False).head(200)
        st.dataframe(top, use_container_width=True, hide_index=True)

elif page == "Application intelligence":
    if "app_status" not in events.columns or events["app_status"].isna().all():
        st.info("No application-classifier output for this source (analyze with --appid).")
        st.stop()
    st.caption(
        "`app_protocol` is an ML prediction of the nDPI master-protocol PROXY label "
        "(it may abstain); `service` is a port heuristic; no application identity "
        "(e.g. which product inside TLS) is inferred."
    )
    c = st.columns(2)
    c[0].subheader("ML app protocol (predicted only)")
    c[0].bar_chart(events["app_protocol"].dropna().value_counts())
    c[1].subheader("Abstention / status")
    c[1].bar_chart(events["app_status"].value_counts())
    st.subheader("Port heuristic vs ML prediction")
    xt = pd.crosstab(events["service"], events["app_protocol"].fillna("(abstained)"))
    st.dataframe(xt, use_container_width=True)

else:  # Model management
    st.subheader("Installed artifacts")
    st.caption(
        "Research metrics below are HISTORICAL validation/test results from the "
        "experiment reports, not measurements of performance on your traffic."
    )
    groups = (
        ("Supervised bundles", "bundle-*/manifest.json"),
        ("Local calibrations", "calibrations/*/manifest.json"),
        ("Application classifiers", "appintel/*/manifest.json"),
    )
    for title, pattern in groups:
        ms = manifests(pattern)
        st.markdown(f"**{title}** ({len(ms)})")
        for m in ms[-5:]:
            name = m.get("bundle_id") or m.get("calibration_id") or m.get("classifier_id")
            with st.expander(str(name)):
                st.json(m)
    st.markdown(
        "**Known limitations**: the supervised bundle was trained on NF-CICIDS2018 and "
        "does not transfer to other networks (Phase 5); calibration controls false "
        "alarms but does not restore attack detection; application labels are nDPI "
        "proxy labels. See docs/phase6/FINAL_AUDIT.md."
    )
    st.caption("Historical research figures and Phase 8 results: Research & diagnostics.")
