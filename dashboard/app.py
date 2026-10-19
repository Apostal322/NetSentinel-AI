"""NetSentinel dashboard (Streamlit). Reads the SAME event store the API writes and the
generated experiment reports; it never fabricates numbers.

Run:  uv run --extra dashboard streamlit run dashboard/app.py -- --events-db artifacts/events.sqlite
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--events-db", default=str(ROOT / "artifacts/events.sqlite"))
parser.add_argument("--models-dir", default=str(ROOT / "models"))
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
        df = pd.read_sql_query(
            "SELECT observation_id, ts, source, verdict, service, anomaly_score, p_malicious, "
            "attack_category, bundle FROM events ORDER BY ts LIMIT ?", conn, params=(limit,)
        )  # fmt: skip
    df["ts"] = pd.to_datetime(df["ts"])
    return df


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
    "**Offline analysis.** Events are model outputs on *recorded* traffic (replayed benchmark "
    "flows or captures you upload), not live network monitoring. Anomaly scores are "
    "benign-tail percentiles, not attack probabilities."
)
page = st.sidebar.radio("Page", ["Overview", "Traffic explorer", "Anomalies", "Threats",
                                 "Analyze capture", "Model performance"])  # fmt: skip

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
    offset = st.number_input("Capture UTC offset (hours)", -14.0, 14.0, 0.0, 0.5)
    up = st.file_uploader("Capture file", type=None, accept_multiple_files=False)
    if up is not None and st.button("Analyze"):
        with tempfile.TemporaryDirectory(prefix="netsentinel-ui-") as tmp:
            path = Path(tmp) / "capture.bin"
            path.write_bytes(up.getbuffer())
            try:
                summary = analyze_capture(path, Path(args.models_dir) / bundle, args.events_db,
                                          offset, source_name=Path(up.name).name[:128])  # fmt: skip
            except ValueError as exc:
                st.error(str(exc))
                st.stop()
        load_events.clear()
        c = st.columns(4)
        c[0].metric("flows", summary["flows"])
        for col, v in zip(c[1:], ("attack", "suspicious", "unusual"), strict=True):
            col.metric(v, summary.get("verdicts", {}).get(v, 0))
        st.write("**Parsing**", summary["parse"])
        if summary.get("missing_features"):
            st.warning(f"{len(summary['missing_features'])} model features missing from this "
                       f"source: {', '.join(summary['missing_features'][:12])}...")  # fmt: skip
        st.write("**Top alerts**")
        st.json(summary.get("top_alerts", [])[:5])
    st.stop()

events = load_events(args.events_db)
if events.empty and page != "Model performance":
    st.info(f"No events in {args.events_db}. Run `netsentinel replay ...` first.")
    st.stop()

if page != "Model performance":
    sources = sorted(events["source"].unique())
    # One replay source (capture day) at a time: time spans and timelines across different
    # days would be meaningless.
    pick = st.sidebar.selectbox("Replay source", sources)
    events = events[events["source"] == pick]
    t0, t1 = events["ts"].min().to_pydatetime(), events["ts"].max().to_pydatetime()
    if t0 < t1:
        rng = st.sidebar.slider("Time window", min_value=t0, max_value=t1, value=(t0, t1),
                                format="HH:mm:ss")  # fmt: skip
        events = events[(events["ts"] >= rng[0]) & (events["ts"] <= rng[1])]
    bucket = st.sidebar.selectbox("Timeline bucket", ["10s", "1min", "5min"], index=1)

if page == "Overview":
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

else:  # Model performance
    report = ROOT / "reports/experiments/results_v1.md"
    bundles = sorted(Path(args.models_dir).glob("bundle-*/manifest.json"))
    if bundles:
        st.subheader("Active bundle manifest")
        st.json(json.loads(bundles[-1].read_text("utf-8")))
    for fig in ("binary_recall_by_label.png", "openset_recall.png"):
        p = ROOT / "reports/figures" / fig
        if p.exists():
            st.image(str(p))
    if report.exists():
        st.markdown(report.read_text("utf-8"))
    else:
        st.info("No experiment report yet (scripts/aggregate_results.py).")
