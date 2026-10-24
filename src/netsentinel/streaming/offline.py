"""Offline analysis of a capture: PCAP/pcapng or Zeek conn.log -> flows -> inference -> events.

The capture is treated as one contiguous stream, so causal context features are computed
from the capture itself (`context="compute"`). The bundle must be trained on a feature set the
source can provide (`nf_portable*` for Zeek; PCAP flows also fill the full NF flow fields,
approximately - see telemetry.flows). Everything the source lacks is listed in the summary's
`missing_features`.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

import polars as pl

from netsentinel.storage.events import EventStore
from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.pcap import ReadStats, read_packets
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log

log = logging.getLogger(__name__)

# Skip reasons that are expected on healthy captures (non-IP frames, fragments); everything
# else (truncated or malformed records, unparseable lines) counts towards parse health.
BENIGN_SKIPS = {"not_ip", "non_ip_ethertype", "non_ip_sll", "ipv4_fragment", "empty"}
PARSE_ERROR_SHARE = 0.01


def parse_health(parse: dict) -> str:
    """Phase 8e telemetry health of an offline capture: "ok" or "parse_errors"."""
    total = parse.get("lines") or parse.get("packets") or 0
    bad = sum(n for why, n in (parse.get("skipped") or {}).items() if why not in BENIGN_SKIPS)
    return "parse_errors" if total and bad / total > PARSE_ERROR_SHARE else "ok"


def detect_kind(path: Path) -> str:
    head = path.open("rb").read(4)
    if head in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
                b"\x0a\x0d\x0d\x0a"):  # fmt: skip
        return "pcap"
    return "zeek"


def load_capture(path: str | Path, kind: str = "auto", utc_offset_hours: float = 0.0,
                 zeek_extras: dict | None = None, since=None, until=None):  # fmt: skip
    """Capture -> (canonical flow frame or None if empty, kind, parse statistics).
    `since` / `until` (datetime, UTC; naive = UTC) keep flows whose END time is in
    [since, until): the period a calibration or analysis refers to."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"capture {path} not found")
    kind = detect_kind(path) if kind == "auto" else kind
    if kind == "pcap":
        pstats = ReadStats()
        records = list(assemble_flows(read_packets(path, pstats)))
        parse = asdict(pstats)
    elif kind == "zeek":
        zstats = ZeekStats()
        records = list(read_conn_log(path, zstats, extras=zeek_extras))
        parse = asdict(zstats)
    else:
        raise ValueError(f"unknown capture kind {kind!r}")
    if not records:
        return None, kind, parse
    frame = records_to_frame(records, utc_offset_hours)
    if since is not None or until is not None:
        end = pl.col("flow_end_milliseconds")
        if since is not None:
            frame = frame.filter(end >= _epoch_ms(since))
        if until is not None:
            frame = frame.filter(end < _epoch_ms(until))
        parse = {**parse, "time_filter": {"since": str(since), "until": str(until),
                                          "flows_kept": frame.height}}  # fmt: skip
        if not frame.height:
            return None, kind, parse
    return frame, kind, parse


def _epoch_ms(t) -> int:
    from datetime import UTC

    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return int(t.timestamp() * 1000)


def analyze_capture(
    path: str | Path,
    bundle_dir: str | Path,
    events_db: str | Path | None = None,
    utc_offset_hours: float = 0.0,
    kind: str = "auto",
    source_name: str | None = None,
    calibration_dir: str | Path | None = None,
    appid_dir: str | Path | None = None,
    threat_policy: str = "unverified",
    since=None,
    until=None,
    incident_gap_s: int = 300,
) -> dict[str, Any]:
    """Capture -> flows -> evidence-aware assessment (supervised bundle; optional local
    behaviour calibration and application classifier) -> events (+ behaviour windows)."""
    from netsentinel.inference.pipeline import AnalysisPipeline

    path = Path(path)
    name = source_name or path.name
    pipe = AnalysisPipeline(bundle_dir, calibration_dir, appid_dir, threat_policy)
    frame, kind, parse = load_capture(path, kind, utc_offset_hours, since=since, until=until)
    if frame is None:
        return {"source": name, "kind": kind, "flows": 0, "parse": parse,
                "model_versions": pipe.versions()}  # fmt: skip
    source = f"{kind}:{name}"
    # Context and behaviour windows need the whole capture as one stream: one pass.
    health = parse_health(parse)
    preds, windows = pipe.assess(frame, source, telemetry_health=health)
    store = EventStore(events_db) if events_db else None
    if store:
        store.add(preds)
        if windows.height and pipe.calibration:
            store.add_behavior(windows, source, pipe.calibration["calibration_id"],
                               pipe.profile.window_s)  # fmt: skip
    incidents = []
    if windows.height and pipe.calibration:
        from netsentinel.incidents import aggregate_incidents

        incidents = aggregate_incidents(
            windows, preds, pipe.calibration["calibration_id"], source, pipe.profile.window_s,
            gap_s=incident_gap_s, model_versions=pipe.versions(),
            baseline_status=pipe.profile.status)  # fmt: skip
        if store:
            store.upsert_incidents(incidents)
    if store:
        store.close()  # release the SQLite file (Windows keeps it locked otherwise)
    categories: Counter = Counter(p.threat.attack_category for p in preds
                                  if p.threat and p.threat.attack_category)  # fmt: skip
    alerts = [p for p in preds if p.verdict in ("attack", "suspicious")]
    alerts.sort(key=lambda p: -(p.threat.probability or 0))
    anomalous = [p for p in preds if p.behavior and p.behavior.behavior_status == "anomalous"]
    anomalous.sort(key=lambda p: -(p.behavior.anomaly_score or 0))
    summary = {
        "source": name,
        "kind": kind,
        "flows": len(preds),
        "parse": parse,
        "telemetry_health": health,
        **pipe.summary(preds, windows),
        "attack_categories": dict(categories),
        "missing_features": preds[0].missing_features if preds else [],
        "bundle": pipe.engine.bundle_id,
        "top_alerts": [a.model_dump(mode="json") for a in alerts[:20]],
        "top_behavior_anomalies": [a.model_dump(mode="json") for a in anomalous[:20]],
        "incidents": {"count": len(incidents),
                      "by_severity": dict(Counter(i.severity for i in incidents)),
                      "by_level": dict(Counter(i.level for i in incidents)),
                      "top": [i.to_dict() for i in sorted(
                          incidents, key=lambda i: (-i.max_ratio, i.incident_id))[:10]]},
        "note": "Detection-only offline analysis. 'unusual' = deviation from the local "
                "baseline (or, uncalibrated, from the training reference), not an attack "
                "verdict; semantics in inference/schema.py and inference/pipeline.py.",
    }  # fmt: skip
    log.info("analyzed %s: %d flows, verdicts %s", name, len(preds), summary["verdicts"])
    return summary
