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

from netsentinel.storage.events import EventStore
from netsentinel.telemetry.flows import assemble_flows
from netsentinel.telemetry.frames import records_to_frame
from netsentinel.telemetry.pcap import ReadStats, read_packets
from netsentinel.telemetry.zeek import ZeekStats, read_conn_log

log = logging.getLogger(__name__)


def detect_kind(path: Path) -> str:
    head = path.open("rb").read(4)
    if head in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
                b"\x0a\x0d\x0d\x0a"):  # fmt: skip
        return "pcap"
    return "zeek"


def load_capture(path: str | Path, kind: str = "auto", utc_offset_hours: float = 0.0,
                 zeek_extras: dict | None = None):  # fmt: skip
    """Capture -> (canonical flow frame or None if empty, kind, parse statistics)."""
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
    return records_to_frame(records, utc_offset_hours), kind, parse


def analyze_capture(
    path: str | Path,
    bundle_dir: str | Path,
    events_db: str | Path | None = None,
    utc_offset_hours: float = 0.0,
    kind: str = "auto",
    source_name: str | None = None,
    calibration_dir: str | Path | None = None,
    appid_dir: str | Path | None = None,
    threat_policy: str = "auto",
) -> dict[str, Any]:
    """Capture -> flows -> evidence-aware assessment (supervised bundle; optional local
    behaviour calibration and application classifier) -> events (+ behaviour windows)."""
    from netsentinel.inference.pipeline import AnalysisPipeline

    path = Path(path)
    name = source_name or path.name
    pipe = AnalysisPipeline(bundle_dir, calibration_dir, appid_dir, threat_policy)
    frame, kind, parse = load_capture(path, kind, utc_offset_hours)
    if frame is None:
        return {"source": name, "kind": kind, "flows": 0, "parse": parse,
                "model_versions": pipe.versions()}  # fmt: skip
    source = f"{kind}:{name}"
    # Context and behaviour windows need the whole capture as one stream: one pass.
    preds, windows = pipe.assess(frame, source)
    store = EventStore(events_db) if events_db else None
    if store:
        store.add(preds)
        if windows.height and pipe.calibration:
            store.add_behavior(windows, source, pipe.calibration["calibration_id"],
                               pipe.profile.window_s)  # fmt: skip
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
        **pipe.summary(preds, windows),
        "attack_categories": dict(categories),
        "missing_features": preds[0].missing_features if preds else [],
        "bundle": pipe.engine.bundle_id,
        "top_alerts": [a.model_dump(mode="json") for a in alerts[:20]],
        "top_behavior_anomalies": [a.model_dump(mode="json") for a in anomalous[:20]],
        "note": "Detection-only offline analysis. 'unusual' = deviation from the local "
                "baseline (or, uncalibrated, from the training reference), not an attack "
                "verdict; semantics in inference/schema.py and inference/pipeline.py.",
    }  # fmt: skip
    log.info("analyzed %s: %d flows, verdicts %s", name, len(preds), summary["verdicts"])
    return summary
