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

from netsentinel.inference.engine import Engine
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


def analyze_capture(
    path: str | Path,
    bundle_dir: str | Path,
    events_db: str | Path | None = None,
    utc_offset_hours: float = 0.0,
    kind: str = "auto",
    source_name: str | None = None,
) -> dict[str, Any]:
    path = Path(path)
    name = source_name or path.name
    kind = detect_kind(path) if kind == "auto" else kind
    if kind == "pcap":
        pstats = ReadStats()
        records = list(assemble_flows(read_packets(path, pstats)))
        parse = asdict(pstats)
    elif kind == "zeek":
        zstats = ZeekStats()
        records = list(read_conn_log(path, zstats))
        parse = asdict(zstats)
    else:
        raise ValueError(f"unknown capture kind {kind!r}")
    if not records:
        return {"source": name, "kind": kind, "flows": 0, "parse": parse}
    frame = records_to_frame(records, utc_offset_hours)
    engine = Engine(bundle_dir)
    store = EventStore(events_db) if events_db else None
    source = f"{kind}:{name}"
    verdicts: Counter = Counter()
    categories: Counter = Counter()
    alerts = []
    # Context needs the whole capture as one stream, so the frame is scored in a single pass.
    preds = engine.predict(frame, source=source, context="compute")
    missing = preds[0].missing_features if preds else []
    for p in preds:
        verdicts[p.verdict] += 1
        if p.threat and p.threat.attack_category:
            categories[p.threat.attack_category] += 1
        if p.verdict in ("attack", "suspicious"):
            alerts.append(p)
    if store:
        store.add(preds)
    alerts.sort(key=lambda p: -(p.threat.probability or 0))
    summary = {
        "source": name,
        "kind": kind,
        "flows": len(preds),
        "parse": parse,
        "verdicts": dict(verdicts),
        "attack_categories": dict(categories),
        "missing_features": missing,
        "bundle": engine.bundle_id,
        "top_alerts": [a.model_dump(mode="json") for a in alerts[:20]],
        "note": "Detection-only offline analysis; verdict semantics in inference/schema.py.",
    }
    log.info("analyzed %s: %d flows, verdicts %s", name, len(preds), dict(verdicts))
    return summary
