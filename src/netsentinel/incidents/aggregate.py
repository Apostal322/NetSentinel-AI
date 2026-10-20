"""Phase 8C: incident aggregation (detection-only; no response actions).

An incident groups the anomalous behaviour windows of ONE entity (a device, a service
category, or the whole network) that follow each other with gaps of at most `gap_s`, plus the
flow events that those windows decided. Rules:

* Grouping key: (calibration, level, entity). Windows of other entities never merge, so a
  scan and a brute force from different hosts stay separate incidents.
* `incident_id` = hash of (calibration, level, entity, start of the first window). It is a
  pure function of the input windows, so batch analysis and in-order streaming/replay
  produce the same IDs; re-running an analysis updates incidents instead of duplicating them.
* `severity` (low | medium | high) from the largest score/threshold ratio and the number of
  windows. It ranks deviation strength; it is not a probability that an attack happened.
* `status` lifecycle: new -> investigating -> acknowledged -> resolved, plus
  insufficient_evidence (set automatically for a single window just above its threshold, or
  when the baseline is provisional). Analyst changes are kept with their history; new
  evidence for a resolved incident re-opens it as "new".
* `threat_status` summarises the supervised evidence of the linked flows; with the default
  policy it is "unverified_domain" (no attack verdicts).
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

STATUSES = ("new", "investigating", "acknowledged", "resolved", "insufficient_evidence")
ENTITY_TYPE = {"device": "device", "service": "service", "global": "network"}
THREAT_ORDER = ("attack", "suspicious", "unverified_domain", "not_assessed", None)
MAX_EVIDENCE = 25


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).replace(tzinfo=None).isoformat()


def incident_id(calibration: str, level: str, entity: str, first_start_ms: int) -> str:
    h = hashlib.sha1(f"{calibration}|{level}|{entity}|{first_start_ms}".encode()).hexdigest()
    return f"inc-{h[:16]}"


@dataclass
class Incident:
    incident_id: str
    level: str
    entity_type: str
    entity: str
    calibration: str
    source: str
    window_s: int
    first_window_start_ms: int
    last_window_end_ms: int
    n_windows: int = 0
    n_flows: int = 0  # flows in the incident's windows (from window counts)
    max_score: float = 0.0
    max_ratio: float = 0.0  # max score / threshold
    explanation: Counter = field(default_factory=Counter)
    window_evidence: list[dict] = field(default_factory=list)
    flow_verdicts: Counter = field(default_factory=Counter)
    threat_status: Counter = field(default_factory=Counter)
    app_protocols: Counter = field(default_factory=Counter)
    flow_evidence: list[str] = field(default_factory=list)
    model_versions: dict[str, str] = field(default_factory=dict)
    baseline_status: str | None = None
    status: str = "new"
    status_history: list[dict] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.max_ratio >= 3.0 or self.n_windows >= 10:
            return "high"
        if self.max_ratio >= 1.5 or self.n_windows >= 3:
            return "medium"
        return "low"

    def auto_status(self) -> str:
        if self.baseline_status == "baseline_provisional" or (
            self.n_windows == 1 and self.max_ratio < 1.25
        ):
            return "insufficient_evidence"
        return "new"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        worst = min(self.threat_status, key=lambda s: THREAT_ORDER.index(s)
                    if s in THREAT_ORDER else len(THREAT_ORDER), default=None)  # fmt: skip
        d.update(
            first_seen=_iso(self.first_window_start_ms),
            last_seen=_iso(self.last_window_end_ms),
            duration_s=(self.last_window_end_ms - self.first_window_start_ms) / 1000,
            severity=self.severity,
            severity_semantics="deviation strength (score/threshold, duration); "
            "not an attack probability",  # fmt: skip
            explanation=[k for k, _ in self.explanation.most_common(5)],
            flow_verdicts=dict(self.flow_verdicts),
            threat_status=dict(self.threat_status),
            threat_status_worst=worst,
            app_protocols=dict(self.app_protocols.most_common(10)),
            n_flow_events=int(sum(self.flow_verdicts.values())),
        )
        return d


class IncidentTracker:
    """Incremental grouping. Feed anomalous windows in window-end order (batch analysis sorts
    them; the streaming pipeline emits closed windows in order), then attach flow events."""

    def __init__(self, calibration: str, source: str, window_s: int, gap_s: int = 300,
                 model_versions: dict[str, str] | None = None,
                 baseline_status: str | None = None):  # fmt: skip
        self.calibration, self.source, self.window_s = calibration, source, window_s
        self.gap_ms = gap_s * 1000
        self.versions = dict(model_versions or {})
        self.baseline_status = baseline_status
        self.open: dict[tuple[str, str], Incident] = {}
        self.all: dict[str, Incident] = {}
        self._by_window: dict[tuple[str, str, int], str] = {}  # (level, entity, end) -> id

    def add_window(self, w: dict) -> Incident:
        lvl, ent = str(w["level"]), str(w["key"])
        start, end = int(w["window_start_ms"]), int(w["window_end_ms"])
        inc = self.open.get((lvl, ent))
        if inc is None or start - inc.last_window_end_ms > self.gap_ms:
            inc = Incident(incident_id(self.calibration, lvl, ent, start), lvl,
                           ENTITY_TYPE.get(lvl, lvl), ent, self.calibration, self.source,
                           self.window_s, start, end, model_versions=dict(self.versions),
                           baseline_status=self.baseline_status)  # fmt: skip
            self.open[(lvl, ent)] = inc
            self.all[inc.incident_id] = inc
        inc.last_window_end_ms = max(inc.last_window_end_ms, end)
        inc.n_windows += 1
        inc.n_flows += int(w.get("n_flows") or 0)
        score, thr = float(w["score"]), float(w["threshold"])
        inc.max_score = max(inc.max_score, score)
        if thr > 0:
            inc.max_ratio = max(inc.max_ratio, score / thr)
        inc.explanation.update(w.get("explanation") or [])
        if len(inc.window_evidence) < MAX_EVIDENCE:
            inc.window_evidence.append({"window_end": _iso(end), "score": round(score, 3),
                                        "threshold": round(thr, 3),
                                        "n_flows": int(w.get("n_flows") or 0)})  # fmt: skip
        inc.status = inc.auto_status()
        self._by_window[(lvl, ent, end)] = inc.incident_id
        return inc

    def add_windows(self, windows) -> None:
        """`windows`: scored behaviour windows (polars frame or iterable of dicts)."""
        rows = windows.iter_rows(named=True) if hasattr(windows, "iter_rows") else windows
        for w in sorted((r for r in rows if r["anomalous"]),
                        key=lambda r: (r["window_end_ms"], r["level"], str(r["key"]))):  # fmt: skip
            self.add_window(w)

    def attach(self, preds) -> int:
        """Link flow predictions whose deciding behaviour window belongs to an incident."""
        n = 0
        for p in preds:
            b = p.behavior
            if not b or b.behavior_status != "anomalous" or b.window_end is None:
                continue
            end = b.window_end
            end = end.replace(tzinfo=UTC) if end.tzinfo is None else end
            iid = self._by_window.get((b.level, b.entity, int(round(end.timestamp() * 1000))))
            if iid is None:
                continue
            inc = self.all[iid]
            inc.flow_verdicts[p.verdict] += 1
            inc.threat_status[p.threat_status] += 1
            if p.application and p.application.app_protocol:
                inc.app_protocols[p.application.app_protocol] += 1
            elif p.application:
                inc.app_protocols[f"<{p.application.app_status}>"] += 1
            if len(inc.flow_evidence) < MAX_EVIDENCE:
                inc.flow_evidence.append(p.observation_id)
            n += 1
        return n

    def incidents(self) -> list[Incident]:
        return sorted(self.all.values(), key=lambda i: (i.first_window_start_ms, i.incident_id))


def aggregate_incidents(windows, preds, calibration: str, source: str, window_s: int,
                        gap_s: int = 300, model_versions: dict[str, str] | None = None,
                        baseline_status: str | None = None) -> list[Incident]:  # fmt: skip
    t = IncidentTracker(calibration, source, window_s, gap_s, model_versions, baseline_status)
    t.add_windows(windows)
    t.attach(preds)
    return t.incidents()
