"""SQLite event store for predictions (stdlib only).

Stores the structured `Prediction` JSON plus indexed columns for filtering. Only flow metadata
and model outputs are stored - never packet payloads. `purge_older_than` implements the
configurable retention policy. Writes are idempotent on `observation_id`, so replaying the
same events twice does not duplicate them.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netsentinel.inference.schema import Prediction

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    observation_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    verdict TEXT NOT NULL,
    service TEXT,
    anomaly_score REAL,
    p_malicious REAL,
    attack_category TEXT,
    bundle TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events (verdict, ts);
CREATE TABLE IF NOT EXISTS behavior_events (
    event_id TEXT PRIMARY KEY,
    window_end TEXT NOT NULL,
    source TEXT NOT NULL,
    level TEXT NOT NULL,
    entity TEXT NOT NULL,
    window_s INTEGER NOT NULL,
    n_flows INTEGER,
    score REAL,
    severity REAL,
    threshold REAL,
    anomalous INTEGER NOT NULL,
    model_scope TEXT,
    explanation TEXT,
    calibration TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_beh_ts ON behavior_events (window_end);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT NOT NULL,
    level TEXT NOT NULL,
    entity TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    n_windows INTEGER NOT NULL,
    n_flow_events INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inc_seen ON incidents (last_seen);
CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents (status, last_seen);
"""
SEVERITIES = ("low", "medium", "high")
# Phase 6 columns on `events`, added to older databases on open (indexed copies of payload
# fields; the payload JSON remains the source of truth).
EVENT_COLUMNS_V2 = {
    "threat_status": "TEXT",
    "behavior_status": "TEXT",
    "behavior_score": "REAL",
    "app_protocol": "TEXT",
    "app_status": "TEXT",
    "assessment_state": "TEXT",
}  # fmt: skip  (assessment_state: Phase 8e)
# Phase 8g: telemetry health when a behaviour window was stored ("ok", or the degrading
# stream/parse condition at that time); NULL for rows stored before the column existed.
BEHAVIOR_COLUMNS_V2 = {"telemetry_health": "TEXT"}
VERDICTS = ("benign", "unusual", "suspicious", "attack", "insufficient_data")


class EventStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._conn:
            for table, extra in (("events", EVENT_COLUMNS_V2),
                                 ("behavior_events", BEHAVIOR_COLUMNS_V2)):  # fmt: skip
                have = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
                for col, typ in extra.items():
                    if col not in have:
                        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")

    def close(self) -> None:
        self._conn.close()

    def add(self, preds: Iterable[Prediction]) -> int:
        rows = []
        for p in preds:
            b, a = p.behavior, p.application
            rows.append((
                p.observation_id, p.timestamp.isoformat(), p.source, p.verdict,
                p.service.category, p.anomaly.score if p.anomaly else None,
                p.threat.probability if p.threat else None,
                p.threat.attack_category if p.threat else None,
                p.model_versions.get("bundle"), p.model_dump_json(), p.threat_status,
                b.behavior_status if b else None, b.anomaly_score if b else None,
                a.app_protocol if a else None, a.app_status if a else None,
                p.assessment.state if p.assessment else None,
            ))  # fmt: skip
        cols = ("observation_id, ts, source, verdict, service, anomaly_score, p_malicious, "
                "attack_category, bundle, payload, " + ", ".join(EVENT_COLUMNS_V2))  # fmt: skip
        with self._lock, self._conn:
            cur = self._conn.executemany(
                f"INSERT OR IGNORE INTO events ({cols}) VALUES ({','.join('?' * 16)})", rows
            )
        return cur.rowcount

    def add_behavior(self, windows, source: str, calibration: str, window_s: int,
                     telemetry_health: str | None = None) -> int:  # fmt: skip
        """Store scored entity-windows (behaviour.profile.score output). Idempotent per
        (calibration, source, level, entity, window). `telemetry_health`: "ok" or the degrading
        condition when the windows were closed (a quiet window is then no sign of normality)."""
        import hashlib

        rows = []
        for r in windows.iter_rows(named=True):
            key = f"{calibration}|{source}|{r['level']}|{r['key']}|{r['win']}"
            end = datetime.fromtimestamp(r["window_end_ms"] / 1000, UTC).replace(tzinfo=None)
            end = end.isoformat()
            sev = r["severity"]
            rows.append((
                hashlib.sha1(key.encode()).hexdigest()[:20], end, source, r["level"],
                str(r["key"]), window_s, int(r["n_flows"] or 0), float(r["score"]),
                None if sev is None or sev != sev else float(sev), float(r["threshold"]),
                int(bool(r["anomalous"])), r["model_scope"],
                json.dumps(list(r["explanation"] or [])), calibration, telemetry_health,
            ))  # fmt: skip
        cols = ("event_id, window_end, source, level, entity, window_s, n_flows, score, "
                "severity, threshold, anomalous, model_scope, explanation, calibration, "
                "telemetry_health")  # fmt: skip
        with self._lock, self._conn:
            cur = self._conn.executemany(
                f"INSERT OR IGNORE INTO behavior_events ({cols}) VALUES ({','.join('?' * 15)})",
                rows,
            )
        return cur.rowcount

    def behavior(self, level: str | None = None, anomalous_only: bool = False,
                 source: str | None = None, limit: int = 500,
                 offset: int = 0) -> list[dict[str, Any]]:  # fmt: skip
        where, args = [], []
        if level:
            where.append("level = ?")
            args.append(level)
        if anomalous_only:
            where.append("anomalous = 1")
        if source:
            where.append("source = ?")
            args.append(source)
        sql = "SELECT * FROM behavior_events" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY window_end DESC, event_id LIMIT ? OFFSET ?"
        cur = self._conn.execute(sql, (*args, max(1, min(int(limit), 5000)), max(0, int(offset))))
        names = [d[0] for d in cur.description]
        out = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        for o in out:
            o["explanation"] = json.loads(o["explanation"] or "[]")
            o["anomalous"] = bool(o["anomalous"])
        return out

    # ------------------------------------------------------------------ incidents (Phase 8)
    def upsert_incidents(self, incidents) -> int:
        """Insert or update incidents (Incident objects or their dicts). Analyst lifecycle
        changes are preserved; new evidence after "resolved" re-opens the incident."""
        from netsentinel.incidents.aggregate import Incident

        now = datetime.now(UTC).replace(tzinfo=None).isoformat()
        n = 0
        with self._lock, self._conn:
            for inc in incidents:
                d = inc.to_dict() if isinstance(inc, Incident) else dict(inc)
                old = self._conn.execute("SELECT payload FROM incidents WHERE incident_id = ?",
                                         (d["incident_id"],)).fetchone()  # fmt: skip
                if old:
                    prev = json.loads(old[0])
                    hist = prev.get("status_history") or []
                    d["status_history"] = hist
                    if hist:  # analyst-managed: keep the analyst's status
                        d["status"] = prev["status"]
                        if prev["status"] == "resolved" and d["last_seen"] > prev["last_seen"]:
                            d["status"] = "new"
                            note = "re-opened: new evidence"
                            hist.append(
                                {
                                    "at": now,
                                    "from": "resolved",
                                    "to": "new",
                                    "by": "system",
                                    "note": note,
                                }
                            )
                self._conn.execute(
                    "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (d["incident_id"], d["first_seen"], d["last_seen"], d["source"], d["level"],
                     d["entity"], d["severity"], d["status"], d["n_windows"],
                     d["n_flow_events"], now, json.dumps(d, default=str)))  # fmt: skip
                n += 1
        return n

    def incidents(self, status: list[str] | None = None, severity: list[str] | None = None,
                  level: str | None = None, entity: str | None = None,
                  source: str | None = None, since: datetime | None = None,
                  until: datetime | None = None, limit: int = 50,
                  offset: int = 0) -> tuple[list[dict[str, Any]], int]:  # fmt: skip
        """Filtered page of incidents (most recent activity first) and the total match count."""
        from netsentinel.incidents.aggregate import STATUSES

        if status and not set(status) <= set(STATUSES):
            raise ValueError(f"unknown status {sorted(set(status) - set(STATUSES))}")
        if severity and not set(severity) <= set(SEVERITIES):
            raise ValueError(f"unknown severity {sorted(set(severity) - set(SEVERITIES))}")
        where, args = [], []
        for col, vals in (("status", status), ("severity", severity)):
            if vals:
                where.append(f"{col} IN ({','.join('?' * len(vals))})")
                args += vals
        for col, val in (("level", level), ("entity", entity), ("source", source)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        if since:
            where.append("last_seen >= ?")
            args.append(since.replace(tzinfo=None).isoformat())
        if until:
            where.append("first_seen < ?")
            args.append(until.replace(tzinfo=None).isoformat())
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM incidents{w}", args).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT payload FROM incidents{w} ORDER BY last_seen DESC, incident_id "
            "LIMIT ? OFFSET ?", (*args, max(1, min(int(limit), 500)), max(0, int(offset)))
        ).fetchall()  # fmt: skip
        return [json.loads(r[0]) for r in rows], int(total)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT payload FROM incidents WHERE incident_id = ?",
                                 (incident_id,)).fetchone()  # fmt: skip
        return json.loads(row[0]) if row else None

    def set_incident_status(self, incident_id: str, status: str, note: str = "",
                            by: str = "analyst") -> dict[str, Any]:  # fmt: skip
        from netsentinel.incidents.aggregate import STATUSES

        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}; allowed {STATUSES}")
        now = datetime.now(UTC).replace(tzinfo=None).isoformat()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT payload FROM incidents WHERE incident_id = ?",
                                     (incident_id,)).fetchone()  # fmt: skip
            if row is None:
                raise KeyError(incident_id)
            d = json.loads(row[0])
            d.setdefault("status_history", []).append(
                {"at": now, "from": d["status"], "to": status, "by": by[:64], "note": note[:500]}
            )
            d["status"] = status
            self._conn.execute("UPDATE incidents SET status = ?, updated_at = ?, payload = ? "
                               "WHERE incident_id = ?",
                               (status, now, json.dumps(d, default=str), incident_id))  # fmt: skip
        return d

    def get(self, observation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload FROM events WHERE observation_id = ?", (observation_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def query(
        self,
        verdicts: list[str] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        source: str | None = None,
        limit: int = 100,
        offset: int = 0,
        states: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        from netsentinel.inference.assessment import STATES

        if states and not set(states) <= set(STATES):
            raise ValueError(f"unknown assessment states {sorted(set(states) - set(STATES))}")
        if verdicts and not set(verdicts) <= set(VERDICTS):
            raise ValueError(f"unknown verdicts {sorted(set(verdicts) - set(VERDICTS))}")
        limit = max(1, min(int(limit), 1000))
        where, args = [], []
        if verdicts:
            where.append(f"verdict IN ({','.join('?' * len(verdicts))})")
            args += verdicts
        if since:
            where.append("ts >= ?")
            args.append(since.isoformat())
        if until:
            where.append("ts < ?")
            args.append(until.isoformat())
        if source:
            where.append("source = ?")
            args.append(source)
        if states:
            where.append(f"assessment_state IN ({','.join('?' * len(states))})")
            args += states
        sql = "SELECT payload FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        rows = self._conn.execute(sql, (*args, limit, max(0, int(offset)))).fetchall()
        return [json.loads(r[0]) for r in rows]

    def summary(self, source: str | None = None) -> dict[str, Any]:
        where, args = ("WHERE source = ?", (source,)) if source else ("", ())
        counts = dict(self._conn.execute(
            f"SELECT verdict, COUNT(*) FROM events {where} GROUP BY verdict", args
        ).fetchall())  # fmt: skip
        span = self._conn.execute(f"SELECT MIN(ts), MAX(ts) FROM events {where}", args).fetchone()
        cats = dict(self._conn.execute(
            f"SELECT attack_category, COUNT(*) FROM events {where + (' AND' if where else 'WHERE')}"
            " attack_category IS NOT NULL GROUP BY attack_category", args
        ).fetchall())  # fmt: skip
        states = dict(self._conn.execute(
            f"SELECT COALESCE(assessment_state, 'not_recorded'), COUNT(*) FROM events {where} "
            "GROUP BY 1", args).fetchall())  # fmt: skip
        return {"counts": {v: counts.get(v, 0) for v in VERDICTS}, "first_ts": span[0],
                "last_ts": span[1], "attack_categories": cats,
                "assessment_states": states}  # fmt: skip

    def timeline(self, bucket_seconds: int = 60, source: str | None = None) -> list[dict]:
        """Per-bucket verdict counts (bucketed on ISO timestamps via SQLite strftime)."""
        where, args = ("WHERE source = ?", (source,)) if source else ("", ())
        rows = self._conn.execute(
            f"SELECT (CAST(strftime('%s', ts) AS INTEGER) / ?) * ? AS b, verdict, COUNT(*), "
            f"AVG(anomaly_score) FROM events {where} GROUP BY b, verdict ORDER BY b",
            (bucket_seconds, bucket_seconds, *args),
        ).fetchall()
        return [{"bucket_epoch": r[0], "verdict": r[1], "count": r[2], "mean_anomaly": r[3]}
                for r in rows]  # fmt: skip

    def purge_older_than(self, cutoff: datetime) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff.isoformat(),))
            self._conn.execute("DELETE FROM behavior_events WHERE window_end < ?",
                               (cutoff.isoformat(),))  # fmt: skip
            self._conn.execute("DELETE FROM incidents WHERE last_seen < ?",
                               (cutoff.isoformat(),))  # fmt: skip
        return cur.rowcount
