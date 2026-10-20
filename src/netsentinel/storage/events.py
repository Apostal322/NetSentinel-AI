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
"""
# Phase 6 columns on `events`, added to older databases on open (indexed copies of payload
# fields; the payload JSON remains the source of truth).
EVENT_COLUMNS_V2 = {"threat_status": "TEXT", "behavior_status": "TEXT", "behavior_score": "REAL",
                    "app_protocol": "TEXT", "app_status": "TEXT"}  # fmt: skip
VERDICTS = ("benign", "unusual", "suspicious", "attack", "insufficient_data")


class EventStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        have = {r[1] for r in self._conn.execute("PRAGMA table_info(events)")}
        with self._conn:
            for col, typ in EVENT_COLUMNS_V2.items():
                if col not in have:
                    self._conn.execute(f"ALTER TABLE events ADD COLUMN {col} {typ}")

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
            ))  # fmt: skip
        cols = ("observation_id, ts, source, verdict, service, anomaly_score, p_malicious, "
                "attack_category, bundle, payload, " + ", ".join(EVENT_COLUMNS_V2))  # fmt: skip
        with self._lock, self._conn:
            cur = self._conn.executemany(
                f"INSERT OR IGNORE INTO events ({cols}) VALUES ({','.join('?' * 15)})", rows
            )
        return cur.rowcount

    def add_behavior(self, windows, source: str, calibration: str, window_s: int) -> int:
        """Store scored entity-windows (behaviour.profile.score output). Idempotent per
        (calibration, source, level, entity, window)."""
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
                json.dumps(list(r["explanation"] or [])), calibration,
            ))  # fmt: skip
        with self._lock, self._conn:
            cur = self._conn.executemany(
                f"INSERT OR IGNORE INTO behavior_events VALUES ({','.join('?' * 14)})", rows
            )
        return cur.rowcount

    def behavior(self, level: str | None = None, anomalous_only: bool = False,
                 source: str | None = None, limit: int = 500) -> list[dict[str, Any]]:  # fmt: skip
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
        sql += " ORDER BY window_end DESC LIMIT ?"
        cur = self._conn.execute(sql, (*args, max(1, min(int(limit), 5000))))
        names = [d[0] for d in cur.description]
        out = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        for o in out:
            o["explanation"] = json.loads(o["explanation"] or "[]")
            o["anomalous"] = bool(o["anomalous"])
        return out

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
    ) -> list[dict[str, Any]]:
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
        return {"counts": {v: counts.get(v, 0) for v in VERDICTS}, "first_ts": span[0],
                "last_ts": span[1], "attack_categories": cats}  # fmt: skip

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
        return cur.rowcount
