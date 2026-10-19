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
from datetime import datetime
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
"""
VERDICTS = ("benign", "unusual", "suspicious", "attack", "insufficient_data")


class EventStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")

    def close(self) -> None:
        self._conn.close()

    def add(self, preds: Iterable[Prediction]) -> int:
        rows = [
            (p.observation_id, p.timestamp.isoformat(), p.source, p.verdict, p.service.category,
             p.anomaly.score if p.anomaly else None,
             p.threat.probability if p.threat else None,
             p.threat.attack_category if p.threat else None,
             p.model_versions.get("bundle"), p.model_dump_json())
            for p in preds
        ]  # fmt: skip
        with self._lock, self._conn:
            cur = self._conn.executemany(
                "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", rows
            )
        return cur.rowcount

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
        return cur.rowcount
