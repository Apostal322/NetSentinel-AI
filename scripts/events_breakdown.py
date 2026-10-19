"""Verdict x service breakdown for one event source in the SQLite store.
Usage: uv run python scripts/events_breakdown.py "pcap:demo_synthetic.pcap" [artifacts/events.sqlite]
"""

import collections
import json
import sqlite3
import sys

source = sys.argv[1]
db = sys.argv[2] if len(sys.argv) > 2 else "artifacts/events.sqlite"
rows = (
    sqlite3.connect(db)
    .execute("SELECT verdict, payload FROM events WHERE source = ?", (source,))
    .fetchall()
)
counts = collections.Counter()
for verdict, payload in rows:
    counts[(verdict, json.loads(payload)["service"]["category"])] += 1
for (verdict, service), n in sorted(counts.items()):
    print(f"{verdict:12s} {service:18s} {n}")
