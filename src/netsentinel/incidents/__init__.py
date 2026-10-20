"""Incident aggregation: anomalous entity windows and their flows -> analyst-sized incidents."""

from netsentinel.incidents.aggregate import (
    STATUSES,
    Incident,
    IncidentTracker,
    aggregate_incidents,
)

__all__ = ["STATUSES", "Incident", "IncidentTracker", "aggregate_incidents"]
