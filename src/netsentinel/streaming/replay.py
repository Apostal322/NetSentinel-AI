"""Offline replay of recorded flow records through the inference engine.

Events are replayed in EVENT-TIME order (flow start + duration), preserving original
timestamps. `speed` scales wall-clock pacing (0 = as fast as possible; 60 = one hour of
traffic per minute). Context features are computed causally over the replayed stream, in
bounded chunks with a lookback equal to the longest window, so memory stays bounded and results
are identical to training-time features. Predictions are idempotent (deterministic ids) and
written to the event store; a status object reports progress for the API/dashboard.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from netsentinel.features.context import DEFAULT_WINDOWS, compute_context_chunked, event_seconds
from netsentinel.inference.engine import Engine
from netsentinel.storage.events import EventStore

log = logging.getLogger(__name__)


def _replay_assessment(p):
    """Replay has a supervised model but no local behaviour calibration, so a quiet flow is
    `insufficient_calibration`, never `normal_valid_baseline` (Phase 8e)."""
    from netsentinel.inference.assessment import Context, assess
    from netsentinel.inference.schema import AssessmentOut

    ctx = Context(has_profile=False, has_model=True)
    return AssessmentOut(**assess(ctx, p.verdict, p.threat_status, "not_calibrated", None, None))


@dataclass
class ReplayStatus:
    state: str = "idle"  # idle | running | finished | failed | cancelled
    source: str = ""
    total: int = 0
    processed: int = 0
    started: str | None = None
    finished: str | None = None
    error: str | None = None
    verdict_counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ReplayConfig:
    path: str  # an ingested day parquet (data/interim/ids2018/<day>.parquet)
    start: datetime | None = None
    end: datetime | None = None
    max_events: int = 50_000
    batch_size: int = 2_000
    speed: float = 0.0
    keep_labels: bool = False  # never fed to the engine; only for offline evaluation output


def load_replay_frame(cfg: ReplayConfig) -> pl.DataFrame:
    path = Path(cfg.path)
    if not path.is_file() or path.suffix != ".parquet":
        raise FileNotFoundError(f"replay source must be an existing .parquet file: {path}")
    base = pl.scan_parquet(path).with_columns(event_seconds())

    def epoch(t: datetime) -> int:  # timestamps are naive; Polars treats them as UTC epochs
        return int(t.replace(tzinfo=UTC).timestamp())

    lf = base
    if cfg.start:
        lf = lf.filter(pl.col("event_sec") >= epoch(cfg.start))
    if cfg.end:
        lf = lf.filter(pl.col("event_sec") < epoch(cfg.end))
    events = lf.sort("event_sec", "row_id").head(cfg.max_events).collect()
    if events.height == 0:
        raise ValueError("no events in the requested replay window")
    # Context over the replayed event-time range plus lookback: everything observable before
    # each event, whether or not that earlier flow is itself replayed.
    lo = int(events["event_sec"].min()) - max(DEFAULT_WINDOWS)
    hi = int(events["event_sec"].max()) + 1
    ctx = compute_context_chunked(base.filter(pl.col("event_sec").is_between(lo, hi, "left")))
    events = events.join(ctx.drop("event_sec"), on="row_id", how="left")
    if not cfg.keep_labels:
        events = events.drop("label", "family", strict=False)
    return events.drop("src_ip", "dst_ip", "src_port", "flow_id", strict=False)


class Replayer:
    def __init__(self, engine: Engine, store: EventStore):
        self.engine = engine
        self.store = store
        self.status = ReplayStatus()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    def run(self, cfg: ReplayConfig) -> ReplayStatus:
        started = datetime.now().isoformat(timespec="seconds")
        st = self.status = ReplayStatus(
            state="running", source=Path(cfg.path).stem, started=started
        )
        self._cancel.clear()
        try:
            frame = load_replay_frame(cfg)
            st.total = frame.height
            source = f"replay:{st.source}"
            t_wall0, t_ev0 = time.monotonic(), None
            for offset in range(0, frame.height, cfg.batch_size):
                if self._cancel.is_set():
                    st.state = "cancelled"
                    return st
                batch = frame.slice(offset, cfg.batch_size)
                if cfg.speed > 0:  # pace to event time
                    ev = batch["event_sec"][0]
                    t_ev0 = ev if t_ev0 is None else t_ev0
                    delay = (ev - t_ev0) / cfg.speed - (time.monotonic() - t_wall0)
                    if delay > 0:
                        self._cancel.wait(delay)
                preds = self.engine.predict(batch, source=source, context="provided")
                preds = [p.model_copy(update={"assessment": _replay_assessment(p)}) for p in preds]
                self.store.add(preds)
                for p in preds:
                    st.verdict_counts[p.verdict] = st.verdict_counts.get(p.verdict, 0) + 1
                st.processed += batch.height
            st.state = "finished"
        except Exception as exc:  # noqa: BLE001 - surfaced through the status endpoint
            log.exception("replay failed")
            st.state, st.error = "failed", f"{type(exc).__name__}: {exc}"
        finally:
            st.finished = datetime.now().isoformat(timespec="seconds")
        return st

    def start_background(self, cfg: ReplayConfig) -> ReplayStatus:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("a replay is already running")
        self.status = ReplayStatus(state="running", source=Path(cfg.path).stem)
        self._thread = threading.Thread(target=self.run, args=(cfg,), daemon=True)
        self._thread.start()
        return self.status

    def cancel(self) -> None:
        self._cancel.set()
