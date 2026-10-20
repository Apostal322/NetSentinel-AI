"""Phase 8E: opt-in streaming monitor for Zeek conn logs (detection only).

NetSentinel never captures, intercepts, scans or blocks traffic. The monitor READS a Zeek
`conn.log` that the operator's own Zeek instance writes (or replays a recorded one), and turns
it into the same behaviour windows, flow predictions and incidents as offline `analyze`.

Event time and windows
* A flow belongs to the window containing its END time (as offline).
* Watermark = (largest flow START seen) - `lateness_s`. A window closes when its end is at or
  below the watermark. This is safe both for logs ordered by start time (IoT-23 files) and
  for live Zeek output (written when connections end): in both cases every later record ends
  after the watermark, unless it is late by more than `lateness_s`.
* Late records (their window has closed) are counted and dropped, never silently merged.
* Duplicates (same 5-tuple, start, end and byte counts) are dropped within their window.
* A record whose start lies more than `max_skew_s` ahead of the watermark clock is processed
  but does not advance the clock (a clock-skewed sensor cannot close every open window).
* Memory is bounded: only the records of open windows (plus a context lookback of whole
  closed windows for the supervised context features) are held; above `max_buffer` records the
  oldest open window is force-closed (counted).

Equivalence: behaviour windows use the profile's frozen destination set, so a window's features
depend only on its own flows. In-order (or within-lateness out-of-order) streaming therefore
reproduces the offline window scores and incident IDs exactly (tests/integration/
test_streaming.py).
"""

from __future__ import annotations

import heapq
import logging
import math
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
END, START = "FLOW_END_MILLISECONDS", "FLOW_START_MILLISECONDS"
DEDUP_KEY = (START, END, "IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT",
             "PROTOCOL", "IN_BYTES", "OUT_BYTES")  # fmt: skip


@dataclass
class StreamStats:
    records: int = 0
    accepted: int = 0
    duplicates: int = 0
    late: int = 0
    clock_skew: int = 0
    forced_closes: int = 0
    windows_closed: int = 0
    max_buffered: int = 0
    watermark_ms: int | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class WindowStream:
    """Event-time tumbling windows over flow records (dicts with NF-style keys)."""

    def __init__(self, window_s: int, lateness_s: float = 360.0, max_buffer: int = 2_000_000,
                 max_skew_s: float = 3600.0):  # fmt: skip
        self.w_ms = int(window_s * 1000)
        self.lateness_ms = int(lateness_s * 1000)
        self.max_buffer = max_buffer
        self.max_skew_ms = int(max_skew_s * 1000)
        self.buf: dict[int, list[dict]] = {}
        self.keys: dict[int, set] = {}
        self.heap: list[int] = []
        self.closed_below: int | None = None  # windows < this index are closed
        self.clock: int | None = None  # largest trusted flow start
        self.n_buffered = 0
        self.stats = StreamStats()

    def _close(self, w: int) -> tuple[int, list[dict]]:
        recs = self.buf.pop(w)
        self.keys.pop(w, None)
        self.n_buffered -= len(recs)
        self.closed_below = w + 1 if self.closed_below is None else max(self.closed_below, w + 1)
        self.stats.windows_closed += 1
        return w, recs

    def push(self, rec: dict) -> list[tuple[int, list[dict]]]:
        """Add one record; returns the windows it closed, in window order."""
        st = self.stats
        st.records += 1
        start, end = int(rec[START]), int(rec[END])
        w = end // self.w_ms
        if self.closed_below is not None and w < self.closed_below:
            st.late += 1
            return []
        k = tuple(rec.get(c) for c in DEDUP_KEY)
        seen = self.keys.setdefault(w, set())
        if k in seen:
            st.duplicates += 1
            return []
        seen.add(k)
        if w not in self.buf:
            self.buf[w] = []
            heapq.heappush(self.heap, w)
        self.buf[w].append(rec)
        self.n_buffered += 1
        st.accepted += 1
        st.max_buffered = max(st.max_buffered, self.n_buffered)
        if self.clock is None or start <= self.clock + self.max_skew_ms:
            self.clock = start if self.clock is None else max(self.clock, start)
        else:
            st.clock_skew += 1
        out = []
        wm = self.clock - self.lateness_ms
        st.watermark_ms = wm
        while self.heap and ((self.heap[0] + 1) * self.w_ms <= wm
                             or self.n_buffered > self.max_buffer):  # fmt: skip
            if (self.heap[0] + 1) * self.w_ms > wm:
                st.forced_closes += 1
            out.append(self._close(heapq.heappop(self.heap)))
        return out

    def flush(self) -> list[tuple[int, list[dict]]]:
        out = []
        while self.heap:
            out.append(self._close(heapq.heappop(self.heap)))
        return out


def follow_lines(path: str | Path, poll_s: float = 1.0,
                 stop: Callable[[], bool] | None = None,
                 idle_timeout_s: float | None = None) -> Iterator[str]:  # fmt: skip
    """Yield lines of a growing local file (tail -f). Stops when `stop()` is true or no new
    data arrived for `idle_timeout_s`. Reads only; never touches the file."""
    idle = 0.0
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        partial = ""
        while not (stop and stop()):
            line = fh.readline()
            if line:
                idle = 0.0
                if not line.endswith("\n"):
                    partial += line
                    continue
                yield partial + line
                partial = ""
                continue
            if idle_timeout_s is not None and idle >= idle_timeout_s:
                return
            time.sleep(poll_s)
            idle += poll_s


@dataclass
class MonitorResult:
    source: str
    stats: dict
    flows: int = 0
    windows: int = 0
    anomalous_windows: int = 0
    incidents: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)
    seconds: float = 0.0
    peak_rss_mb: float | None = None


class StreamMonitor:
    """Closed windows -> (optional) flow predictions via AnalysisPipeline -> behaviour windows
    -> incidents -> event store. Without a model bundle only the behaviour path runs."""

    def __init__(self, pipeline, store=None, source: str = "zeek-stream",
                 lateness_s: float = 360.0, max_buffer: int = 2_000_000, batch_flows: int = 20_000,
                 context_lookback_s: int = 300, incident_gap_s: int = 300,
                 utc_offset_hours: float = 0.0):  # fmt: skip
        from netsentinel.incidents import IncidentTracker

        if pipeline.profile is None:
            raise ValueError("streaming monitoring needs a behaviour calibration "
                             "(netsentinel calibrate / calibration activate)")  # fmt: skip
        self.pipe, self.store, self.source = pipeline, store, source
        self.window_s = pipeline.profile.window_s
        self.stream = WindowStream(self.window_s, lateness_s, max_buffer)
        self.batch_flows = batch_flows
        self.utc_offset = utc_offset_hours
        self.lookback_windows = math.ceil(context_lookback_s / self.window_s)
        self.recent: deque[tuple[int, list[dict]]] = deque()  # closed windows for context
        self.pending: list[tuple[int, list[dict]]] = []
        self.tracker = IncidentTracker(pipeline.calibration["calibration_id"], source,
                                       self.window_s, incident_gap_s, pipeline.versions(),
                                       pipeline.profile.status)  # fmt: skip
        self.result = MonitorResult(source=source, stats={})
        self.windows_out: list = []  # scored behaviour windows (kept only if keep_windows)
        self.keep_windows = False

    def _process(self, closed: list[tuple[int, list[dict]]]) -> None:
        import polars as pl

        from netsentinel.behavior.monitor import score_flows
        from netsentinel.telemetry.frames import records_to_frame

        recs = [r for _, rs in closed for r in rs]
        if not recs:
            return
        lo_ms = closed[0][0] * self.stream.w_ms
        hi_ms = (closed[-1][0] + 1) * self.stream.w_ms
        if self.pipe.engine is not None:
            ctx = [r for _, rs in self.recent for r in rs]
            frame = records_to_frame(ctx + recs, self.utc_offset)
            preds, windows = self.pipe.assess(frame, self.source)
            keep = (frame["flow_end_milliseconds"] >= lo_ms).to_numpy()
            preds = [p for p, k in zip(preds, keep, strict=True) if k]
        else:
            frame = records_to_frame(recs, self.utc_offset)
            preds, windows = [], score_flows(self.pipe.profile, frame)
        if windows.height:
            windows = windows.filter((pl.col("window_end_ms") > lo_ms)
                                     & (pl.col("window_end_ms") <= hi_ms))  # fmt: skip
        self.tracker.add_windows(windows)
        self.tracker.attach(preds)
        r = self.result
        r.flows += len(recs)
        r.windows += windows.height
        r.anomalous_windows += int(windows["anomalous"].sum()) if windows.height else 0
        for p in preds:
            r.verdicts[p.verdict] = r.verdicts.get(p.verdict, 0) + 1
        if self.keep_windows and windows.height:
            self.windows_out.append(windows)
        if self.store is not None:
            if preds:
                self.store.add(preds)
            if windows.height:
                cid = self.pipe.calibration["calibration_id"]
                self.store.add_behavior(windows, self.source, cid, self.window_s)
                hot = windows.filter(pl.col("anomalous")).iter_rows(named=True)
                touched = {
                    self.tracker._by_window[(r_["level"], str(r_["key"]), int(r_["window_end_ms"]))]
                    for r_ in hot
                }
                if touched:
                    self.store.upsert_incidents([self.tracker.all[i] for i in sorted(touched)])
        for item in closed:
            self.recent.append(item)
        while len(self.recent) > self.lookback_windows:
            self.recent.popleft()

    def _maybe_flush(self, force: bool = False) -> None:
        n = sum(len(rs) for _, rs in self.pending)
        if self.pending and (force or n >= self.batch_flows):
            self._process(self.pending)
            self.pending = []

    def feed(self, records: Iterable[dict]) -> MonitorResult:
        from netsentinel.resources import peak_rss_mb

        t0 = time.perf_counter()
        for rec in records:
            closed = self.stream.push(rec)
            if closed:
                # consecutive windows batch together; a gap in window indices is fine
                self.pending.extend(closed)
                self._maybe_flush()
        return self._finish(t0, peak_rss_mb)

    def close(self) -> MonitorResult:
        from netsentinel.resources import peak_rss_mb

        t0 = time.perf_counter()
        self.pending.extend(self.stream.flush())
        self._maybe_flush(force=True)
        return self._finish(t0, peak_rss_mb)

    def _finish(self, t0: float, rss) -> MonitorResult:
        self._maybe_flush(force=True)
        r = self.result
        r.stats = self.stream.stats.as_dict()
        r.incidents = len(self.tracker.all)
        r.seconds += time.perf_counter() - t0
        r.peak_rss_mb = rss()
        return r

    def summary(self) -> dict[str, Any]:
        return asdict(self.result)
