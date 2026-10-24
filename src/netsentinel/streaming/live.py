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
* Clock integrity (Phase 8e state machine). Relative to the committed clock a record is
  IN RANGE, AHEAD (start > clock + max_skew_s) or BEHIND (start < clock - max_skew_s -
  lateness_s). Out-of-range records never move the clock and never enter a window directly:
  they go to a bounded QUARANTINE (`max_quarantine`; the oldest are evicted and counted).
  - A PENDING jump opens only when >= 90% of the last `resync_after` records are out of range
    in the same direction (a capture gap, a quiet period, a sensor clock reset - or a burst of
    malformed / forged timestamps).
  - While pending, the committed timeline is processed normally: in-range records vote
    AGAINST the jump, records consistent with it vote FOR it.
  - COMMIT (`resync_after` votes for): the open windows are emitted, the clock moves, and the
    quarantined records consistent with the new time are replayed - a genuine gap or reset
    loses nothing. A backward commit (`clock_reset`) can repeat window indices.
  - REJECT (`resync_after` votes against, or the old timeline keeps interleaving: more than 2%
    contradicting records by the time the jump has `resync_after` votes for - a flood of forged
    timestamps among genuine traffic): the quarantined records are dropped and counted
    (`quarantine_rejected`), health `clock_anomaly`; genuine records are not lost.
  Health flags: `resynced` (informational), `clock_reset`, `clock_anomaly`,
  `integrity_degraded` (out-of-range records evicted unconfirmed), `buffer_pressure` (forced
  closes). `health` = the most severe flag, "ok" when none degrades monitoring.
* `advance(now_ms)` closes windows by wall-clock time during idle periods (follow mode), so a
  quiet network does not hold its last windows open until traffic resumes.
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


SEVERITY = {"resynced": 0, "buffer_pressure": 1, "integrity_degraded": 2, "clock_anomaly": 3,
            "clock_reset": 4}  # fmt: skip
DEGRADING = {f for f, v in SEVERITY.items() if v > 0}


@dataclass
class StreamStats:
    records: int = 0
    accepted: int = 0
    duplicates: int = 0
    late: int = 0
    clock_skew: int = 0  # out-of-range records quarantined (ahead or behind)
    clock_resyncs: int = 0  # committed forward jumps (gaps)
    clock_resets: int = 0  # committed backward jumps (sensor clock resets)
    clock_reverts: int = 0  # rejected jumps (malformed / forged timestamps)
    quarantine_rejected: int = 0  # quarantined records dropped after a rejected jump
    quarantine_evicted: int = 0  # quarantined records dropped by the quarantine cap
    replayed: int = 0  # quarantined records replayed after a committed jump
    forced_closes: int = 0
    windows_closed: int = 0
    max_buffered: int = 0
    max_quarantined: int = 0
    watermark_ms: int | None = None
    health: str = "ok"
    health_flags: list[str] = field(default_factory=list)

    def flag(self, f: str) -> None:
        if f not in self.health_flags:
            self.health_flags.append(f)
            self.health_flags.sort(key=lambda x: SEVERITY[x])
        worst = [x for x in self.health_flags if x in DEGRADING]
        self.health = max(worst, key=lambda x: SEVERITY[x]) if worst else "ok"

    def as_dict(self) -> dict:
        return asdict(self)


class WindowStream:
    """Event-time tumbling windows over flow records (dicts with NF-style keys), with a clock
    integrity state machine (module docstring)."""

    def __init__(self, window_s: int, lateness_s: float = 360.0, max_buffer: int = 2_000_000,
                 max_skew_s: float = 3600.0, resync_after: int = 1000,
                 max_quarantine: int | None = None, trigger_share: float = 0.9):  # fmt: skip
        self.w_ms = int(window_s * 1000)
        self.lateness_ms = int(lateness_s * 1000)
        self.max_buffer = max_buffer
        self.max_skew_ms = int(max_skew_s * 1000)
        self.resync_after = resync_after
        self.max_quarantine = max_quarantine or 4 * resync_after
        self.trigger_share = trigger_share
        self.interleave_limit = 0.02
        self.buf: dict[int, list[dict]] = {}
        self.keys: dict[int, set] = {}
        self.heap: list[int] = []
        self.closed_below: int | None = None  # windows < this index are closed
        self.clock: int | None = None  # committed clock: largest trusted flow start
        self.n_buffered = 0
        self.quarantine: deque[tuple[str, dict]] = deque()  # (direction, record)
        self._recent: deque[str] = deque(maxlen=resync_after)  # "in" | "ahead" | "behind"
        self._pending: dict | None = None
        self.stats = StreamStats()

    # ---------------------------------------------------------------- windows
    def _close(self, w: int) -> tuple[int, list[dict]]:
        recs = self.buf.pop(w)
        self.keys.pop(w, None)
        self.n_buffered -= len(recs)
        self.closed_below = w + 1 if self.closed_below is None else max(self.closed_below, w + 1)
        self.stats.windows_closed += 1
        return w, recs

    def _accept(self, rec: dict, start: int, w: int) -> bool:
        st = self.stats
        if self.closed_below is not None and w < self.closed_below:
            st.late += 1
            return False
        k = tuple(rec.get(c) for c in DEDUP_KEY)
        seen = self.keys.setdefault(w, set())
        if k in seen:
            st.duplicates += 1
            return False
        seen.add(k)
        if w not in self.buf:
            self.buf[w] = []
            heapq.heappush(self.heap, w)
        self.buf[w].append(rec)
        self.n_buffered += 1
        st.accepted += 1
        st.max_buffered = max(st.max_buffered, self.n_buffered)
        self.clock = start if self.clock is None else max(self.clock, start)
        return True

    def _drain(self) -> list[tuple[int, list[dict]]]:
        st = self.stats
        out = []
        wm = self.clock - self.lateness_ms
        st.watermark_ms = wm
        while self.heap and ((self.heap[0] + 1) * self.w_ms <= wm
                             or self.n_buffered > self.max_buffer):  # fmt: skip
            if (self.heap[0] + 1) * self.w_ms > wm:
                st.forced_closes += 1
                st.flag("buffer_pressure")
            out.append(self._close(heapq.heappop(self.heap)))
        return out

    # ---------------------------------------------------------------- clock integrity
    def _side(self, start: int) -> str:
        if start > self.clock + self.max_skew_ms:
            return "ahead"
        if start < self.clock - self.max_skew_ms - self.lateness_ms:
            return "behind"
        return "in"

    def _quarantine(self, side: str, rec: dict) -> None:
        st = self.stats
        st.clock_skew += 1
        self.quarantine.append((side, rec))
        if len(self.quarantine) > self.max_quarantine:
            self.quarantine.popleft()
            st.quarantine_evicted += 1
            st.flag("integrity_degraded")
        st.max_quarantined = max(st.max_quarantined, len(self.quarantine))

    def _consistent(self, start: int) -> bool:
        a = self._pending["anchor"]
        return a - self.max_skew_ms - self.lateness_ms <= start <= a + self.max_skew_ms * 2

    def _maybe_open(self, side: str) -> None:
        if self._pending is not None or side == "in" or len(self._recent) < self.resync_after:
            return
        if sum(x == side for x in self._recent) < self.trigger_share * self.resync_after:
            return
        starts = sorted(int(r[START]) for d, r in self.quarantine if d == side)
        if not starts:
            return
        self._pending = {"side": side, "anchor": starts[len(starts) // 2], "for": 0, "against": 0}

    def _commit(self) -> list[tuple[int, list[dict]]]:
        st = self.stats
        side = self._pending["side"]
        out = [self._close(heapq.heappop(self.heap)) for _ in range(len(self.heap))]  # old timeline
        if side == "behind":  # sensor clock reset: window indices may repeat
            self.closed_below = None
            st.clock_resets += 1
            st.flag("clock_reset")
        else:
            st.clock_resyncs += 1
            st.flag("resynced")
        keep = [r for d, r in self.quarantine if d == side and self._consistent(int(r[START]))]
        dropped = sum(1 for d, r in self.quarantine) - len(keep)
        st.quarantine_rejected += dropped
        self.quarantine.clear()
        self._pending = None
        self._recent.clear()
        self.clock = min(int(r[START]) for r in keep) if keep else self.clock
        for r in sorted(keep, key=lambda x: int(x[START])):
            if self._accept(r, int(r[START]), int(r[END]) // self.w_ms):
                st.replayed += 1
        return out + self._drain()

    def _reject(self) -> None:
        st = self.stats
        side = self._pending["side"]
        n = sum(1 for d, _ in self.quarantine if d == side)
        st.quarantine_rejected += n
        self.quarantine = deque((d, r) for d, r in self.quarantine if d != side)
        st.clock_reverts += 1
        st.flag("clock_anomaly")
        self._pending = None
        self._recent.clear()

    # ---------------------------------------------------------------- public
    def push(self, rec: dict) -> list[tuple[int, list[dict]]]:
        """Add one record; returns the windows it closed, in window order."""
        st = self.stats
        st.records += 1
        start, end = int(rec[START]), int(rec[END])
        if self.clock is None:
            self.clock = start
        side = self._side(start)
        self._recent.append(side)
        if side == "in":
            self._accept(rec, start, end // self.w_ms)
            if self._pending is not None:
                self._pending["against"] += 1
                if self._pending["against"] >= self.resync_after:
                    self._reject()
            return self._drain()
        self._quarantine(side, rec)
        if self._pending is not None and side == self._pending["side"] \
                and self._consistent(start):  # fmt: skip
            self._pending["for"] += 1
            if self._pending["for"] >= self.resync_after:
                # a genuine gap or reset silences the old timeline; if it keeps interleaving
                # (> 2% contradicting records), two timelines coexist: integrity anomaly
                if self._pending["against"] <= self.interleave_limit * self._pending["for"]:
                    return self._commit()
                self._reject()
                return []
        self._maybe_open(side)
        return []

    def advance(self, now_ms: int) -> list[tuple[int, list[dict]]]:
        """Idle tick (wall-clock time in ms, follow mode): close windows that ended more than
        `lateness_s` ago. Never moves the clock backwards or past `max_skew_s` ahead."""
        if self.clock is None or self._pending is not None:
            return []
        if now_ms > self.clock and now_ms <= self.clock + self.max_skew_ms:
            self.clock = now_ms
        return self._drain()

    def flush(self) -> list[tuple[int, list[dict]]]:
        out = []
        while self.heap:
            out.append(self._close(heapq.heappop(self.heap)))
        if self.quarantine:  # never confirmed: dropped and counted
            self.stats.quarantine_rejected += len(self.quarantine)
            if any(d == "ahead" for d, _ in self.quarantine):
                self.stats.flag("integrity_degraded")
            self.quarantine.clear()
        return out


def follow_lines(path: str | Path, poll_s: float = 1.0,
                 stop: Callable[[], bool] | None = None,
                 idle_timeout_s: float | None = None,
                 idle_marker: bool = False) -> Iterator[str]:  # fmt: skip
    """Yield lines of a growing local file (tail -f). Stops when `stop()` is true or no new
    data arrived for `idle_timeout_s`. Reads only; never touches the file. With
    `idle_marker`, yields `telemetry.zeek.IDLE` after every idle poll so the monitor can close
    windows by wall-clock time while the network is quiet."""
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
            if idle_marker:
                from netsentinel.telemetry.zeek import IDLE

                yield IDLE


@dataclass
class MonitorResult:
    source: str
    stats: dict
    flows: int = 0
    windows: int = 0
    anomalous_windows: int = 0
    incidents: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)
    assessment_states: dict[str, int] = field(default_factory=dict)
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
            health = self.stream.stats.health
            preds, windows = self.pipe.assess(frame, self.source, telemetry_health=health)
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
            if p.assessment:
                r.assessment_states[p.assessment.state] = (
                    r.assessment_states.get(p.assessment.state, 0) + 1)  # fmt: skip
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
        from netsentinel.telemetry.zeek import IDLE

        t0 = time.perf_counter()
        for rec in records:
            if rec is IDLE:  # quiet network: close windows by wall-clock time
                closed = self.stream.advance(int(time.time() * 1000))
                if closed:
                    self.pending.extend(closed)
                    self._maybe_flush(force=True)
                continue
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
