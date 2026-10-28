"""Phase 8g finalization: streaming edge cases found by the review of the d67f061 spill and
long-connection changes (docs/phase8g/REAL_DATA_STREAMING_AUDIT.md, section 4).

Each test reproduces a failure of d67f061 unless marked "sanity":
* appends to spilled windows ignored the disk budget and held up to 999 records per window in
  memory;
* a failed or interrupted spill write (disk full, Ctrl+C) raised out of `push` or lost records;
* a truncated or edited spill file raised on read;
* spill directories of a crashed or abandoned process were never removed;
* records ending before they start were classified BEHIND by their end, so a flood of them
  could force a backward clock commit and be emitted into old windows.
"""

from __future__ import annotations

import errno
import gc
import importlib.util
import os
import pathlib
import subprocess
import sys
import time
from pathlib import Path

import pytest

from netsentinel.streaming.live import END, START, WindowStream

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "stream_robustness", ROOT / "scripts/phase8e/stream_robustness.py"
)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

LOSS_COUNTERS = ("duplicates", "late", "quarantine_rejected", "quarantine_evicted",
                 "invalid_time", "spill_lost")  # fmt: skip


def _drive(ws: WindowStream, recs: list[dict], watch=None) -> list[dict]:
    out = []
    for r in recs:
        out += [x for _, rs in ws.push(r) for x in rs]
        if watch:
            watch(ws)
    return out + [x for _, rs in ws.flush() for x in rs]


def _key(r: dict) -> tuple:
    return r[START], r[END], r["IPV4_SRC_ADDR"], r["L4_SRC_PORT"]


def _conserved(ws: WindowStream, n_out: int) -> bool:
    st = ws.stats.as_dict()
    return st["records"] == n_out + sum(st.get(k, 0) for k in LOSS_COUNTERS)


def _trickle(per_s: int = 3, hours: int = 2) -> list[dict]:
    """In-order traffic plus `per_s` distinct records per second that end 30 min in the past
    (inside a 1 h lateness): every open window is on disk and keeps receiving records."""
    out = []
    for i, r in enumerate(sr.genuine_stream(0, hours * 3600)):
        out.append(r)
        t = r[START]
        if t >= 1_800_000 and i % 3 == 0:
            for j in range(per_s):
                out.append(sr.rec(t - 1_800_000, "10.0.0.7", 10_000_000 + 10 * i + j))
    return out


def _pending(ws: WindowStream) -> int:
    return sum(len(v) for v in ws.spill.pending.values())


# ----------------------------------------------------------------------------- budgets
def test_spill_pending_memory_is_bounded_across_many_spilled_windows():
    ws = WindowStream(30, lateness_s=3600, max_buffer=50, max_spill=10**7)
    peak = [0]
    recs = _trickle()
    out = _drive(ws, recs, lambda s: peak.__setitem__(0, max(peak[0], _pending(s))))
    assert ws.stats.spilled_windows > 0
    assert peak[0] <= ws.spill.FLUSH, peak  # d67f061: about 5,000 records held in memory
    assert len(out) == len(recs) and _conserved(ws, len(out))


def test_appends_to_spilled_windows_respect_the_disk_budget():
    # 150 records of one window: spilled at 51, the next 99 arrive while it is on disk
    recs = [sr.rec(i * 190, "10.0.0.1", i) for i in range(150)] + sr.genuine_stream(30_000, 60)
    ws = WindowStream(30, lateness_s=600, max_buffer=50, max_spill=100)
    peak = [0]
    out = _drive(ws, recs, lambda s: peak.__setitem__(0, max(peak[0], s.spill.count)))
    assert ws.stats.spilled_windows > 0
    assert peak[0] <= 100 and ws.stats.max_spilled <= 100, peak  # d67f061: 150 on disk
    assert ws.stats.forced_closes > 0 and ws.stats.health == "buffer_pressure"
    assert _conserved(ws, len(out))


# ----------------------------------------------------------------------------- disk faults
class _FailingFile:
    """Writes half of what it is given, then raises (disk full or Ctrl+C mid-write)."""

    def __init__(self, f, exc):
        self.f, self.exc = f, exc

    def write(self, data):
        self.f.write(data[: len(data) // 2])
        self.f.flush()
        raise self.exc

    def writelines(self, lines):
        self.write("".join(lines))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.f.close()


def _fail_spill_writes(monkeypatch, exc, after: int = 3):
    real = pathlib.Path.open
    n = [0]

    def fake(self, mode="r", *a, **k):
        f = real(self, mode, *a, **k)
        if "netsentinel-spill-" in str(self) and mode[0] in "aw":
            n[0] += 1
            if n[0] > after:
                return _FailingFile(f, exc)
        return f

    monkeypatch.setattr(pathlib.Path, "open", fake)


def test_disk_full_keeps_records_and_degrades_explicitly(monkeypatch, tmp_path):
    _fail_spill_writes(monkeypatch, OSError(errno.ENOSPC, "No space left on device"))
    recs = sr.genuine_stream(0, 900)
    ws = WindowStream(30, lateness_s=600, max_buffer=50, max_spill=10**6, spill_dir=tmp_path)
    out = _drive(ws, recs)  # d67f061: the OSError propagates out of push
    st = ws.stats
    assert st.spill_error and "spill_failed" in st.health_flags
    assert st.spill_lost == 0 and _conserved(ws, len(out))
    assert st.health == "buffer_pressure"
    assert not any(tmp_path.iterdir())


def test_interrupted_spill_write_loses_nothing(monkeypatch, tmp_path):
    _fail_spill_writes(monkeypatch, KeyboardInterrupt(), after=2)
    recs = sr.genuine_stream(0, 300)
    ws = WindowStream(30, lateness_s=600, max_buffer=50, max_spill=10**6, spill_dir=tmp_path)
    out = []
    with pytest.raises(KeyboardInterrupt):
        for r in recs:
            out += [x for _, rs in ws.push(r) for x in rs]
    n_pushed = ws.stats.records
    monkeypatch.undo()
    out += [x for _, rs in ws.flush() for x in rs]  # the CLI closes the stream on Ctrl+C
    assert len(out) == n_pushed and ws.stats.spill_lost == 0  # d67f061: records lost
    assert {_key(r) for r in out} == {_key(r) for r in recs[:n_pushed]}
    assert not any(tmp_path.iterdir())


def test_truncated_or_edited_spill_files_are_counted_not_fatal(tmp_path):
    recs = sr.genuine_stream(0, 600)
    ws = WindowStream(30, lateness_s=3600, max_buffer=50, max_spill=10**6, spill_dir=tmp_path)
    for r in recs:
        ws.push(r)
    files = sorted(ws.spill.dir.glob("*.jsonl"))
    assert len(files) >= 4
    data = files[0].read_bytes()
    files[0].write_bytes(data[: len(data) // 2])  # truncated mid-line
    marker = tmp_path / "pwned"
    with files[1].open("ab") as f:  # appended junk, a pickle payload and an oversized line
        f.write(b'not json\n[1, 2]\n{"x": 1}\n')
        f.write(b"cos\nsystem\n(S'echo > " + str(marker).encode() + b"'\ntR.\n")
        f.write(b'{"a": "' + b"x" * 300_000 + b'"}\n')
    lines = files[2].read_bytes().splitlines(keepends=True)
    moved = lines[0].replace(b'"FLOW_END_MILLISECONDS": ', b'"FLOW_END_MILLISECONDS": 9')
    files[2].write_bytes(moved + b"".join(lines[1:]))  # a record moved to another window
    out = [x for _, rs in ws.flush() for x in rs]  # d67f061: JSONDecodeError
    st = ws.stats
    assert st.spill_lost > 0 and st.spill_invalid >= 3
    assert st.health == "integrity_degraded" and not marker.exists()
    assert _conserved(ws, len(out)) and not any(tmp_path.iterdir())


# ----------------------------------------------------------------------------- cleanup
def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def test_stale_spill_directories_of_dead_processes_are_removed(tmp_path):
    old = time.time() - 3 * 86_400
    dead = tmp_path / "netsentinel-spill-dead"
    live_ = tmp_path / "netsentinel-spill-live"
    legacy_old = tmp_path / "netsentinel-spill-legacyold"  # d67f061 directories: no owner file
    legacy_new = tmp_path / "netsentinel-spill-legacynew"
    other = tmp_path / "unrelated"
    for d in (dead, live_, legacy_old, legacy_new, other):
        d.mkdir()
        (d / "1.jsonl").write_text("{}\n")
    (dead / "owner").write_text(f"{_dead_pid()} {old}")
    (live_ / "owner").write_text(f"{os.getpid()} {old}")
    os.utime(legacy_old / "1.jsonl", (old, old))
    os.utime(legacy_old, (old, old))
    ws = WindowStream(30, lateness_s=600, max_buffer=50, max_spill=10**6, spill_dir=tmp_path)
    for r in sr.genuine_stream(0, 120):
        ws.push(r)
    assert ws.stats.spilled_windows > 0
    assert not dead.exists() and not legacy_old.exists()
    assert live_.exists() and legacy_new.exists() and other.exists()
    ws.flush()


def test_abandoned_stream_removes_its_spill_directory(tmp_path):
    ws = WindowStream(30, lateness_s=600, max_buffer=50, max_spill=10**6, spill_dir=tmp_path)
    for r in sr.genuine_stream(0, 120):
        ws.push(r)
    d = ws.spill.dir
    assert d is not None and d.exists()
    del ws  # an exception in the caller: flush() never runs
    gc.collect()
    assert not d.exists()


def test_restart_after_interruption_reproduces_the_reference(tmp_path):
    recs = sr.genuine_stream(0, 900)
    first = WindowStream(30, lateness_s=600, max_buffer=50, spill_dir=tmp_path)
    for r in recs[:1500]:  # killed mid-run: no flush, nothing carried over
        first.push(r)
    del first
    gc.collect()
    ws = WindowStream(30, lateness_s=600, max_buffer=50, spill_dir=tmp_path)
    out = _drive(ws, recs)
    assert sorted(map(_key, out)) == sorted(map(_key, recs)) and not any(tmp_path.iterdir())


# ----------------------------------------------------------------------------- timestamps
def test_records_ending_before_they_start_are_rejected():
    g = sr.genuine_stream(0, 3600)
    forged = [dict(sr.rec(1_800_000 + i, "10.0.0.66", 900_000 + i, genuine=False),
                   **{END: 1_800_000 + i - 2 * sr.DAY}) for i in range(3000)]  # fmt: skip
    r = sr.run(g[:5400] + forged + g[5400:])
    assert r["forged_emitted"] == 0 and r["genuine_lost"] == 0, r  # d67f061: 3,000 emitted
    assert r["stats"]["invalid_time"] == 3000 and r["stats"]["clock_resets"] == 0
    assert r["health"] == "integrity_degraded"


def test_connection_spanning_several_windows_is_emitted_once_in_its_end_window():  # sanity
    recs = sr.genuine_stream(0, 600)
    span = sr.rec(100_000, "10.0.0.8", 77, dur=95_000)  # windows 3..6, logged when it ends
    recs.insert(3 * 196, span)
    ws = WindowStream(30, lateness_s=360)
    hits = [w for r in recs for w, rs in ws.push(r) for x in rs if x is span]
    hits += [w for w, rs in ws.flush() for x in rs if x is span]
    assert hits == [195_000 // 30_000]


def test_records_are_conserved_in_every_robustness_scenario():
    sc = sr.scenarios()
    cases = [(recs, {}) for recs in sc.values()]
    cases += [(sc["baseline"], {"max_buffer": 100}),
              (_trickle(1, 1), {"max_buffer": 50, "max_spill": 500})]  # fmt: skip
    for recs, kw in cases:
        params = {"lateness_s": 60, "max_skew_s": 3600, "resync_after": 1000} | kw
        ws = WindowStream(30, **params)
        out = _drive(ws, recs)
        assert _conserved(ws, len(out)), ws.stats.as_dict()
        assert ws.stats.emitted == len(out)


# ----------------------------------------------------------------------------- memory on close
def _spilled_stream(n_s: int = 1200) -> WindowStream:
    ws = WindowStream(30, lateness_s=7200, max_buffer=100, max_spill=10**7)
    for r in sr.genuine_stream(0, n_s):
        ws.push(r)
    assert ws.stats.spilled_windows > 0
    return ws


def test_restored_records_share_key_strings():
    # CTU-13 scenario 9 (100k buffer): restored dicts took 1,592 bytes vs 753 for the originals
    ws = _spilled_stream(120)
    out = [x for _, rs in ws.flush() for x in rs]
    first = out[0]
    assert all(k1 is k2 for x in out for k1, k2 in zip(x, first, strict=True))


def test_flush_iter_does_not_materialise_every_spilled_window():
    import tracemalloc

    peaks = []
    for lazy in (False, True):
        ws = _spilled_stream()
        tracemalloc.start()
        n = 0
        windows = ws.flush_iter() if lazy else ws.flush()
        for _, rs in windows:
            n += len(rs)
            del rs
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
        assert n == 3600 and _conserved(ws, n)
    assert peaks[1] < peaks[0] / 5, peaks  # d67f061/9e526ca: no lazy close
