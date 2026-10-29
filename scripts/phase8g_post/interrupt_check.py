"""Phase 8g post-hoc [R]: cleanup after a hard interruption on real data
(docs/phase8g/REAL_DATA_STREAMING_AUDIT.md, section 5.1).

Starts the scenario 9 spill replay (stream_audit.py stream, 100k buffer, no feature build) in
a child process, kills it with TerminateProcess once its spill directory holds more than
`--kill-at-mb`, so no finalizer or `finally` can run, and then checks:
* the killed process left its spill directory (with its owner file) behind;
* a new process's `sweep_stale_spills` removes it, because the owner pid is dead;
* younger directories without an owner file (legacy) and directories of live processes are kept.
The partial run directory under data/derived/phase8g_post/runs/interrupt is removed.
Usage: uv run python scripts/phase8g_post/interrupt_check.py [--kill-at-mb 40]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from netsentinel.streaming.live import SPILL_PREFIX, _pid_alive, sweep_stale_spills

ROOT = Path(__file__).resolve().parents[2]
OUT = Path("reports/phase8g_post/interrupt_check.json")
RUN = Path("data/derived/phase8g_post/runs/interrupt")


def dir_bytes(d: Path) -> int:
    return sum(f.stat().st_size for f in d.iterdir() if f.is_file()) if d.exists() else 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kill-at-mb", type=float, default=40)
    ap.add_argument("--timeout-s", type=float, default=600)
    a = ap.parse_args()
    tmp = Path(tempfile.gettempdir())
    before = {d.name for d in tmp.glob(SPILL_PREFIX + "*")}
    child = subprocess.Popen([sys.executable, "-W", "ignore",
                              str(ROOT / "scripts/phase8g_post/stream_audit.py"), "stream",
                              "scenario_9", "--run", "interrupt", "--max-buffer", "100000",
                              "--no-build"], cwd=ROOT)  # fmt: skip
    # the owner is the interpreter, which on Windows is a child of the venv launcher
    t0, target, pid = time.time(), None, None
    while time.time() - t0 < a.timeout_s and child.poll() is None:
        for d in tmp.glob(SPILL_PREFIX + "*"):
            if target is None and d.name not in before and (d / "owner").exists():
                target, pid = d, int((d / "owner").read_text("utf-8").split()[0])
        if target is not None and dir_bytes(target) > a.kill_at_mb * 1e6:
            break
        time.sleep(0.5)
    if target is None or child.poll() is not None:
        child.kill()
        raise SystemExit("the child finished or never spilled before the kill point")
    size = dir_bytes(target)
    os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows: no finalizer or finally runs
    child.wait(timeout=60)
    killed_at = time.time() - t0
    left = target.exists()
    files = len(list(target.glob("*.jsonl"))) if left else None
    alive = _pid_alive(pid)
    others = sorted(d.name for d in tmp.glob(SPILL_PREFIX + "*") if d != target)
    removed = sweep_stale_spills()
    after = sorted(d.name for d in tmp.glob(SPILL_PREFIX + "*"))
    shutil.rmtree(RUN, ignore_errors=True)
    out = {"label": "[R] engineering check on consumed CTU-13 scenario 9 data",
           "killed_after_s": killed_at, "killed_pid": pid, "spill_dir_bytes_at_kill": size,
           "spill_files_at_kill": files,
           "left_behind_after_kill": left, "owner_pid_alive_after_kill": alive,
           "sweep_removed": removed, "killed_dir_removed_by_sweep": not target.exists(),
           "other_spill_dirs_before_sweep": others, "spill_dirs_after_sweep": after,
           "partial_run_dir_removed": not RUN.exists()}  # fmt: skip
    OUT.write_text(json.dumps(out, indent=1), "utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
