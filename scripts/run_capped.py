"""Run a command under the project's hard memory cap (default 3.4 GiB, the CLAUDE.md limit).

The cap is enforced by the OS (Windows Job Object on total committed memory; RLIMIT_AS on
POSIX): an allocation past it fails inside the command, which then exits non-zero. The exact
peak (not a sample) is printed and, with --record, appended as a JSON line.

Usage: uv run python scripts/run_capped.py [--limit-gb 3.4] [--record FILE] -- CMD ...
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from netsentinel.resources import run_with_memory_cap


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit-gb", type=float, default=3.4)
    ap.add_argument("--record", type=Path)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        ap.error("no command given")
    t0 = time.perf_counter()
    rc, peak = run_with_memory_cap(cmd, a.limit_gb * 1024)
    rec = {"cmd": cmd, "exit": rc, "limit_mib": a.limit_gb * 1024, "peak_mib": peak,
           "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
    shown = "unknown" if peak is None else f"{peak:.0f}"
    print(f"[run_capped] exit {rc}, peak {shown} MiB of {a.limit_gb * 1024:.0f} MiB cap",
          file=sys.stderr)  # fmt: skip
    if a.record:
        with a.record.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
