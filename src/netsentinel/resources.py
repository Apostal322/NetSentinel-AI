"""Process resource usage without extra dependencies (peak resident memory), and a hard
memory cap for child commands (`run_with_memory_cap`)."""

from __future__ import annotations

import subprocess
import sys


def peak_rss_mb() -> float | None:
    """Peak resident set / working set of THIS process in MiB, or None if unavailable."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t),
                            ("PeakPagefileUsage", ctypes.c_size_t)]  # fmt: skip

            pmc = PMC()
            pmc.cb = ctypes.sizeof(PMC)
            k32 = ctypes.WinDLL("kernel32")
            k32.GetCurrentProcess.restype = wintypes.HANDLE  # 64-bit pseudo-handle
            k32.K32GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PMC),
                wintypes.DWORD,
            ]
            k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
            if k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return pmc.PeakWorkingSetSize / 2**20
            return None
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak / 2**20 if sys.platform == "darwin" else peak / 1024
    except (OSError, AttributeError, ImportError):
        return None


def run_with_memory_cap(cmd: list[str], limit_mb: float) -> tuple[int, float | None]:
    """Run `cmd` under a hard memory cap; return (exit code, peak MiB).

    Windows: this process joins a Job Object whose TOTAL committed memory (this process plus
    every descendant, e.g. `uv` and its Python child) may not exceed `limit_mb`. An allocation
    past the cap fails inside the child, so the overrun cannot happen at all. The peak is the
    OS's exact `PeakJobMemoryUsed`, not a sample (after a refused allocation it also counts
    the refused request, so it can then exceed the cap). Call it from a dedicated process: the
    cap stays on the caller afterwards.
    POSIX: RLIMIT_AS (address space, not commit; it can fail spuriously with allocators that
    reserve large ranges) of the child; peak = the largest child's max RSS, not a total."""
    limit = int(limit_mb * 2**20)
    if sys.platform != "win32":
        import resource

        def cap() -> None:
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

        rc = subprocess.call(cmd, preexec_fn=cap)  # noqa: PLW1509 - no threads in this caller
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        return rc, peak / 2**20 if sys.platform == "darwin" else peak / 1024
    import ctypes
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]  # fmt: skip

    class Extended(ctypes.Structure):
        _fields_ = [("Basic", Basic), ("Io", ctypes.c_uint64 * 6),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]  # fmt: skip

    job_memory, kill_on_close, extended = 0x200, 0x2000, 9
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    common = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.SetInformationJobObject.argtypes = common
    k32.QueryInformationJobObject.argtypes = [*common, ctypes.c_void_p]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = k32.CreateJobObjectW(None, None)
    info = Extended()
    info.Basic.LimitFlags = job_memory | kill_on_close
    info.JobMemoryLimit = limit
    if not (job and k32.SetInformationJobObject(job, extended, ctypes.byref(info),
                                                 ctypes.sizeof(info))
            and k32.AssignProcessToJobObject(job, k32.GetCurrentProcess())):  # fmt: skip
        raise OSError(ctypes.get_last_error(), "could not set up the memory-capped job object")
    rc = subprocess.call(cmd)
    if not k32.QueryInformationJobObject(job, extended, ctypes.byref(info), ctypes.sizeof(info),
                                         None):  # fmt: skip
        return rc, None
    return rc, info.PeakJobMemoryUsed / 2**20
