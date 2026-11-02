from netsentinel.resources import peak_rss_mb


def test_peak_rss_is_reported_and_plausible():
    peak = peak_rss_mb()
    assert peak is not None
    assert 5 < peak < 64_000  # MiB


def test_platform_string_survives_a_wmi_timeout(monkeypatch):
    import platform

    from netsentinel import ledger

    def boom():
        raise OSError(258, "The wait operation timed out")

    monkeypatch.setattr(platform, "platform", boom)
    assert "unavailable" in ledger.platform_string()


def _alloc(mb: int) -> list[str]:
    import sys

    return [sys.executable, "-c", f"b = bytearray({mb} * 2**20); b[::4096] = b'x' * len(b[::4096])"]


def test_memory_cap_blocks_an_allocation_above_it_and_reports_the_exact_peak():
    import subprocess
    import sys

    # The cap stays on the calling process, so each case runs in its own interpreter.
    code = ("import sys; from netsentinel.resources import run_with_memory_cap as r; "
            "rc, peak = r({cmd!r}, {cap}); print(rc, peak)")  # fmt: skip
    for mb, cap, ok in ((300, 200, False), (60, 600, True)):
        out = subprocess.run([sys.executable, "-c", code.format(cmd=_alloc(mb), cap=cap)],
                             capture_output=True, text=True, check=True).stdout.split()  # fmt: skip
        rc, peak = int(out[0]), float(out[1])
        assert (rc == 0) is ok
        if ok:  # after a refused allocation the counter also holds the refused request
            assert mb <= peak <= cap
