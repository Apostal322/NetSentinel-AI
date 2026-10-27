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
