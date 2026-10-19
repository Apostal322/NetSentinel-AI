from netsentinel.resources import peak_rss_mb


def test_peak_rss_is_reported_and_plausible():
    peak = peak_rss_mb()
    assert peak is not None
    assert 5 < peak < 64_000  # MiB
